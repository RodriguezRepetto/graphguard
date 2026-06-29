"""
analyzer.py — analyzer_node implementation.

Sends parsed AST data to the local LLM (Qwen3.5-9B via llama-server)
and detects security vulnerabilities across seven OWASP ASI vectors.
The LLM reasons over the full parsed structure — no hardcoded rules.
"""

import json
import httpx
from graphguard.state import GraphGuardState, Finding, Severity


# Model endpoint configuration — selected by the --model CLI flag.
# fast:      Qwen3.5-9B  on port 8080 — default, good for most scans
# reasoning: Qwen3.5-35B-A3B on port 8081 — slower but deeper analysis
LLAMA_ENDPOINTS = {
    "fast": {
        "url":   "http://127.0.0.1:8080/v1/chat/completions",
        "model": "qwen3.5-9b",
    },
    "reasoning": {
        "url":   "http://127.0.0.1:8081/v1/chat/completions",
        "model": "qwen3.5-35b-a3b",
    },
}

# system prompt that tells the LLM what to look for
SYSTEM_PROMPT = """You are GraphGuard, an expert security auditor for LangGraph agent pipelines.

You will receive the parsed structure of a Python LangGraph agent — its functions, classes,
imports, function calls, assignments, and string literals extracted via AST analysis.

Your job is to identify security vulnerabilities across these seven vectors:
- ASI01: Prompt injection — user input passed to LLM without sanitization
- ASI02: Tool misuse — tools called with unvalidated or raw inputs
- ASI03: State leakage — sensitive fields (tokens, passwords, keys) in shared state
- ASI05: Supply chain — imports of known vulnerable package versions
- ASI06: Privilege escalation — powerful tools accessible without authorization checks
- ASI07: Inter-node validation — raw LLM output passed directly to next node without validation
- ASI08: Memory poisoning — persistent memory or checkpointers written without validation,
         allowing an attacker to corrupt future agent executions via poisoned memory entries

For each vulnerability found, respond with a JSON array of findings.
Each finding must follow this exact schema:
{
  "id": "GG-001",
  "owasp_id": "ASI01",
  "title": "Short title of the vulnerability",
  "description": "Detailed explanation of why this is a vulnerability",
  "severity": "critical|high|medium|low",
  "file": "path/to/file.py",
  "line": 42,
  "remediation": "Concrete step-by-step fix"
}

Return ONLY the JSON array. No explanation, no markdown, no preamble.
If no vulnerabilities are found, return an empty array: []
"""


def build_prompt(parsed_ast: dict) -> str:
    """
    Converts the parsed AST dict into a prompt string for the LLM.
    Serializes the structure as JSON and includes it in the user message.
    """
    ast_json = json.dumps(parsed_ast, indent=2)
    if len(ast_json) > 12000:
        ast_json = ast_json[:12000] + "\n... [truncated for context window]"
    return f"Analyze this LangGraph agent for security vulnerabilities:\n\n{ast_json}"


def call_llm(prompt: str, endpoint: dict) -> str:
    """
    Sends the prompt to llama-server and returns the raw text response.
    Uses the OpenAI-compatible /v1/chat/completions endpoint.
    """
    payload = {
        "model":    endpoint["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens":  2048,
    }

    response = httpx.post(
        endpoint["url"],
        json=payload,
        timeout=120.0,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def parse_llm_response(raw: str, finding_counter: list) -> list[Finding]:
    """
    Parses the LLM JSON response into a list of Finding objects.
    Handles malformed responses gracefully including Qwen3 thinking mode.
    """
    findings = []
    clean = raw.strip()

    # strip thinking mode output — Qwen3 adds <think>...</think> before responding
    if "<think>" in clean and "</think>" in clean:
        clean = clean.split("</think>")[-1].strip()

    # strip any accidental markdown fences the LLM might add
    if "```" in clean:
        parts = clean.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("[") or part.startswith("{"):
                clean = part
                break

    # find the JSON array even if there's text before or after it
    start = clean.find("[")
    end   = clean.rfind("]")
    if start != -1 and end != -1:
        clean = clean[start:end+1]

    # attempt to parse as JSON array
    try:
        items = json.loads(clean.strip())
    except json.JSONDecodeError:
        print(f"[analyzer] warning: could not parse LLM response as JSON")
        return []   # only reached on parse failure

    # convert each dict into a Finding object
    for item in items:
        try:
            finding_counter[0] += 1
            item["id"] = f"GG-{finding_counter[0]:03d}"

            finding = Finding(
                id=          item.get("id",          f"GG-{finding_counter[0]:03d}"),
                owasp_id=    item.get("owasp_id",    "UNKNOWN"),
                title=       item.get("title",       "Untitled finding"),
                description= item.get("description", "No description provided"),
                severity=    Severity(item.get("severity", "medium")),
                file=        item.get("file",        "unknown"),
                line=        item.get("line",        None),
                remediation= item.get("remediation", "No remediation provided"),
            )
            findings.append(finding)
        except Exception as e:
            print(f"[analyzer] warning: skipped malformed finding — {e}")

    return findings


def analyzer_node(state: GraphGuardState) -> dict:
    """
    Node 2: sends parsed AST to local LLM and collects security findings.
    Iterates over each parsed file and runs the LLM analysis on each one.
    """
    parsed_ast = state["parsed_ast"]
    all_findings = []
    finding_counter = [0]

    # select endpoint based on the model flag passed from the CLI
    model_key = state.get("model", "fast")
    endpoint  = LLAMA_ENDPOINTS.get(model_key, LLAMA_ENDPOINTS["fast"])

    print(f"[analyzer] analyzing {len(parsed_ast)} files with LLM ({model_key} model)")

    for filepath, ast_data in parsed_ast.items():

        # skip files with parse errors
        if "error" in ast_data:
            print(f"[analyzer] skipping {filepath} — parse error: {ast_data['error']}")
            continue

        # skip empty files — no functions or classes means nothing to analyze
        if not ast_data.get("functions") and not ast_data.get("classes"):
            continue

        print(f"[analyzer] scanning {filepath}")

        prompt = build_prompt({filepath: ast_data})

        try:
            raw_response = call_llm(prompt, endpoint)
        except httpx.ConnectError:
            print(f"[analyzer] error: cannot reach llama-server at {endpoint['url']}")
            print(f"[analyzer] hint: start llama-server before running graphguard")
            return {"findings": all_findings}
        except Exception as e:
            print(f"[analyzer] error calling LLM for {filepath}: {e}")
            continue

        findings = parse_llm_response(raw_response, finding_counter)
        print(f"[analyzer] {len(findings)} findings in {filepath}")
        all_findings.extend(findings)

    print(f"[analyzer] total findings: {len(all_findings)}")

    return {"findings": all_findings}
