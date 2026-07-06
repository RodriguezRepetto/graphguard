"""
analyzer.py — analyzer_node implementation.

Sends parsed AST data to the local LLM (Qwen3.5-9B via llama-server)
and detects security vulnerabilities across seven OWASP ASI vectors.
The LLM reasons over the full parsed structure — no hardcoded rules.
"""

import json
import time
import threading
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from graphguard.state import GraphGuardState, Finding, Severity

# Default number of GraphGuard-side worker threads used to call the LLM
# concurrently. No benchmark against Qwen3.5-9B on llama-server backs this
# number — it's a conservative default meant to be tuned via --workers, not
# a measured optimum. See README for why this must be coordinated with
# llama-server's own --parallel flag to see any real speedup.
DEFAULT_WORKERS = 2


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

You will receive the parsed structure of one or more LangGraph agent source files — their
functions, classes, imports, function calls, assignments, and string literals extracted via
AST analysis. The input JSON may contain multiple top-level keys, one per file path, when
several small files are batched into a single request.

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
  "owasp_id": "ASI01",
  "title": "Short title of the vulnerability",
  "description": "Detailed explanation of why this is a vulnerability",
  "severity": "critical|high|medium|low",
  "file": "path/to/file.py",
  "line": 42,
  "remediation": "Concrete step-by-step fix"
}

Do not include an "id" field — GraphGuard assigns finding IDs itself and any "id" you generate
is discarded.

The "file" field must exactly match the top-level key (file path) of the input JSON where the
issue was found — this is how findings get attributed back to the correct file when multiple
files are analyzed in one request.

Return ONLY the JSON array. No explanation, no markdown, no preamble.
If no vulnerabilities are found, return an empty array: []
"""

# JSON Schema for grammar-constrained output via llama-server's response_format
# (see tools/server/README.md in llama.cpp — "response_format (GBNF/JSON Schema)").
# Aditive only: reduces malformed output at generation time, but parse_llm_response()
# below stays as the full safety net regardless, because:
#   1. some llama.cpp builds silently accept response_format without enforcing it
#      (reported in upstream issues) — there is no guarantee this build honors it;
#   2. the schema constrains output tokens, but is not injected into the prompt, so
#      it does NOT suppress a Qwen3 <think>...</think> block emitted before the JSON.
# "id" is deliberately excluded: parse_llm_response() always overwrites it with a
# sequential counter (see below), so asking the model to generate one wastes output
# tokens on a field that's never used.
FINDING_JSON_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "owasp_id": {
                "type": "string",
                "enum": ["ASI01", "ASI02", "ASI03", "ASI05", "ASI06", "ASI07", "ASI08"],
            },
            "title":       {"type": "string"},
            "description": {"type": "string"},
            "severity":    {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "file":        {"type": "string"},
            "line":        {"type": ["integer", "null"]},
            "remediation": {"type": "string"},
        },
        "required": ["owasp_id", "title", "description", "severity", "file", "remediation"],
        "additionalProperties": False,
    },
}

# Single source of truth for the prompt-truncation cutoff used by build_prompt()
# below. Reference llama-server config (see README): --ctx-size 8192. call_llm()
# reserves max_tokens=2048 for the response, leaving ~6144 tokens of context for
# input (system prompt + batched AST) at ~4 chars/token — 12000 chars stays well
# under that ceiling, leaving headroom for the system prompt itself.
PROMPT_TRUNCATE_CHARS = 12000

# Safety margin build_batches() keeps below PROMPT_TRUNCATE_CHARS when assembling
# batches. v1.5.1 batched purely on a per-file char/4 token *estimate* summed
# across files, which could accumulate a batch whose *actual* serialized JSON
# (built with json.dumps(..., indent=2), so real overhead from braces/indentation/
# multiple top-level keys) exceeded build_prompt()'s hard truncation threshold —
# silently dropping AST content for whichever file landed at the tail of the
# batch. build_batches() now measures the real serialized size of the batch as
# it's assembled instead, using this single constant as its cap — no second,
# separately-tuned token budget to keep in sync with the truncation limit.
BATCH_CHAR_BUDGET = PROMPT_TRUNCATE_CHARS - 1000


def build_batches(parsed_ast: dict, char_budget: int = BATCH_CHAR_BUDGET) -> list[dict]:
    """
    Groups files into batches whose combined *actual* serialized JSON size
    (the same measure build_prompt() uses) stays under char_budget, so several
    small files can share one LLM call without build_prompt()'s truncation
    ever having to cut into a finished batch. A file whose own serialized size
    already meets or exceeds the budget is placed alone in its own batch —
    build_prompt()'s 12000-char truncation is a last-resort backstop for that
    case only, and logs a warning if it actually has to cut into a solo file.
    Preserves the input dict's insertion order.
    """
    batches: list[dict] = []
    current_batch: dict = {}

    for filepath, ast_data in parsed_ast.items():
        candidate = {**current_batch, filepath: ast_data}
        candidate_size = len(json.dumps(candidate, indent=2))

        if current_batch and candidate_size > char_budget:
            # adding this file would overflow the current batch — flush it first
            batches.append(current_batch)
            current_batch = {}

        current_batch[filepath] = ast_data

        # a single file whose own serialized size already meets/exceeds the
        # budget can't share a batch with anything — flush it alone right away
        if len(current_batch) == 1:
            solo_size = len(json.dumps(current_batch, indent=2))
            if solo_size >= char_budget:
                batches.append(current_batch)
                current_batch = {}

    if current_batch:
        batches.append(current_batch)

    return batches


def build_prompt(parsed_ast: dict) -> str:
    """
    Converts the parsed AST dict (one or more files, keyed by filepath) into a
    prompt string for the LLM. Serializes the structure as JSON and includes
    it in the user message. Truncation here should only ever be hit for a
    single file too large to fit on its own — build_batches() keeps assembled
    multi-file batches under BATCH_CHAR_BUDGET specifically to avoid this path.
    """
    ast_json = json.dumps(parsed_ast, indent=2)
    if len(ast_json) > PROMPT_TRUNCATE_CHARS:
        # last-resort backstop: content past the cutoff is dropped from the
        # prompt entirely, so this is surfaced instead of failing silently —
        # matches the "never lose content without a warning" principle applied
        # to LLM timeouts in the previous round.
        print(f"[analyzer] warning: prompt for {', '.join(parsed_ast.keys())} exceeds "
              f"{PROMPT_TRUNCATE_CHARS} chars ({len(ast_json)} chars) and will be "
              f"truncated — some AST content will be lost")
        ast_json = ast_json[:PROMPT_TRUNCATE_CHARS] + "\n... [truncated for context window]"
    return f"Analyze this LangGraph agent for security vulnerabilities:\n\n{ast_json}"


def call_llm(prompt: str, endpoint: dict, timeout: float = 120.0) -> str:
    """
    Sends the prompt to llama-server and returns the raw text response.
    Uses the OpenAI-compatible /v1/chat/completions endpoint.
    `timeout` is configurable so slower hardware (or larger batched prompts)
    can raise it via the --timeout CLI flag instead of aborting mid-scan.
    """
    payload = {
        "model":    endpoint["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens":  2048,
        # constrains output to the Finding array schema via llama-server's
        # grammar-from-json-schema support. Not mutually usable with a "grammar"
        # field (llama.cpp returns 400 if both are set) — this codebase never
        # sets "grammar", so there's no conflict here.
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name":   "graphguard_findings",
                "schema": FINDING_JSON_SCHEMA,
            },
        },
    }

    response = httpx.post(
        endpoint["url"],
        json=payload,
        timeout=timeout,
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


def _call_batch(batch: dict, endpoint: dict, timeout: float, abort_event: threading.Event) -> dict:
    """
    Worker function run in a thread pool: performs the network call for one
    batch and returns a plain result dict instead of mutating any shared state,
    so the caller can aggregate results (findings, skips) back in the main
    thread without needing locks. Only the network call happens here — JSON
    parsing and Finding construction (which touch the shared finding_counter)
    stay in the main thread to avoid a race on that counter.
    """
    filepaths = list(batch.keys())

    # a prior batch already hit ConnectError — don't bother dialing a dead server
    if abort_event.is_set():
        return {"status": "aborted", "filepaths": filepaths}

    if len(filepaths) == 1:
        print(f"[analyzer] scanning {filepaths[0]}")
    else:
        print(f"[analyzer] scanning batch of {len(filepaths)} files: {', '.join(filepaths)}")

    prompt = build_prompt(batch)

    try:
        raw_response = call_llm(prompt, endpoint, timeout)
        return {"status": "ok", "filepaths": filepaths, "raw_response": raw_response}
    except httpx.ConnectError:
        # signal every other worker (queued or about to start) to stop dialing
        abort_event.set()
        return {"status": "connect_error", "filepaths": filepaths}
    # must come before the generic Exception handler below: httpx.TimeoutException
    # is a subclass of httpx.TransportError (not ConnectError), so a real timeout
    # would otherwise fall through to the generic branch and look like any other
    # transient error instead of being tracked and surfaced to the user.
    except httpx.TimeoutException:
        return {"status": "timeout", "filepaths": filepaths}
    except Exception as e:
        return {"status": "error", "filepaths": filepaths, "error": str(e)}


def analyzer_node(state: GraphGuardState) -> dict:
    """
    Node 2: sends parsed AST to local LLM and collects security findings.
    Small files are grouped into batches (see build_batches()), and batches
    are analyzed concurrently across a small pool of worker threads — this
    only translates into wall-clock speedup if llama-server itself is started
    with --parallel N >= number of workers; otherwise requests just queue up
    server-side. See README for hardware-dependent guidance.
    """
    parsed_ast = state["parsed_ast"]
    all_findings = []
    skipped_files = []  # files skipped due to LLM timeout: {"filepath": str, "reason": str}
    finding_counter = [0]

    # select endpoint based on the model flag passed from the CLI
    model_key = state.get("model", "fast")
    endpoint  = LLAMA_ENDPOINTS.get(model_key, LLAMA_ENDPOINTS["fast"])

    # per-call timeout, configurable via --timeout so slow hardware isn't forced
    # to abort mid-scan on the hardcoded 120s default. Batching makes prompts
    # larger and generation slower, so this may need to be raised further when
    # batching is in play — the --timeout help text calls this out.
    timeout = state.get("timeout", 120.0)

    # client-side worker count, configurable via --workers
    workers = state.get("workers", DEFAULT_WORKERS)

    print(f"[analyzer] analyzing {len(parsed_ast)} files with LLM ({model_key} model, {workers} worker(s))")
    start_time = time.monotonic()

    # step 1: drop files with parse errors or no analyzable structure before batching
    analyzable = {}
    for filepath, ast_data in parsed_ast.items():

        # skip files with parse errors
        if "error" in ast_data:
            print(f"[analyzer] skipping {filepath} — parse error: {ast_data['error']}")
            continue

        # skip files with no analyzable structure at all. Checks assignments and
        # calls too (not just functions/classes) because a file that only wires up
        # a graph via top-level statements — e.g. `const graph = new StateGraph(...)`
        # or `Annotation.Root({...})` — has real structure worth sending to the LLM
        # even though it declares no function/class. imports and strings are
        # deliberately excluded: a file with only those and nothing else has already
        # passed the relevance filter but carries no analyzable structure on its own.
        structural_keys = ("functions", "classes", "calls", "assignments")
        if not any(ast_data.get(key) for key in structural_keys):
            continue

        analyzable[filepath] = ast_data

    # step 2: group small files together so several can share one LLM call
    batches = build_batches(analyzable)

    # step 3: analyze batches concurrently. abort_event replaces the old
    # sequential-loop's `return` on ConnectError — a bare return inside a worker
    # thread wouldn't stop the other threads, so every worker checks this event
    # before dialing and the first ConnectError trips it for everyone else.
    abort_event = threading.Event()
    connection_error = None  # set to a message when a ConnectError aborts the whole analysis

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [
            executor.submit(_call_batch, batch, endpoint, timeout, abort_event)
            for batch in batches
        ]

        for future in as_completed(futures):
            result = future.result()
            filepaths = result["filepaths"]
            status = result["status"]

            if status == "ok":
                findings = parse_llm_response(result["raw_response"], finding_counter)
                print(f"[analyzer] {len(findings)} findings in batch of {len(filepaths)} file(s)")
                all_findings.extend(findings)

            elif status == "timeout":
                print(f"[analyzer] timeout calling LLM for batch of {len(filepaths)} file(s) "
                      f"(timeout={timeout}s) — skipping all of them")
                reason = f"LLM call timed out after {timeout}s"
                if len(filepaths) > 1:
                    reason += f" (batched with {len(filepaths) - 1} other file(s))"
                for fp in filepaths:
                    skipped_files.append({"filepath": fp, "reason": reason})

            elif status == "connect_error":
                connection_error = f"cannot reach llama-server at {endpoint['url']}"
                print(f"[analyzer] error: {connection_error}")
                print(f"[analyzer] hint: start llama-server before running graphguard")
                # cancel whatever hasn't started yet — already-running requests
                # will each fail fast on their own ConnectError
                for f in futures:
                    f.cancel()

            elif status == "error":
                print(f"[analyzer] error calling LLM for batch ({', '.join(filepaths)}): {result['error']}")

            # "aborted" batches never dialed the server — nothing to report

    elapsed = time.monotonic() - start_time
    print(f"[analyzer] total analysis time: {elapsed:.1f}s")

    if connection_error:
        return {"findings": all_findings, "skipped_files": skipped_files, "connection_error": connection_error}

    print(f"[analyzer] total findings: {len(all_findings)}")
    if skipped_files:
        print(f"[analyzer] {len(skipped_files)} file(s) skipped due to LLM timeout")

    return {"findings": all_findings, "skipped_files": skipped_files, "connection_error": None}
