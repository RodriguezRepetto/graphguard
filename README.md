# GraphGuard

**Security linter for LangGraph agent pipelines.**

GraphGuard scans LangGraph agent source code for security vulnerabilities using LLM-driven static analysis. It detects misconfigurations, insecure patterns, and known OWASP ASI threats — before your agent reaches production.

```bash
graphguard scan ./my_agent/
```

---

## Why GraphGuard

Most LangGraph agents are built for functionality, not security. GraphGuard fills that gap: run it before deployment and get a structured report with findings, severity ratings, and concrete remediations — no security expertise required.

---

## Features

- **LLM-driven analysis** — no hardcoded rules, reasoning over your actual code
- **Multi-language support** — analyzes Python (`.py`), JavaScript (`.js`), and TypeScript (`.ts`) LangGraph agents via tree-sitter AST parsing
- **7 OWASP ASI vectors** — prompt injection, tool misuse, state leakage, supply chain, privilege escalation, inter-node validation, memory poisoning
- **Rich console output** — color-coded findings table with detailed remediations
- **CI/CD ready** — `--strict` flag exits with code 1 on critical or high findings
- **Supply chain check** — detects known vulnerable LangGraph/LangChain dependency versions
- **100% local** — runs entirely offline with a local LLM via llama-server

---

## Requirements

- Python 3.10+
- [llama.cpp](https://github.com/ggerganov/llama.cpp) with `llama-server` — chosen for 100% local inference with no telemetry, no API calls, and no data leaving your machine. All analysis stays on your hardware.
- **Qwen3.5-9B-Q4_K_M** loaded at `127.0.0.1:8080` — default fast model for analysis
- **Qwen3.5-35B-A3B-UD-Q4_K_XL** loaded at `127.0.0.1:8081` *(optional)* — reasoning model for complex agents, activated with `--model reasoning`
- macOS / Linux / Windows (WSL2)

> **Note:** GraphGuard invokes a local LLM during analysis. Expect fan activity and brief CPU/thermal load while the scan runs — this is normal. The chip's thermal protection handles it automatically.

> **Hardware:** Developed and tested on Apple Silicon (M5 Pro, 48GB unified memory). Runs well on any Apple Silicon chip (M1 and later) or modern CPU with 16GB+ RAM. Performance scales with available memory — more RAM means larger context and faster inference.

---

## Installation

```bash
git clone https://github.com/RodriguezRepetto/GraphGuard
cd graphguard
uv pip install -e .
```

Or with pip:

```bash
pip install -e .
```

---

## Usage

**Start your local LLM first:**

```bash
llama-server \
  --model /path/to/Qwen3.5-9B-Q4_K_M.gguf \
  --host 127.0.0.1 --port 8080 \
  --ctx-size 8192
```

**Verify setup:**

```bash
graphguard check
```

**Scan an agent:**

```bash
graphguard scan ./my_agent/
```

**Save report as JSON:**

```bash
graphguard scan ./my_agent/ --format json --output report.json
```

**CI/CD mode (fails on critical or high findings):**

```bash
graphguard scan ./my_agent/ --strict
```

---

## OWASP ASI Coverage

| ID | Vector | Description |
|---|---|---|
| ASI01 | Prompt Injection | User input passed to LLM without sanitization |
| ASI02 | Tool Misuse | Tools called with unvalidated inputs |
| ASI03 | State Leakage | Sensitive fields exposed in shared graph state |
| ASI05 | Supply Chain | Vulnerable dependency versions |
| ASI06 | Privilege Escalation | Powerful tools accessible without authorization |
| ASI07 | Inter-Node Validation | Raw LLM output passed directly to next node |
| ASI08 | Memory Poisoning | Persistent state written without validation |

---

## Architecture

GraphGuard is itself a LangGraph agent — a pipeline of four nodes:

```
parser_node → analyzer_node → scorer_node → reporter_node
```

- **parser_node** — walks the target directory, parses `.py`, `.js`, and `.ts` files using Python's `ast` module and tree-sitter respectively
- **analyzer_node** — sends parsed AST to local LLM (Qwen3.5-9B), receives findings as structured JSON
- **scorer_node** — validates, deduplicates, and sorts findings by severity
- **reporter_node** — renders Rich console output and serializes the final JSON report

---

## Running Tests

```bash
python -m pytest graphguard/tests/ -v
```

---

## Portfolio Context

GraphGuard is part of a two-project portfolio combining offensive and defensive AI security:

- **ReconAgent** — autonomous LangGraph recon agent for offensive security (nmap, gobuster, ffuf)
- **GraphGuard** — static security auditor for LangGraph agent pipelines

Both projects use the same architecture: Python nodes, LangGraph graph state, local LLM for fast analysis escalating to larger models for complex reasoning.

---

## License

MIT