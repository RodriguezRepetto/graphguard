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
- **Smart filtering** — automatically detects LangGraph-relevant files and ignores node_modules, build artifacts, and dependencies. Point it at your entire project — GraphGuard figures out what to scan.
- **7 OWASP ASI vectors** — prompt injection, tool misuse, state leakage, supply chain, privilege escalation, inter-node validation, memory poisoning
- **Batched analysis** — small files are automatically grouped into a single LLM call instead of one call per file, cutting round-trips on projects with many small modules
- **Parallel analysis** — configurable `--workers` for concurrent LLM calls, coordinated with `llama-server`'s own `--parallel` slots (see [Performance tuning](#performance-tuning---timeout-and---workers))
- **Configurable timeout** — `--timeout` per LLM call, useful on slower hardware or with larger batched prompts
- **Schema-constrained output** — findings are requested via `response_format`/JSON schema when the local `llama-server` build supports it, for more reliable structured output
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

**Tune timeout and concurrency for your hardware:**

```bash
graphguard scan ./my_agent/ --timeout 240 --workers 2
```

**Tip: scan a specific path while iterating, not the whole project every time**

```bash
graphguard scan ./my_agent/nodes/analyzer.py
graphguard scan ./my_agent/nodes/
```

If you're actively working on one file or module, point GraphGuard directly at it instead of
scanning the entire project on every run. Each call to the LLM (or batch of calls, see
[Performance tuning](#performance-tuning---timeout-and---workers) below) takes real time — on
constrained hardware, a full-project scan can take several minutes, while a single file or
directory comes back in seconds. Run the full scan (`graphguard scan .`) when you want a
complete audit — before a commit, before a release, or once in a while to catch anything an
incremental scan wouldn't — but for the tight loop of "change something, check it," scanning
just the part you touched gives a much faster feedback cycle.

---

## Performance tuning: `--timeout` and `--workers`

- `--timeout` (default `120.0`, seconds) — per-LLM-call timeout. Small file batching (files
  are grouped into fewer, larger requests automatically) means each call can take longer than
  before; raise this on slower hardware or if you see files reported as skipped due to timeout.
- `--workers` (default `2`) — number of GraphGuard-side threads used to call the LLM concurrently.

**These two client-side flags are not the same thing as `llama-server`'s own `--parallel N`
flag**, and raising GraphGuard's `--workers` alone does **not** guarantee a speedup:

- GraphGuard's `--workers` controls how many requests *this tool* fires off at once.
- `llama-server`'s `--parallel N` controls how many of those requests the model can actually
  process *simultaneously*. If `llama-server` is running with its default single slot, extra
  workers on the GraphGuard side just queue up behind each other server-side — no time is saved,
  only extra open connections.
- Both sides need to be coordinated for parallel workers to pay off, and `--parallel N` on
  `llama-server` reserves additional KV-cache per slot, which costs RAM.

Guidance by hardware:
- **RAM-constrained (e.g. M1 16GB):** keep `--workers` low (the default `2`, or `1` to force
  fully serial behavior) and do **not** raise `llama-server --parallel` to match — the extra
  KV-cache reservation can make things slower, not faster, on tight memory.
- **Headroom available (e.g. M5 Pro 48GB):** both `--workers` and `llama-server --parallel N`
  can be raised together, since there's RAM to sustain multiple KV-caches at once.

**How to actually enable parallel speedup (both sides, coordinated):**

```bash
# llama-server: --ctx-size is split across --parallel slots, so scale it up
# to keep the same effective context per slot (here: 2 slots x 8192 = 16384)
llama-server --model /path/to/Qwen3.5-9B-Q4_K_M.gguf \
  --host 127.0.0.1 --port 8080 \
  --ctx-size 16384 --parallel 2

# GraphGuard: match --workers to llama-server's --parallel value
graphguard scan ./my_agent/ --workers 2
```

Forgetting to raise `--ctx-size` when adding `--parallel N` is a common way to silently shrink
the context available per request — each slot only gets `ctx-size / parallel` tokens, which can
make batched prompts (see [Batching](#features) above) more likely to hit the truncation limit.

Measured example (not a formal benchmark, just one real run for reference): on an Apple M5 Pro
48GB, scanning `tests/vulnerable_agent/` (3 files, 2 LLM calls after batching) went from **83.4s**
with `--workers 1` down to **64.0s** with `--workers 2` + `llama-server --parallel 2` — roughly a
**23% reduction**. Your numbers will depend on file count, batch sizes, and hardware; this is a
real data point, not a guaranteed multiplier.

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
- **analyzer_node** — sends parsed AST to local LLM (Qwen3.5-9B), batching small files into fewer calls and running calls across configurable worker threads; requests schema-constrained JSON output where the local `llama-server` build supports it
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