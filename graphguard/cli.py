"""
cli.py — GraphGuard CLI entry point.

Defines the Typer CLI with three subcommands:
  graphguard scan    — runs the full security audit pipeline
  graphguard check   — verifies llama-server is reachable
  graphguard version — prints the current version
"""

import sys
import json
import httpx
import typer
from pathlib import Path
from rich.console import Console
from graphguard.graph import app_graph

app = typer.Typer(
    name="graphguard",
    help="Security linter for LangGraph agent pipelines.",
    add_completion=False,
)

console = Console()

VERSION = "0.1.0"

# fast model llama-server endpoint — used by the check command
LLAMA_SERVER_URL = "http://127.0.0.1:8080/v1/chat/completions"

# valid output format values
VALID_FORMATS = {"text", "json"}


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Path to the LangGraph agent directory or file to scan.",
    ),
    format: str = typer.Option(
        "text",
        "--format", "-f",
        help="Output format: text (default), json.",
    ),
    output: Path = typer.Option(
        None,
        "--output", "-o",
        help="Save report to file instead of printing to console.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Exit with code 1 if any Critical or High findings are found.",
    ),
    model: str = typer.Option(
        "fast",
        "--model", "-m",
        help="Model to use: fast (Qwen3.5-9B) or reasoning (Qwen3.5-35B-A3B).",
    ),
    timeout: float = typer.Option(
        120.0,
        "--timeout", "-t",
        help="Per-LLM-call timeout in seconds. Raise this on slower hardware "
             "(e.g. M1 16GB) or when file batching produces larger prompts.",
    ),
    workers: int = typer.Option(
        2,
        "--workers", "-w",
        help="Number of GraphGuard-side worker threads for concurrent LLM calls. "
             "This only speeds things up if llama-server is started with "
             "--parallel N >= this value and enough KV-cache per slot; "
             "otherwise requests just queue up server-side with no gain. On "
             "RAM-constrained hardware (e.g. M1 16GB), keep this low (or even 1 "
             "for fully serial behavior) and do NOT raise llama-server's "
             "--parallel to match — that reserves more KV-cache and can make "
             "things slower, not faster. On hardware with headroom (e.g. M5 Pro "
             "48GB) both sides can be raised together.",
    ),
):
    """
    Scan a LangGraph agent for security vulnerabilities.
    Runs the full parser -> analyzer -> scorer -> reporter pipeline.
    """

    # validate --format before running the pipeline
    if format not in VALID_FORMATS:
        console.print(
            f"[bold red]✗[/bold red] Invalid format '{format}'. "
            f"Valid options: {', '.join(sorted(VALID_FORMATS))}"
        )
        sys.exit(1)

    # warn when --format text --output is used: Rich output cannot be written to
    # a file, so the saved file will contain JSON regardless of the format flag
    if format == "text" and output:
        console.print(
            f"[yellow]⚠ Note: Rich console output cannot be saved to file. "
            f"{output} will be saved as JSON.[/yellow]"
        )

    # build the initial state — model and timeout are passed through to analyzer_node
    initial_state = {
        "target_path":   target,
        "source_files":  [],
        "parsed_ast":    {},
        "findings":      [],
        "scored":        False,
        "report":        {},
        "error":         None,
        "model":            model,
        "timeout":          timeout,
        "skipped_files":    [],
        "workers":          workers,
        "connection_error": None,
    }

    result = app_graph.invoke(initial_state)

    # surface any pipeline error (e.g., target path not found)
    if result.get("error"):
        console.print(f"[bold red]✗[/bold red] {result['error']}")
        sys.exit(1)

    report = result["report"]

    if format == "json":
        json_output = json.dumps(report, indent=2)
        if output:
            output.write_text(json_output)
            console.print(f"[dim]Report saved to {output}[/dim]")
        else:
            console.print_json(json_output)

    elif output:
        output.write_text(json.dumps(report, indent=2))
        console.print(f"[dim]Report saved to {output}[/dim]")

    if strict:
        summary = report.get("summary", {})
        if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0:
            console.print(
                "[bold red]✗ Strict mode: critical or high findings detected.[/bold red]"
            )
            sys.exit(1)


@app.command()
def check():
    """
    Verify that llama-server is reachable and check for known vulnerable dependencies.
    Run this before scanning to ensure the environment is safe and ready.
    """

    from graphguard.analyzers.supply_chain import check_supply_chain

    console.print(f"\n[bold white]GraphGuard[/bold white] v{VERSION}\n")

    try:
        response = httpx.post(
            LLAMA_SERVER_URL,
            json={
                "model":      "qwen3.5-9b",
                "messages":   [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            },
            timeout=10.0,
        )
        response.raise_for_status()
        console.print("[bold green]✓[/bold green] llama-server reachable at 127.0.0.1:8080")
        console.print("[bold green]✓[/bold green] ready to scan\n")

    except httpx.ConnectError:
        console.print("[bold red]✗[/bold red] llama-server not reachable at 127.0.0.1:8080")
        console.print("[dim]  Start it with: llama-server --model <path> --port 8080[/dim]\n")
        sys.exit(1)

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] unexpected error: {e}\n")
        sys.exit(1)

    console.print("[bold white]Checking dependencies for known CVEs...[/bold white]")
    vulns = check_supply_chain()

    if not vulns:
        console.print("[bold green]✓[/bold green] No known vulnerable dependencies found.\n")
    else:
        for v in vulns:
            console.print(
                f"[bold red]✗[/bold red] [bold]{v['package']}[/bold] {v['installed']} — "
                f"{v['cve']} ({v['severity'].upper()})"
            )
            console.print(f"  [dim]{v['description']}[/dim]")
            console.print(f"  [yellow]Fix: {v['remediation']}[/yellow]\n")


@app.command()
def version():
    """Print the current GraphGuard version."""
    console.print(f"graphguard v{VERSION}")


if __name__ == "__main__":
    app()
