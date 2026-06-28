"""
main.py — GraphGuard CLI entry point.

Defines the Typer CLI with three subcommands:
  graphguard scan    — runs the full security audit pipeline
  graphguard check   — verifies llama-server is reachable
  graphguard version — prints the current version
"""

import sys                               # for exit codes in --strict mode
import json                              # for --format json output
import httpx                             # for check command connectivity test
import typer                             # CLI framework
from pathlib import Path                 # for --output file handling
from rich.console import Console         # for styled terminal output
from graphguard.graph import app_graph   # compiled LangGraph pipeline

# Typer app instance
app = typer.Typer(
    name="graphguard",
    help="Security linter for LangGraph agent pipelines.",
    add_completion=False,                # disable shell completion for now
)

# Rich console for check and version commands
console = Console()

# current version — matches pyproject.toml
VERSION = "0.1.0"

# llama-server URL — same as analyzer_node
LLAMA_SERVER_URL = "http://127.0.0.1:8080/v1/chat/completions"


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
        help="Model to use: fast (Qwen3.5-9B) or reasoning (Qwen3.5-35B).",
    ),
):
    """
    Scan a LangGraph agent for security vulnerabilities.
    Runs the full parser -> analyzer -> scorer -> reporter pipeline.
    """

    # build the initial state with the target path
    initial_state = {
        "target_path":  target,   # path provided by the user
        "source_files": [],       # populated by parser_node
        "parsed_ast":   {},       # populated by parser_node
        "findings":     [],       # populated by analyzer_node
        "scored":       False,    # set to True by scorer_node
        "report":       {},       # populated by reporter_node
        "error":        None,     # set if any node fails
    }

    # invoke the compiled graph — Rich output is handled inside reporter_node
    result = app_graph.invoke(initial_state)
    report = result["report"]

    # handle --format json — print or save structured JSON
    if format == "json":
        json_output = json.dumps(report, indent=2)
        if output:
            # save to file
            output.write_text(json_output)
            console.print(f"[dim]Report saved to {output}[/dim]")
        else:
            # print to console
            console.print_json(json_output)

    # handle --output for text format — save Rich output isn't supported,
    # so we save the JSON report to file regardless and notify the user
    elif output:
        output.write_text(json.dumps(report, indent=2))
        console.print(f"[dim]Report saved to {output}[/dim]")

    # handle --strict — exit 1 if any critical or high findings exist
    if strict:
        summary = report.get("summary", {})
        if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0:
            console.print(
                "[bold red]✗ Strict mode: critical or high findings detected.[/bold red]"
            )
            sys.exit(1)             # non-zero exit code for CI/CD pipelines


@app.command()
def check():
    """
    Verify that llama-server is reachable and check for known vulnerable dependencies.
    Run this before scanning to ensure the environment is safe and ready.
    """

    from graphguard.analyzers.supply_chain import check_supply_chain  # supply chain checker

    console.print(f"\n[bold white]GraphGuard[/bold white] v{VERSION}\n")

    # step 1: check llama-server connectivity
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

    # step 2: check for known vulnerable dependencies
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
    # allow running as `python main.py` during development
    app()