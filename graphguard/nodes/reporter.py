"""
reporter.py — reporter_node implementation.

Serializes scored findings into a structured JSON report and
renders a summary to the console using Rich for colored output.
"""

import json                              # for JSON serialization
from datetime import datetime, timezone  # for report timestamp
from rich.console import Console         # Rich console for colored output
from rich.table import Table             # Rich table for findings summary
from rich import box                     # Rich box styles for table borders
from graphguard.state import GraphGuardState, Finding, Severity


# Rich console instance — used for all terminal output
console = Console()

# color mapping per severity for Rich markup
SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "bold blue",
    Severity.LOW:      "dim white",
}


def build_summary(findings: list[Finding]) -> dict:
    """
    Counts findings per severity level.
    Returns a dict with counts for critical, high, medium, low.
    """

    # initialize all counts to zero
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # increment the appropriate counter for each finding
    for finding in findings:
        severity_key = finding.severity.value  # e.g. "critical", "high"
        if severity_key in summary:
            summary[severity_key] += 1

    return summary


def render_console_output(findings: list[Finding], summary: dict) -> None:
    """
    Renders a Rich-formatted summary table and detailed findings to the terminal.
    Shows each finding with severity, OWASP ID, title, file, line, and remediation.
    """

    # print GraphGuard header
    console.print("\n[bold white]GraphGuard[/bold white] — Security Audit Report", style="bold")
    console.print(f"[dim]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]\n")

    if not findings:
        # no findings — print a clean result
        console.print("[bold green]✓ No security issues found.[/bold green]\n")
        return

    # build the findings summary table
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold white")
    table.add_column("ID",       style="dim",  width=8)
    table.add_column("Severity", width=10)
    table.add_column("OWASP",    style="dim",  width=7)
    table.add_column("Title",    width=38)
    table.add_column("Location", style="dim",  width=24)

    # add one row per finding
    for finding in findings:
        color    = SEVERITY_COLOR.get(finding.severity, "white")
        location = f"{finding.file}:{finding.line}" if finding.line else finding.file

        table.add_row(
            finding.id,
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.owasp_id,
            finding.title,
            location,
        )

    console.print(table)

    # print severity summary line
    console.print(
        f"[bold red]{summary['critical']} critical[/bold red]  "
        f"[bold yellow]{summary['high']} high[/bold yellow]  "
        f"[bold blue]{summary['medium']} medium[/bold blue]  "
        f"[dim]{summary['low']} low[/dim]\n"
    )

    # print detailed findings with description and remediation
    console.print("[bold white]── Detailed Findings ──────────────────────────────[/bold white]\n")

    for finding in findings:
        color    = SEVERITY_COLOR.get(finding.severity, "white")
        location = f"{finding.file}:{finding.line}" if finding.line else finding.file

        # finding header
        console.print(
            f"[{color}][{finding.severity.value.upper()}][/{color}] "
            f"[bold]{finding.id}[/bold] · {finding.owasp_id} · {finding.title}"
        )

        # location
        console.print(f"  [dim]→ {location}[/dim]")

        # description
        console.print(f"  [white]{finding.description}[/white]")

        # remediation — split by newline for step-by-step display
        console.print(f"  [bold green]Fix:[/bold green]")
        for line in finding.remediation.split("\n"):
            line = line.strip()
            if line:
                console.print(f"    [green]{line}[/green]")

        console.print()  # blank line between findings

def reporter_node(state: GraphGuardState) -> dict:
    """
    Node 4: builds the final report from scored findings.
    Renders console output and returns the structured JSON report.
    """

    findings = state["findings"]   # scored and sorted findings from scorer_node
    print(f"[reporter] building report for {len(findings)} findings")

    # step 1: build the summary counts
    summary = build_summary(findings)

    # step 2: serialize findings to JSON-safe dicts
    findings_json = [
        {
            "id":          f.id,
            "owasp_id":    f.owasp_id,
            "title":       f.title,
            "description": f.description,
            "severity":    f.severity.value,
            "file":        f.file,
            "line":        f.line,
            "remediation": f.remediation,
        }
        for f in findings
    ]

    # step 3: build the full report dict
    report = {
        "graphguard_version": "0.1.0",                                          # tool version
        "timestamp":          datetime.now(timezone.utc).isoformat(),           # scan time
        "total_findings":     len(findings),                                    # total count
        "summary":            summary,                                          # per-severity counts
        "findings":           findings_json,                                    # full findings list
    }

    # step 4: render the console output with Rich
    render_console_output(findings, summary)

    return {"report": report}   # final state update - end of pipeline