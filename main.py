"""
main.py — thin compatibility shim for the `graphguard` console script.

The real CLI implementation lives in graphguard/cli.py (the module
pyproject.toml's [project.scripts] entry actually points to). This file
used to duplicate that Typer app; the duplicate has been removed so
there is a single source of truth for CLI flags going forward.

Kept only so `python main.py` still works during local development,
and so the already-installed console script (which was generated
pointing at `main:app` before pyproject.toml was updated) picks up
the real, up-to-date app without needing a reinstall.
"""

from graphguard.cli import app  # single source of truth for all CLI commands

if __name__ == "__main__":
    app()
