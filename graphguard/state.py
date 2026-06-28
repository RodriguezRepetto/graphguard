"""
state.py — GraphGuard shared state schema.

Defines the data structures that flow through the LangGraph pipeline.
Every node reads from and writes to this state.
"""

from typing import TypedDict, List, Optional
from pydantic import BaseModel
from enum import Enum


class Severity(str, Enum):
    """Severity levels for security findings, following CVSS conventions."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class Finding(BaseModel):
    """
    A single security finding produced by an analyzer.
    This is the core data unit of GraphGuard.
    """
    id:           str            # unique finding ID, e.g. "GG-001"
    owasp_id:     str            # OWASP ASI reference, e.g. "ASI01"
    title:        str            # short human-readable title
    description:  str            # detailed explanation of the vulnerability
    severity:     Severity       # critical / high / medium / low
    file:         str            # source file where the issue was found
    line:         Optional[int]  # line number in the source file, if known
    remediation:  str            # concrete fix recommendation


class GraphGuardState(TypedDict):
    """
    LangGraph state that flows through all four nodes.
    Each node receives this dict and returns a partial update.
    """
    target_path:   str            # path to the agent directory or file being scanned
    source_files:  List[str]      # list of .py file paths found in target
    parsed_ast:    dict           # structured representation extracted by parser_node
    findings:      List[Finding]  # findings accumulated by analyzer_node
    scored:        bool           # flag set to True after scorer_node runs
    report:        dict           # final structured report produced by reporter_node
    error:         Optional[str]  # any fatal error message, None if clean run
