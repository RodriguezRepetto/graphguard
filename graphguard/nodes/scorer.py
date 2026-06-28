"""
scorer.py — scorer_node implementation.

Validates and deduplicates findings produced by the analyzer_node.
Maps each finding to its OWASP ASI identifier and ensures severity
levels are consistent before passing to the reporter.
"""

from graphguard.state import GraphGuardState, Finding, Severity


# severity priority order — used for deduplication (keep highest)
SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH:     3,
    Severity.MEDIUM:   2,
    Severity.LOW:      1,
}

# valid OWASP ASI IDs that GraphGuard covers
VALID_OWASP_IDS = {"ASI01", "ASI02", "ASI03", "ASI05", "ASI06", "ASI07", "ASI08"}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Removes duplicate findings based on file + line + owasp_id.
    When duplicates exist, keeps the one with the highest severity.
    """

    seen = {}  # key: (file, line, owasp_id) -> Finding

    for finding in findings:
        # build a deduplication key from location and vector
        key = (finding.file, finding.line, finding.owasp_id)

        if key not in seen:
            # first time seeing this finding — store it
            seen[key] = finding
        else:
            # duplicate found — keep the one with higher severity
            existing_rank = SEVERITY_RANK.get(seen[key].severity, 0)
            new_rank      = SEVERITY_RANK.get(finding.severity, 0)
            if new_rank > existing_rank:
                seen[key] = finding  # replace with higher severity finding

    return list(seen.values())


def validate_finding(finding: Finding) -> bool:
    """
    Validates that a finding has the minimum required fields.
    Returns False if the finding should be discarded.
    """

    # must have a non-empty title
    if not finding.title or finding.title == "Untitled finding":
        return False

    # must reference a known OWASP ASI vector
    if finding.owasp_id not in VALID_OWASP_IDS:
        print(f"[scorer] discarding finding with unknown OWASP ID: {finding.owasp_id}")
        return False

    # must have a description longer than 10 characters
    if not finding.description or len(finding.description) < 10:
        return False

    return True


def scorer_node(state: GraphGuardState) -> dict:
    """
    Node 3: validates, deduplicates and scores findings from analyzer_node.
    Returns the cleaned findings list with scored flag set to True.
    """

    raw_findings = state["findings"]   # findings from analyzer_node
    print(f"[scorer] received {len(raw_findings)} findings to score")

    # step 1: validate each finding — discard malformed ones
    valid_findings = [f for f in raw_findings if validate_finding(f)]
    discarded = len(raw_findings) - len(valid_findings)
    if discarded > 0:
        print(f"[scorer] discarded {discarded} invalid findings")

    # step 2: deduplicate — remove redundant findings
    unique_findings = deduplicate(valid_findings)
    duplicates = len(valid_findings) - len(unique_findings)
    if duplicates > 0:
        print(f"[scorer] removed {duplicates} duplicate findings")

    # step 3: sort by severity — critical first, low last
    sorted_findings = sorted(
        unique_findings,
        key=lambda f: SEVERITY_RANK.get(f.severity, 0),
        reverse=True,   # highest severity first
    )

    print(f"[scorer] {len(sorted_findings)} findings after scoring")

    return {
        "findings": sorted_findings,  # clean, sorted, deduplicated findings
        "scored":   True,             # marks scoring phase as complete
    }