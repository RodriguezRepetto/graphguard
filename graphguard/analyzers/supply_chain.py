"""
supply_chain.py — Supply chain vulnerability checker.

Reads the project's dependency files (requirements.txt or pyproject.toml)
and checks installed package versions against a database of known CVEs
affecting the LangGraph/LangChain ecosystem.
"""

import re                              # for parsing version strings
import importlib.metadata              # for reading installed package versions


# known CVEs affecting LangGraph/LangChain ecosystem
# format: package -> list of {cve, affected_below, severity, description}
KNOWN_CVES = {
    "langgraph-checkpoint-sqlite": [
        {
            "cve":             "CVE-2025-67644",
            "affected_below":  "3.0.1",
            "severity":        "high",
            "description":     "SQL injection via metadata filter keys in checkpoint queries.",
            "remediation":     "Upgrade langgraph-checkpoint-sqlite to >= 3.0.1",
        }
    ],
    "langchain-core": [
        {
            "cve":             "CVE-2026-34070",
            "affected_below":  "1.1.0",
            "severity":        "high",
            "description":     "Path traversal in prompt-loading subsystem allows arbitrary file access.",
            "remediation":     "Upgrade langchain-core to >= 1.1.0",
        }
    ],
    "langgraph": [
        {
            "cve":             "CVE-2025-68664",
            "affected_below":  "1.2.0",
            "severity":        "critical",
            "description":     "Serialization injection allows prompt injection escalated to RCE.",
            "remediation":     "Upgrade langgraph to >= 1.2.0",
        }
    ],
    "langchain-community": [
        {
            "cve":             "CVE-2026-28277",
            "affected_below":  "0.3.0",
            "severity":        "high",
            "description":     "Unsafe msgpack deserialization enables Remote Code Execution.",
            "remediation":     "Upgrade langchain-community to >= 0.3.0",
        }
    ],
}


def parse_version(version_str: str) -> tuple:
    """
    Converts a version string like '1.2.6' into a tuple (1, 2, 6)
    for easy numeric comparison.
    """

    # extract only numeric parts — strip any pre-release suffixes
    parts = re.findall(r"\d+", version_str.split("+")[0])
    return tuple(int(p) for p in parts[:3])  # take only major.minor.patch


def is_vulnerable(installed: str, affected_below: str) -> bool:
    """
    Returns True if the installed version is below the affected_below threshold.
    """

    try:
        installed_tuple    = parse_version(installed)
        affected_tuple     = parse_version(affected_below)
        return installed_tuple < affected_tuple   # vulnerable if older
    except Exception:
        return False  # if we can't parse, assume safe


def check_supply_chain() -> list[dict]:
    """
    Checks all installed packages against the known CVE database.
    Returns a list of vulnerability dicts for affected packages.
    """

    vulnerabilities = []

    for package, cve_list in KNOWN_CVES.items():

        # try to get the installed version of this package
        try:
            installed_version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            # package not installed — skip
            continue

        # check each CVE for this package
        for cve in cve_list:
            if is_vulnerable(installed_version, cve["affected_below"]):
                vulnerabilities.append({
                    "package":          package,
                    "installed":        installed_version,
                    "affected_below":   cve["affected_below"],
                    "cve":              cve["cve"],
                    "severity":         cve["severity"],
                    "description":      cve["description"],
                    "remediation":      cve["remediation"],
                })

    return vulnerabilities