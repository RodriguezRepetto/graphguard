"""
test_analyzers.py — Unit tests for the scorer_node and supply chain checker.

Tests verify that scoring, deduplication, validation and CVE detection
work correctly without requiring the LLM to be running.
"""

import unittest
from graphguard.state import Finding, Severity
from graphguard.nodes.scorer import deduplicate, validate_finding, scorer_node
from graphguard.analyzers.supply_chain import parse_version, is_vulnerable, check_supply_chain


class TestParseVersion(unittest.TestCase):
    """Tests for the version string parser."""

    def test_standard_version(self):
        """Standard semver string is parsed correctly."""
        self.assertEqual(parse_version("1.2.6"), (1, 2, 6))

    def test_short_version(self):
        """Two-part version string is handled."""
        self.assertEqual(parse_version("1.2"), (1, 2))

    def test_version_with_suffix(self):
        """Pre-release suffix is stripped correctly."""
        self.assertEqual(parse_version("1.2.6+local"), (1, 2, 6))


class TestIsVulnerable(unittest.TestCase):
    """Tests for the vulnerability version comparator."""

    def test_older_version_is_vulnerable(self):
        """An installed version older than threshold is flagged."""
        self.assertTrue(is_vulnerable("1.0.0", "1.2.0"))

    def test_exact_threshold_is_safe(self):
        """An installed version equal to threshold is safe."""
        self.assertFalse(is_vulnerable("1.2.0", "1.2.0"))

    def test_newer_version_is_safe(self):
        """An installed version newer than threshold is safe."""
        self.assertFalse(is_vulnerable("2.0.0", "1.2.0"))


class TestValidateFinding(unittest.TestCase):
    """Tests for the finding validator in scorer_node."""

    def _make_finding(self, **kwargs) -> Finding:
        """Helper: create a Finding with sensible defaults."""
        defaults = {
            "id":          "GG-001",
            "owasp_id":    "ASI01",
            "title":       "Test finding",
            "description": "A long enough description to pass validation.",
            "severity":    Severity.HIGH,
            "file":        "agent.py",
            "line":        10,
            "remediation": "Fix it.",
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_valid_finding_passes(self):
        """A well-formed finding passes validation."""
        finding = self._make_finding()
        self.assertTrue(validate_finding(finding))

    def test_unknown_owasp_id_fails(self):
        """A finding with an unknown OWASP ID is rejected."""
        finding = self._make_finding(owasp_id="ASI99")
        self.assertFalse(validate_finding(finding))

    def test_short_description_fails(self):
        """A finding with a description shorter than 10 chars is rejected."""
        finding = self._make_finding(description="Too short")
        self.assertFalse(validate_finding(finding))

    def test_untitled_finding_fails(self):
        """A finding with the default untitled title is rejected."""
        finding = self._make_finding(title="Untitled finding")
        self.assertFalse(validate_finding(finding))


class TestDeduplicate(unittest.TestCase):
    """Tests for the deduplication logic in scorer_node."""

    def _make_finding(self, id, severity, owasp_id="ASI01", line=10) -> Finding:
        """Helper: create a minimal Finding."""
        return Finding(
            id=          id,
            owasp_id=    owasp_id,
            title=       "Test finding",
            description= "A long enough description to pass validation.",
            severity=    severity,
            file=        "agent.py",
            line=        line,
            remediation= "Fix it.",
        )

    def test_no_duplicates_unchanged(self):
        """A list with no duplicates is returned as-is."""
        findings = [
            self._make_finding("GG-001", Severity.HIGH,   line=10),
            self._make_finding("GG-002", Severity.MEDIUM, line=20),
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 2)

    def test_duplicate_keeps_highest_severity(self):
        """When duplicates exist, the highest severity is kept."""
        findings = [
            self._make_finding("GG-001", Severity.MEDIUM, line=10),
            self._make_finding("GG-002", Severity.CRITICAL, line=10),  # same location
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 1)                    # only one kept
        self.assertEqual(result[0].severity, Severity.CRITICAL)  # highest wins


class TestScorerNode(unittest.TestCase):
    """Tests for the scorer_node LangGraph node function."""

    def _make_finding(self, id, severity) -> Finding:
        """Helper: create a valid Finding."""
        return Finding(
            id=          id,
            owasp_id=    "ASI01",
            title=       "Test finding",
            description= "A long enough description to pass validation.",
            severity=    severity,
            file=        "agent.py",
            line=        10,
            remediation= "Fix it.",
        )

    def test_scorer_sorts_by_severity(self):
        """scorer_node returns findings sorted critical first."""
        state = {
            "target_path":  ".",
            "source_files": [],
            "parsed_ast":   {},
            "findings": [
                self._make_finding("GG-001", Severity.LOW),
                self._make_finding("GG-002", Severity.CRITICAL),
                self._make_finding("GG-003", Severity.MEDIUM),
            ],
            "scored": False,
            "report": {},
            "error":  None,
        }
        result = scorer_node(state)
        findings = result["findings"]
        self.assertEqual(findings[0].severity, Severity.CRITICAL)  # critical first
        self.assertTrue(result["scored"])                           # flag set

    def test_scorer_empty_findings(self):
        """scorer_node handles empty findings list without errors."""
        state = {
            "target_path":  ".",
            "source_files": [],
            "parsed_ast":   {},
            "findings":     [],
            "scored":       False,
            "report":       {},
            "error":        None,
        }
        result = scorer_node(state)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["scored"])


if __name__ == "__main__":
    unittest.main()