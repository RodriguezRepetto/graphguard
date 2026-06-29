"""
test_analyzers.py — Unit tests for the scorer_node, analyzer helpers, and supply chain checker.

Tests verify that scoring, deduplication, validation, LLM response parsing,
and CVE detection work correctly without requiring the LLM to be running.
"""

import json
import unittest
from graphguard.state import Finding, Severity
from graphguard.nodes.scorer import deduplicate, validate_finding, scorer_node
from graphguard.nodes.analyzer import parse_llm_response
from graphguard.analyzers.supply_chain import parse_version, is_vulnerable, check_supply_chain


class TestParseVersion(unittest.TestCase):
    """Tests for the version string parser."""

    def test_standard_version(self):
        """Standard semver string is parsed correctly."""
        self.assertEqual(parse_version("1.2.6"), (1, 2, 6))

    def test_short_version(self):
        """Two-part version string is padded to a 3-tuple."""
        self.assertEqual(parse_version("1.2"), (1, 2, 0))

    def test_version_with_suffix(self):
        """Pre-release suffix is stripped correctly."""
        self.assertEqual(parse_version("1.2.6+local"), (1, 2, 6))

    def test_empty_string_returns_zero_tuple(self):
        """Empty version string returns (0, 0, 0) instead of an empty tuple."""
        self.assertEqual(parse_version(""), (0, 0, 0))

    def test_non_digit_string_returns_zero_tuple(self):
        """Non-digit version string returns (0, 0, 0) instead of an empty tuple."""
        self.assertEqual(parse_version("abc"), (0, 0, 0))


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

    def test_two_part_version_equal_to_three_part_threshold_is_safe(self):
        """F6 regression: '1.2' must not be reported as vulnerable against '1.2.0'."""
        self.assertFalse(is_vulnerable("1.2", "1.2.0"))


class TestParseLlmResponse(unittest.TestCase):
    """Tests for parse_llm_response — including the F1 regression (return [] bug)."""

    def _make_raw_json(self, overrides: dict = None) -> str:
        """Build a minimal valid LLM response JSON string."""
        item = {
            "id":          "GG-001",
            "owasp_id":    "ASI01",
            "title":       "Prompt injection via user input",
            "description": "User input is passed directly to the LLM prompt without sanitization.",
            "severity":    "high",
            "file":        "agent.py",
            "line":        10,
            "remediation": "Sanitize all user inputs before including them in prompts.",
        }
        if overrides:
            item.update(overrides)
        return json.dumps([item])

    def test_valid_json_returns_findings(self):
        """F1 regression: a valid JSON response must produce at least one Finding."""
        counter = [0]
        findings = parse_llm_response(self._make_raw_json(), counter)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].owasp_id, "ASI01")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_finding_counter_is_incremented(self):
        """The sequential finding ID counter is incremented for each finding."""
        counter = [0]
        parse_llm_response(self._make_raw_json(), counter)
        self.assertEqual(counter[0], 1)

    def test_thinking_block_is_stripped(self):
        """Qwen3 <think>...</think> wrapper is removed before JSON parsing."""
        raw = f"<think>Let me analyze this carefully.</think>\n{self._make_raw_json()}"
        counter = [0]
        findings = parse_llm_response(raw, counter)
        self.assertEqual(len(findings), 1)

    def test_markdown_fences_are_stripped(self):
        """Markdown ```json code fences are removed before JSON parsing."""
        raw = f"```json\n{self._make_raw_json()}\n```"
        counter = [0]
        findings = parse_llm_response(raw, counter)
        self.assertEqual(len(findings), 1)

    def test_invalid_json_returns_empty_list(self):
        """A response that cannot be parsed as JSON returns an empty list, not an error."""
        counter = [0]
        findings = parse_llm_response("this is not valid json at all", counter)
        self.assertEqual(findings, [])

    def test_empty_array_response_returns_empty_list(self):
        """LLM returning [] (no findings) produces an empty list."""
        counter = [0]
        findings = parse_llm_response("[]", counter)
        self.assertEqual(findings, [])

    def test_malformed_finding_is_skipped(self):
        """A finding with an invalid severity value is skipped without crashing."""
        raw = json.dumps([{
            "id":          "GG-001",
            "owasp_id":    "ASI01",
            "title":       "Some finding",
            "description": "A long enough description for this finding.",
            "severity":    "extreme",     # not a valid Severity value
            "file":        "agent.py",
            "line":        5,
            "remediation": "Fix it.",
        }])
        counter = [0]
        findings = parse_llm_response(raw, counter)
        self.assertEqual(findings, [])


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

    def _make_finding(self, id, severity, title="Test finding", owasp_id="ASI01", line=10) -> Finding:
        """Helper: create a minimal Finding."""
        return Finding(
            id=          id,
            owasp_id=    owasp_id,
            title=       title,
            description= "A long enough description to pass validation.",
            severity=    severity,
            file=        "agent.py",
            line=        line,
            remediation= "Fix it.",
        )

    def test_no_duplicates_unchanged(self):
        """A list with no duplicates (distinct titles) is returned as-is."""
        findings = [
            self._make_finding("GG-001", Severity.HIGH,   title="Prompt injection via query param",  line=10),
            self._make_finding("GG-002", Severity.MEDIUM, title="State leakage of auth token field", line=20, owasp_id="ASI03"),
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 2)

    def test_duplicate_keeps_highest_severity(self):
        """When duplicates exist (same file+owasp_id+title), the highest severity is kept."""
        findings = [
            self._make_finding("GG-001", Severity.MEDIUM, line=10),
            self._make_finding("GG-002", Severity.CRITICAL, line=10),  # same title → duplicate
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, Severity.CRITICAL)

    def test_no_collision_on_none_line_with_different_titles(self):
        """F5 regression: findings with line=None but distinct titles are both kept."""
        findings = [
            self._make_finding("GG-001", Severity.HIGH, title="Injection via input A", line=None),
            self._make_finding("GG-002", Severity.HIGH, title="Injection via input B", line=None),
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 2)

    def test_same_title_and_none_line_deduplicates(self):
        """Two findings with identical file+owasp_id+title and line=None are merged."""
        findings = [
            self._make_finding("GG-001", Severity.MEDIUM, title="Same issue", line=None),
            self._make_finding("GG-002", Severity.HIGH,   title="Same issue", line=None),
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, Severity.HIGH)


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

    def _base_state(self, findings):
        return {
            "target_path":  ".",
            "source_files": [],
            "parsed_ast":   {},
            "findings":     findings,
            "scored":       False,
            "report":       {},
            "error":        None,
            "model":        "fast",
        }

    def test_scorer_sorts_by_severity(self):
        """scorer_node returns findings sorted critical first."""
        state = self._base_state([
            self._make_finding("GG-001", Severity.LOW),
            self._make_finding("GG-002", Severity.CRITICAL),
            self._make_finding("GG-003", Severity.MEDIUM),
        ])
        result = scorer_node(state)
        findings = result["findings"]
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertTrue(result["scored"])

    def test_scorer_empty_findings(self):
        """scorer_node handles empty findings list without errors."""
        state = self._base_state([])
        result = scorer_node(state)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["scored"])


if __name__ == "__main__":
    unittest.main()
