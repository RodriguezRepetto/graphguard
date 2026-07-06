"""
test_reporter.py — Unit tests for the reporter_node console output.

Tests verify that the timeout-skip warning (Bug 2) is surfaced correctly and
that a clean "no issues found" message is never shown when the scan skipped
files due to a timeout, even when the findings list ends up empty.
"""

import unittest
from graphguard.nodes.reporter import console, render_console_output


class TestRenderConsoleOutputSkips(unittest.TestCase):
    """Tests for the skipped_files warning path in render_console_output()."""

    def _capture(self, findings, summary, skipped_files=None, connection_error=None) -> str:
        """Helper: render console output and return the captured text."""
        with console.capture() as capture:
            render_console_output(findings, summary, skipped_files, connection_error)
        return capture.get()

    def test_no_findings_no_skips_shows_clean_success(self):
        """With nothing skipped and no findings, the clean success message is shown."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        output = self._capture([], summary, skipped_files=[])
        self.assertIn("No security issues found.", output)

    def test_no_findings_with_skips_does_not_show_clean_success(self):
        """Bug 2 regression: skips with zero findings must not print the clean
        success message — the scan was incomplete, not clean."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        skipped = [{"filepath": "slow.py", "reason": "LLM call timed out after 120.0s"}]
        output = self._capture([], summary, skipped_files=skipped)

        self.assertNotIn("No security issues found.", output)
        self.assertIn("skipped due to timeout", output)
        self.assertIn("slow.py", output)

    def test_skips_warning_shown_even_with_findings(self):
        """The timeout warning is shown regardless of whether findings exist."""
        from graphguard.state import Finding, Severity

        finding = Finding(
            id="GG-001", owasp_id="ASI01", title="Test finding",
            description="A long enough description to pass validation.",
            severity=Severity.HIGH, file="agent.py", line=10,
            remediation="Fix it.",
        )
        summary = {"critical": 0, "high": 1, "medium": 0, "low": 0}
        skipped = [{"filepath": "slow.py", "reason": "LLM call timed out after 120.0s"}]
        output = self._capture([finding], summary, skipped_files=skipped)

        self.assertIn("skipped due to timeout", output)

    def test_no_findings_with_connection_error_does_not_show_clean_success(self):
        """Task B regression: an aborted analysis (ConnectError) with zero
        findings must not print the clean success message — the same false-
        success pattern already fixed for timeouts, now fixed for aborts too."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        output = self._capture(
            [], summary, skipped_files=[],
            connection_error="cannot reach llama-server at http://127.0.0.1:8080/v1/chat/completions",
        )

        self.assertNotIn("No security issues found.", output)
        self.assertIn("Analysis aborted", output)
        self.assertIn("could not connect to llama-server", output)

    def test_connection_error_warning_shown_even_with_findings(self):
        """The abort warning is shown regardless of whether findings exist —
        e.g. some batches completed before the ConnectError was hit."""
        from graphguard.state import Finding, Severity

        finding = Finding(
            id="GG-001", owasp_id="ASI01", title="Test finding",
            description="A long enough description to pass validation.",
            severity=Severity.HIGH, file="agent.py", line=10,
            remediation="Fix it.",
        )
        summary = {"critical": 0, "high": 1, "medium": 0, "low": 0}
        output = self._capture(
            [finding], summary,
            connection_error="cannot reach llama-server at http://127.0.0.1:8080/v1/chat/completions",
        )

        self.assertIn("Analysis aborted", output)

    def test_both_connection_error_and_skips_can_show_together(self):
        """Some batches may have timed out before the ConnectError hit —
        both warnings must be shown, not just one clobbering the other."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        skipped = [{"filepath": "slow.py", "reason": "LLM call timed out after 120.0s"}]
        output = self._capture(
            [], summary, skipped_files=skipped,
            connection_error="cannot reach llama-server at http://127.0.0.1:8080/v1/chat/completions",
        )

        self.assertIn("Analysis aborted", output)
        self.assertIn("skipped due to timeout", output)
        self.assertNotIn("No security issues found.", output)


if __name__ == "__main__":
    unittest.main()
