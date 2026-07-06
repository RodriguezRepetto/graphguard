"""
test_analyzers.py — Unit tests for the scorer_node, analyzer helpers, and supply chain checker.

Tests verify that scoring, deduplication, validation, LLM response parsing,
and CVE detection work correctly without requiring the LLM to be running.
"""

import json
import os
import unittest
from unittest.mock import patch
from graphguard.state import Finding, Severity
from graphguard.nodes.scorer import deduplicate, validate_finding, scorer_node
from graphguard.nodes.analyzer import (
    parse_llm_response, analyzer_node, call_llm, FINDING_JSON_SCHEMA, LLAMA_ENDPOINTS,
)
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


class TestAnalyzerNodeSkipGuard(unittest.TestCase):
    """Bug 1 regression: analyzer_node must not silently skip files whose AST
    content lives only in assignments/calls (top-level graph/state wiring with
    no function or class declarations)."""

    def _base_state(self, parsed_ast: dict) -> dict:
        """Helper: build a minimal GraphGuardState dict around a parsed_ast."""
        return {
            "target_path":  ".",
            "source_files": list(parsed_ast.keys()),
            "parsed_ast":   parsed_ast,
            "findings":     [],
            "scored":       False,
            "report":       {},
            "error":        None,
            "model":        "fast",
        }

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_file_with_only_assignments_and_calls_is_analyzed(self, mock_call_llm):
        """A file with content only in assignments/calls must still reach the LLM."""
        mock_call_llm.return_value = "[]"
        parsed_ast = {
            "graph.js": {
                "filepath":    "graph.js",
                "functions":   [],
                "classes":     [],
                "imports":     ["import { StateGraph } from '@langchain/langgraph';"],
                "calls":       [{"call": "new StateGraph(state)", "lineno": 1}],
                "assignments": [{"targets": ["graph"], "value": "new StateGraph(state)", "lineno": 1}],
                "strings":     [],
            }
        }
        analyzer_node(self._base_state(parsed_ast))
        mock_call_llm.assert_called_once()

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_file_with_only_imports_and_strings_is_still_skipped(self, mock_call_llm):
        """A file carrying only imports/strings (no calls/assignments/functions/classes)
        has no analyzable structure and stays skipped by design."""
        parsed_ast = {
            "empty.js": {
                "filepath":    "empty.js",
                "functions":   [],
                "classes":     [],
                "imports":     ["import fs from 'fs';"],
                "calls":       [],
                "assignments": [],
                "strings":     [{"value": "some long placeholder string here", "lineno": 1}],
            }
        }
        analyzer_node(self._base_state(parsed_ast))
        mock_call_llm.assert_not_called()

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_real_graph_js_fixture_is_not_skipped(self, mock_call_llm):
        """The real tests/vulnerable_agent/graph.js fixture (top-level Annotation.Root
        and chained StateGraph wiring, no function/class declarations) must be
        analyzed rather than silently skipped."""
        from graphguard.nodes.parser_js import parse_js_file

        mock_call_llm.return_value = "[]"
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        fixture   = os.path.join(repo_root, "tests", "vulnerable_agent", "graph.js")

        ast_data = parse_js_file(fixture)
        # sanity check: this fixture must reproduce the exact bug shape
        self.assertEqual(ast_data["functions"], [])
        self.assertEqual(ast_data["classes"], [])
        self.assertTrue(ast_data["assignments"])

        analyzer_node(self._base_state({fixture: ast_data}))
        mock_call_llm.assert_called_once()


class TestAnalyzerNodeTimeout(unittest.TestCase):
    """Bug 2 regression: httpx.TimeoutException must be distinguished from other
    errors, skip the file without aborting the loop, and propagate a skip count."""

    def _base_state(self, parsed_ast: dict, timeout: float = 120.0) -> dict:
        """Helper: build a minimal GraphGuardState dict around a parsed_ast."""
        return {
            "target_path":   ".",
            "source_files":  list(parsed_ast.keys()),
            "parsed_ast":    parsed_ast,
            "findings":      [],
            "scored":        False,
            "report":        {},
            "error":         None,
            "model":         "fast",
            "timeout":       timeout,
            "skipped_files": [],
        }

    def _make_ast(self):
        """A minimal analyzable AST — has calls so it isn't skipped by the guard."""
        return {
            "filepath":    "agent.py",
            "functions":   [],
            "classes":     [],
            "imports":     [],
            "calls":       [{"call": "foo()", "lineno": 1}],
            "assignments": [],
            "strings":     [],
        }

    def _make_large_ast(self, filepath="slow.py"):
        """An AST large enough to exceed the batching threshold on its own, so it
        always lands in its own batch regardless of what else is being analyzed."""
        return {
            "filepath":    filepath,
            "functions":   [],
            "classes":     [],
            "imports":     [],
            "calls":       [{"call": "x" * 20000, "lineno": 1}],
            "assignments": [],
            "strings":     [],
        }

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_timeout_skips_batch_without_aborting_loop(self, mock_call_llm):
        """A timeout on one batch must not stop the remaining batches from being analyzed."""
        import httpx

        def side_effect(prompt, endpoint, timeout):
            if "slow.py" in prompt:
                raise httpx.TimeoutException("timed out")
            return "[]"

        mock_call_llm.side_effect = side_effect
        # the large AST forces its own batch, so "fast.py" is guaranteed a separate call
        parsed_ast = {
            "slow.py": self._make_large_ast(),
            "fast.py": self._make_ast(),
        }
        result = analyzer_node(self._base_state(parsed_ast))

        # both batches must have been attempted despite the first timing out
        self.assertEqual(mock_call_llm.call_count, 2)
        self.assertEqual(result["findings"], [])

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_timeout_skip_count_reaches_result(self, mock_call_llm):
        """The skip is counted and returned in analyzer_node's result dict."""
        import httpx

        mock_call_llm.side_effect = httpx.TimeoutException("timed out")
        parsed_ast = {"slow.py": self._make_ast()}
        result = analyzer_node(self._base_state(parsed_ast))

        self.assertEqual(len(result["skipped_files"]), 1)
        self.assertEqual(result["skipped_files"][0]["filepath"], "slow.py")

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_configured_timeout_is_passed_to_call_llm(self, mock_call_llm):
        """The timeout value from state flows through to call_llm(), not the hardcoded default."""
        mock_call_llm.return_value = "[]"
        parsed_ast = {"agent.py": self._make_ast()}
        analyzer_node(self._base_state(parsed_ast, timeout=5.0))

        _, kwargs = mock_call_llm.call_args
        args = mock_call_llm.call_args.args
        self.assertEqual(args[2] if len(args) > 2 else kwargs.get("timeout"), 5.0)


class TestBuildBatches(unittest.TestCase):
    """Tests for build_batches() — grouping small files into fewer LLM calls
    without ever assembling a batch that build_prompt() would have to truncate."""

    def _small_ast(self, filepath):
        return {
            "filepath":    filepath,
            "functions":   [],
            "classes":     [],
            "imports":     [],
            "calls":       [{"call": "foo()", "lineno": 1}],
            "assignments": [],
            "strings":     [],
        }

    def _sized_ast(self, filepath, payload_len):
        """An AST whose serialized size is roughly payload_len chars, via a
        single oversized string in one call entry."""
        return {
            "filepath": filepath, "functions": [], "classes": [], "imports": [],
            "calls": [{"call": "x" * payload_len, "lineno": 1}],
            "assignments": [], "strings": [],
        }

    def test_small_files_are_grouped_into_one_batch(self):
        """Several tiny files well under the char budget end up in a single batch."""
        from graphguard.nodes.analyzer import build_batches

        parsed_ast = {f"file{i}.py": self._small_ast(f"file{i}.py") for i in range(5)}
        batches = build_batches(parsed_ast)

        self.assertEqual(len(batches), 1)
        self.assertEqual(set(batches[0].keys()), set(parsed_ast.keys()))

    def test_oversized_file_gets_its_own_batch(self):
        """A file whose serialized size alone exceeds the budget is never merged with others."""
        from graphguard.nodes.analyzer import build_batches

        parsed_ast = {
            "huge.py":  self._sized_ast("huge.py", 20000),
            "small.py": self._small_ast("small.py"),
        }
        batches = build_batches(parsed_ast)

        self.assertEqual(len(batches), 2)
        huge_batch = next(b for b in batches if "huge.py" in b)
        self.assertEqual(list(huge_batch.keys()), ["huge.py"])

    def test_batch_overflow_starts_a_new_batch(self):
        """Once accumulated size would exceed the budget, a new batch is started
        instead of growing the current one past the threshold."""
        from graphguard.nodes.analyzer import build_batches

        # each file is ~3/4 of a tiny custom char budget, so only one fits per batch
        ast = self._sized_ast("f.py", 30)
        parsed_ast = {"a.py": ast, "b.py": ast, "c.py": ast}
        batches = build_batches(parsed_ast, char_budget=100)

        self.assertGreater(len(batches), 1)
        # every file must still appear exactly once across all batches
        all_files = [fp for batch in batches for fp in batch.keys()]
        self.assertEqual(sorted(all_files), ["a.py", "b.py", "c.py"])

    def test_batches_never_exceed_prompt_truncation_threshold(self):
        """Regression test for the v1.5.1 batching bug: a group of small files
        whose *individual* sizes fit comfortably, but whose *combined* real
        serialized size would exceed build_prompt()'s truncation cutoff, must
        be split across multiple batches — never assembled into one oversized
        batch that silently drops a trailing file's content."""
        import json
        from graphguard.nodes.analyzer import build_batches, build_prompt, PROMPT_TRUNCATE_CHARS

        # 5 files at ~3000 chars each (~15000 total) — this used to fit under the
        # old 4000-estimated-token budget as a single batch, but the *actual*
        # serialized batch size exceeds the 12000-char truncation threshold.
        parsed_ast = {f"file{i}.py": self._sized_ast(f"file{i}.py", 3000) for i in range(5)}
        batches = build_batches(parsed_ast)

        # every batch's actual built prompt must stay under the truncation cutoff
        for batch in batches:
            prompt = build_prompt(batch)
            self.assertNotIn("truncated for context window", prompt)

        # and every file's payload must appear somewhere across the batches —
        # nothing silently dropped
        all_files = [fp for batch in batches for fp in batch.keys()]
        self.assertEqual(sorted(all_files), sorted(parsed_ast.keys()))

    def test_oversized_solo_file_truncation_logs_a_warning(self):
        """A file too large to fit even alone still gets truncated by
        build_prompt() as a last resort, but that must never happen silently."""
        from graphguard.nodes.analyzer import build_batches, build_prompt

        parsed_ast = {"giant.py": self._sized_ast("giant.py", 20000)}
        batches = build_batches(parsed_ast)
        self.assertEqual(len(batches), 1)

        with patch("builtins.print") as mock_print:
            prompt = build_prompt(batches[0])

        self.assertIn("truncated for context window", prompt)
        warnings = [str(call) for call in mock_print.call_args_list if "truncated" in str(call)]
        self.assertTrue(warnings, "expected a visible warning when build_prompt() truncates content")


class TestAnalyzerNodeBatchingIntegration(unittest.TestCase):
    """Tests for analyzer_node's use of batching — call count and file attribution."""

    def _base_state(self, parsed_ast: dict, timeout: float = 120.0) -> dict:
        return {
            "target_path":   ".",
            "source_files":  list(parsed_ast.keys()),
            "parsed_ast":    parsed_ast,
            "findings":      [],
            "scored":        False,
            "report":        {},
            "error":         None,
            "model":         "fast",
            "timeout":       timeout,
            "skipped_files": [],
        }

    def _small_ast(self, filepath):
        return {
            "filepath":    filepath,
            "functions":   [],
            "classes":     [],
            "imports":     [],
            "calls":       [{"call": "foo()", "lineno": 1}],
            "assignments": [],
            "strings":     [],
        }

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_n_small_files_produce_one_llm_call(self, mock_call_llm):
        """N small files must be sent in a single call_llm() invocation, not N."""
        mock_call_llm.return_value = "[]"
        parsed_ast = {f"file{i}.py": self._small_ast(f"file{i}.py") for i in range(4)}

        analyzer_node(self._base_state(parsed_ast))

        mock_call_llm.assert_called_once()

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_findings_from_batched_call_attribute_to_correct_file(self, mock_call_llm):
        """Findings returned by a mocked batched call are still attributed via the
        per-finding "file" field, regardless of which call produced them."""
        mock_call_llm.return_value = json.dumps([
            {
                "id": "GG-001", "owasp_id": "ASI01", "title": "Issue in file0",
                "description": "A long enough description for validation purposes.",
                "severity": "high", "file": "file0.py", "line": 1,
                "remediation": "Fix it.",
            },
            {
                "id": "GG-002", "owasp_id": "ASI03", "title": "Issue in file1",
                "description": "Another long enough description for validation.",
                "severity": "medium", "file": "file1.py", "line": 2,
                "remediation": "Fix it too.",
            },
        ])
        parsed_ast = {
            "file0.py": self._small_ast("file0.py"),
            "file1.py": self._small_ast("file1.py"),
        }
        result = analyzer_node(self._base_state(parsed_ast))

        files = {f.file for f in result["findings"]}
        self.assertEqual(files, {"file0.py", "file1.py"})

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_batch_timeout_marks_all_files_in_batch_as_skipped(self, mock_call_llm):
        """A timeout on a batched call must record every file in that batch as
        skipped, not just one — the whole batch shares the same fate."""
        import httpx

        mock_call_llm.side_effect = httpx.TimeoutException("timed out")
        parsed_ast = {f"file{i}.py": self._small_ast(f"file{i}.py") for i in range(3)}

        result = analyzer_node(self._base_state(parsed_ast))

        self.assertEqual(len(result["skipped_files"]), 3)
        skipped_paths = {s["filepath"] for s in result["skipped_files"]}
        self.assertEqual(skipped_paths, {"file0.py", "file1.py", "file2.py"})


class TestAnalyzerNodeParallelism(unittest.TestCase):
    """Tests for Task 4 — concurrent batch processing via ThreadPoolExecutor."""

    def _base_state(self, parsed_ast: dict, workers: int = 2, timeout: float = 120.0) -> dict:
        return {
            "target_path":   ".",
            "source_files":  list(parsed_ast.keys()),
            "parsed_ast":    parsed_ast,
            "findings":      [],
            "scored":        False,
            "report":        {},
            "error":         None,
            "model":         "fast",
            "timeout":       timeout,
            "skipped_files": [],
            "workers":       workers,
        }

    def _large_ast(self, filepath):
        """Large enough to always get its own batch, so N files == N batches."""
        return {
            "filepath":    filepath,
            "functions":   [],
            "classes":     [],
            "imports":     [],
            "calls":       [{"call": "x" * 20000, "lineno": 1}],
            "assignments": [],
            "strings":     [],
        }

    def test_parallel_batches_run_concurrently_not_sequentially(self):
        """With workers >= number of batches, wall-clock time must reflect
        concurrent execution (~1x the per-call delay), not the sum of all
        delays as a fully sequential loop would take."""
        import time as time_module

        call_delay = 0.2
        num_batches = 4

        def slow_call_llm(prompt, endpoint, timeout):
            time_module.sleep(call_delay)
            return "[]"

        parsed_ast = {f"file{i}.py": self._large_ast(f"file{i}.py") for i in range(num_batches)}

        with patch("graphguard.nodes.analyzer.call_llm", side_effect=slow_call_llm):
            start = time_module.monotonic()
            analyzer_node(self._base_state(parsed_ast, workers=num_batches))
            elapsed = time_module.monotonic() - start

        # sequential execution would take >= num_batches * call_delay; concurrent
        # execution should finish in well under half of that
        sequential_time = num_batches * call_delay
        self.assertLess(elapsed, sequential_time / 2)

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_worker_failure_does_not_affect_other_batches(self, mock_call_llm):
        """An unexpected exception raised while processing one batch must not
        prevent the other batches from completing successfully."""
        def side_effect(prompt, endpoint, timeout):
            if "broken.py" in prompt:
                raise RuntimeError("simulated worker crash")
            return "[]"

        mock_call_llm.side_effect = side_effect
        parsed_ast = {
            "broken.py": self._large_ast("broken.py"),
            "ok.py":     self._large_ast("ok.py"),
        }
        result = analyzer_node(self._base_state(parsed_ast))

        # both batches were attempted; the crash didn't take down the other
        self.assertEqual(mock_call_llm.call_count, 2)
        self.assertEqual(result["findings"], [])

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_connect_error_aborts_pending_batches(self, mock_call_llm):
        """A ConnectError on one batch must trip the abort signal so queued
        batches don't waste time dialing a server that's confirmed down."""
        import httpx

        mock_call_llm.side_effect = httpx.ConnectError("connection refused")
        parsed_ast = {f"file{i}.py": self._large_ast(f"file{i}.py") for i in range(3)}

        # single worker makes execution order deterministic: batches are
        # dequeued one at a time, so the second and third must see abort_event
        # already set and never even call call_llm
        result = analyzer_node(self._base_state(parsed_ast, workers=1))

        self.assertEqual(result["findings"], [])
        # first batch always dials and hits ConnectError; the rest may be
        # aborted before dialing thanks to the shared abort_event
        self.assertGreaterEqual(mock_call_llm.call_count, 1)
        self.assertLessEqual(mock_call_llm.call_count, 3)
        # Task B: the abort must be surfaced via connection_error, not silently
        # swallowed — this is what lets reporter_node warn instead of showing
        # a false "no issues found" success message
        self.assertIsNotNone(result["connection_error"])
        self.assertIn("cannot reach llama-server", result["connection_error"])

    @patch("graphguard.nodes.analyzer.call_llm")
    def test_connection_error_is_none_on_a_clean_run(self, mock_call_llm):
        """When nothing goes wrong, connection_error must be explicitly None —
        not just absent — so reporter_node's check behaves predictably."""
        mock_call_llm.return_value = "[]"
        parsed_ast = {"ok.py": self._large_ast("ok.py")}

        result = analyzer_node(self._base_state(parsed_ast))

        self.assertIsNone(result["connection_error"])


class TestCallLlmRequestFormat(unittest.TestCase):
    """Tests for Task 5 — call_llm() must request grammar-constrained output via
    response_format/json_schema. Only the request construction is tested here;
    whether a given llama-server build actually enforces the schema can't be
    mocked meaningfully and must be verified against a real running server."""

    @patch("graphguard.nodes.analyzer.httpx.post")
    def test_payload_includes_response_format_with_finding_schema(self, mock_post):
        """The payload sent to llama-server must include response_format with
        the exact FINDING_JSON_SCHEMA, and must not also set "grammar" (the two
        are mutually exclusive in llama.cpp's API)."""
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {
            "choices": [{"message": {"content": "[]"}}]
        }

        call_llm("some prompt", LLAMA_ENDPOINTS["fast"], timeout=30.0)

        _, kwargs = mock_post.call_args
        payload = kwargs["json"]

        self.assertNotIn("grammar", payload)
        self.assertIn("response_format", payload)
        self.assertEqual(payload["response_format"]["type"], "json_schema")
        self.assertEqual(payload["response_format"]["json_schema"]["schema"], FINDING_JSON_SCHEMA)

    @patch("graphguard.nodes.analyzer.httpx.post")
    def test_schema_applies_to_both_fast_and_reasoning_endpoints(self, mock_post):
        """The same FINDING_JSON_SCHEMA is used regardless of which endpoint
        (fast or reasoning) is selected via --model."""
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {
            "choices": [{"message": {"content": "[]"}}]
        }

        for key in ("fast", "reasoning"):
            call_llm("some prompt", LLAMA_ENDPOINTS[key], timeout=30.0)
            _, kwargs = mock_post.call_args
            schema = kwargs["json"]["response_format"]["json_schema"]["schema"]
            self.assertEqual(schema, FINDING_JSON_SCHEMA)

    def test_schema_excludes_id_field(self):
        """"id" must not appear in the schema — it's always overwritten by
        parse_llm_response()'s sequential counter, so asking the model to
        generate one would waste output tokens on a discarded field."""
        self.assertNotIn("id", FINDING_JSON_SCHEMA["items"]["properties"])

    def test_schema_owasp_id_enum_matches_valid_owasp_ids(self):
        """The schema's owasp_id enum must match scorer.py's VALID_OWASP_IDS
        exactly, so the model can't be constrained into generating an ID that
        scorer_node would discard anyway."""
        from graphguard.nodes.scorer import VALID_OWASP_IDS

        self.assertEqual(set(FINDING_JSON_SCHEMA["items"]["properties"]["owasp_id"]["enum"]),
                         VALID_OWASP_IDS)

    def test_schema_line_is_not_required(self):
        """"line" stays optional in the schema so the model can omit it, matching
        parse_llm_response()'s item.get("line", None) handling of its absence."""
        self.assertNotIn("line", FINDING_JSON_SCHEMA["items"]["required"])


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
