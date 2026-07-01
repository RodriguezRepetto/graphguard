"""
test_parser.py — Unit tests for the parser_node and its helper functions.

Tests verify that AST parsing correctly extracts functions, classes,
imports, calls and assignments from Python source files, and that
edge cases (missing paths, bad encodings) are handled gracefully.
"""

import os
import tempfile
import unittest
from graphguard.nodes.parser import collect_python_files, collect_source_files, parse_file, parser_node
from graphguard.nodes.parser_js import parse_js_file


class TestCollectPythonFiles(unittest.TestCase):
    """Tests for the collect_python_files helper."""

    def test_single_file(self):
        """Passing a single .py file returns a list with that file."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"x = 1")
            path = f.name
        try:
            result = collect_python_files(path)
            self.assertEqual(result, [path])
        finally:
            os.unlink(path)

    def test_directory(self):
        """Passing a directory returns all .py files recursively."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = os.path.join(tmpdir, "a.py")
            file2 = os.path.join(tmpdir, "b.py")
            open(file1, "w").close()
            open(file2, "w").close()

            result = collect_python_files(tmpdir)
            self.assertEqual(len(result), 2)
            self.assertIn(file1, result)
            self.assertIn(file2, result)

    def test_non_py_files_ignored(self):
        """Non-.py files in the directory are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file  = os.path.join(tmpdir, "agent.py")
            txt_file = os.path.join(tmpdir, "readme.txt")
            open(py_file,  "w").close()
            open(txt_file, "w").close()

            result = collect_python_files(tmpdir)
            self.assertEqual(len(result), 1)
            self.assertIn(py_file, result)


class TestParseFile(unittest.TestCase):
    """Tests for the parse_file helper."""

    def _write_temp(self, source: str) -> str:
        """Helper: write source to a temp file and return its path."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(source)
            return f.name

    def test_extracts_functions(self):
        """Functions defined in source are extracted correctly."""
        path = self._write_temp("def my_func(x, y):\n    pass\n")
        try:
            result = parse_file(path)
            names = [f["name"] for f in result["functions"]]
            self.assertIn("my_func", names)
        finally:
            os.unlink(path)

    def test_extracts_classes(self):
        """Classes defined in source are extracted correctly."""
        path = self._write_temp("class MyState:\n    pass\n")
        try:
            result = parse_file(path)
            names = [c["name"] for c in result["classes"]]
            self.assertIn("MyState", names)
        finally:
            os.unlink(path)

    def test_extracts_imports(self):
        """Import statements are extracted correctly."""
        path = self._write_temp("import os\nfrom pathlib import Path\n")
        try:
            result = parse_file(path)
            self.assertTrue(len(result["imports"]) >= 2)
        finally:
            os.unlink(path)

    def test_syntax_error_handled(self):
        """Files with syntax errors return an error entry without crashing."""
        path = self._write_temp("def broken(\n")
        try:
            result = parse_file(path)
            self.assertIn("error", result)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        """Empty files are parsed without errors and return empty structures."""
        path = self._write_temp("")
        try:
            result = parse_file(path)
            self.assertEqual(result["functions"], [])
            self.assertEqual(result["classes"],   [])
        finally:
            os.unlink(path)

    def test_non_utf8_file_returns_error(self):
        """F4: parse_file returns an error dict for files with non-UTF-8 encoding."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"\xff\xfe# invalid utf-8 bytes \x80\x81\x82")
            path = f.name
        try:
            result = parse_file(path)
            self.assertIn("error", result)
            self.assertEqual(result["filepath"], path)
        finally:
            os.unlink(path)


class TestParserNode(unittest.TestCase):
    """Tests for the parser_node LangGraph node function."""

    def _base_state(self, target_path: str) -> dict:
        """Helper: build a minimal GraphGuardState dict."""
        return {
            "target_path":  target_path,
            "source_files": [],
            "parsed_ast":   {},
            "findings":     [],
            "scored":       False,
            "report":       {},
            "error":        None,
            "model":        "fast",
        }

    def test_parser_node_returns_source_files(self):
        """parser_node correctly populates source_files in state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            agent_file = os.path.join(tmpdir, "agent.py")
            with open(agent_file, "w") as f:
                f.write("def my_node(state):\n    return state\n")

            result = parser_node(self._base_state(tmpdir))

            self.assertIn(agent_file, result["source_files"])
            self.assertIn(agent_file, result["parsed_ast"])
            self.assertIsNone(result["error"])

    def test_nonexistent_path_returns_error(self):
        """F3: parser_node returns an error state for a path that does not exist."""
        result = parser_node(self._base_state("/nonexistent/path/that/cannot/exist"))

        self.assertIsNotNone(result["error"])
        self.assertIn("does not exist", result["error"])
        self.assertEqual(result["source_files"], [])
        self.assertEqual(result["parsed_ast"],   {})


class TestJSParser(unittest.TestCase):
    """Tests for collect_source_files and parse_js_file (JavaScript/TypeScript support)."""

    _EXPECTED_KEYS = {"filepath", "functions", "classes", "imports", "calls", "assignments", "strings"}

    def _write_js(self, source: str, suffix: str = ".js") -> str:
        """Write source to a temp JS/TS file and return its path."""
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w") as f:
            f.write(source)
            return f.name

    # --- collect_source_files tests ---

    def test_collect_source_files_finds_js(self):
        """collect_source_files includes .js files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            js_file = os.path.join(tmpdir, "agent.js")
            open(js_file, "w").close()

            result = collect_source_files(tmpdir)
            self.assertIn(js_file, result)

    def test_collect_source_files_finds_ts(self):
        """collect_source_files includes .ts files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ts_file = os.path.join(tmpdir, "agent.ts")
            open(ts_file, "w").close()

            result = collect_source_files(tmpdir)
            self.assertIn(ts_file, result)

    def test_collect_source_files_finds_py(self):
        """collect_source_files still includes .py files (backward compatibility)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = os.path.join(tmpdir, "agent.py")
            open(py_file, "w").close()

            result = collect_source_files(tmpdir)
            self.assertIn(py_file, result)

    # --- parse_js_file tests ---

    def test_parse_js_file_extracts_functions(self):
        """Function declarations in .js source are extracted correctly."""
        path = self._write_js("function myFunc(x, y) { return x + y; }\n")
        try:
            result = parse_js_file(path)
            names = [f["name"] for f in result["functions"]]
            self.assertIn("myFunc", names)
            fn = next(f for f in result["functions"] if f["name"] == "myFunc")
            self.assertIn("x", fn["args"])
            self.assertIn("y", fn["args"])
            self.assertEqual(fn["decorators"], [])
        finally:
            os.unlink(path)

    def test_parse_js_file_extracts_classes(self):
        """Class declarations in .js source are extracted correctly."""
        path = self._write_js("class MyState extends BaseState { }\n")
        try:
            result = parse_js_file(path)
            names = [c["name"] for c in result["classes"]]
            self.assertIn("MyState", names)
            cls = next(c for c in result["classes"] if c["name"] == "MyState")
            self.assertIn("BaseState", cls["bases"])
            self.assertIsInstance(cls["lineno"], int)
        finally:
            os.unlink(path)

    def test_parse_js_file_extracts_imports(self):
        """Import statements in .js source are extracted correctly."""
        path = self._write_js(
            'import { StateGraph } from "@langchain/langgraph";\n'
            'import fs from "fs";\n'
        )
        try:
            result = parse_js_file(path)
            self.assertGreaterEqual(len(result["imports"]), 2)
            combined = " ".join(result["imports"])
            self.assertIn("@langchain/langgraph", combined)
        finally:
            os.unlink(path)

    def test_parse_js_file_syntax_error_handled(self):
        """Files with syntax errors return an error entry without crashing."""
        path = self._write_js("function broken(\n")
        try:
            result = parse_js_file(path)
            self.assertIn("error", result)
            self.assertEqual(result["filepath"], path)
        finally:
            os.unlink(path)

    def test_parse_js_file_returns_same_keys_as_python_parser(self):
        """parse_js_file returns a dict with the exact same top-level keys as parse_file()."""
        path = self._write_js("function hello() { return 1; }\n")
        try:
            result = parse_js_file(path)
            self.assertEqual(set(result.keys()), self._EXPECTED_KEYS)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
