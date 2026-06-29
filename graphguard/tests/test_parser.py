"""
test_parser.py — Unit tests for the parser_node and its helper functions.

Tests verify that AST parsing correctly extracts functions, classes,
imports, calls and assignments from Python source files, and that
edge cases (missing paths, bad encodings) are handled gracefully.
"""

import os
import tempfile
import unittest
from graphguard.nodes.parser import collect_python_files, parse_file, parser_node


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


if __name__ == "__main__":
    unittest.main()
