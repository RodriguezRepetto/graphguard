"""
parser.py — parser_node implementation.

Walks the target path, collects Python and JavaScript/TypeScript source files,
and parses them using the stdlib ast module (Python) or tree-sitter (JS/TS) to
extract LangGraph-specific structures.
"""

import ast
import os
from graphguard.state import GraphGuardState

_JS_EXTS = {".js", ".ts", ".mjs"}
_SOURCE_EXTS = {".py"} | _JS_EXTS


def collect_source_files(target_path: str) -> list[str]:
    """
    Recursively collect all .py, .js, .ts, and .mjs files under target_path.
    If target_path is a single file, return it directly (if it has a supported extension).
    """

    if os.path.isfile(target_path):
        return [target_path] if os.path.splitext(target_path)[1].lower() in _SOURCE_EXTS else []

    source_files = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for file in files:
            if os.path.splitext(file)[1].lower() in _SOURCE_EXTS:
                source_files.append(os.path.join(root, file))

    return sorted(source_files)


# Backward-compatible alias so existing code and tests that import collect_python_files
# continue to work without modification.
collect_python_files = collect_source_files


def parse_file(filepath: str) -> dict:
    """
    Parse a single Python file with ast and extract LangGraph structures.
    Returns a dict with nodes, tools, state fields, edges, and raw imports.
    """

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except (UnicodeDecodeError, PermissionError) as e:
        return {"error": str(e), "filepath": filepath}

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        return {"error": str(e), "filepath": filepath}

    result = {
        "filepath":    filepath,
        "functions":   [],
        "classes":     [],
        "imports":     [],
        "calls":       [],
        "assignments": [],
        "strings":     [],
    }

    for node in ast.walk(tree):

        if isinstance(node, ast.FunctionDef):
            result["functions"].append({
                "name":       node.name,
                "lineno":     node.lineno,
                "args":       [a.arg for a in node.args.args],
                "decorators": [ast.unparse(d) for d in node.decorator_list],
            })

        elif isinstance(node, ast.ClassDef):
            result["classes"].append({
                "name":   node.name,
                "lineno": node.lineno,
                "bases":  [ast.unparse(b) for b in node.bases],
            })

        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            result["imports"].append(ast.unparse(node))

        elif isinstance(node, ast.Call):
            result["calls"].append({
                "call":   ast.unparse(node),
                "lineno": node.lineno,
            })

        elif isinstance(node, ast.Assign):
            result["assignments"].append({
                "targets": [ast.unparse(t) for t in node.targets],
                "value":   ast.unparse(node.value),
                "lineno":  node.lineno,
            })

        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) > 20:
                result["strings"].append({
                    "value":  node.value[:200],
                    "lineno": node.lineno,
                })

    return result


def parser_node(state: GraphGuardState) -> dict:
    """
    Node 1: walks target_path, parses all source files, returns structured AST data.
    Python files use the stdlib ast parser; JS/TS files use the tree-sitter parser.
    This is the entry point of the GraphGuard analysis pipeline.
    """
    from graphguard.nodes.parser_js import parse_js_file

    target = state["target_path"]

    # fail fast if the target path doesn't exist
    if not os.path.exists(target):
        return {
            "error":        f"target path does not exist: {target}",
            "source_files": [],
            "parsed_ast":   {},
        }

    source_files = collect_source_files(target)
    print(f"[parser] found {len(source_files)} source files in {target}")

    parsed_ast = {}
    for filepath in source_files:
        print(f"[parser] parsing {filepath}")
        ext = os.path.splitext(filepath)[1].lower()
        if ext in _JS_EXTS:
            parsed_ast[filepath] = parse_js_file(filepath)
        else:
            parsed_ast[filepath] = parse_file(filepath)

    return {
        "source_files": source_files,
        "parsed_ast":   parsed_ast,
        "error":        None,
    }
