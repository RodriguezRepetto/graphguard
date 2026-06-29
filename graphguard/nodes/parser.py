"""
parser.py — parser_node implementation.

Walks the target path, collects Python source files, and parses them
using the stdlib ast module to extract LangGraph-specific structures.
"""

import ast
import os
from graphguard.state import GraphGuardState


def collect_python_files(target_path: str) -> list[str]:
    """
    Recursively collect all .py files under target_path.
    If target_path is a single file, return it directly.
    """

    if os.path.isfile(target_path):
        return [target_path] if target_path.endswith(".py") else []

    py_files = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for file in files:
            if file.endswith(".py"):
                py_files.append(os.path.join(root, file))

    return sorted(py_files)


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
    Node 1: walks target_path, parses all .py files, returns structured AST data.
    This is the entry point of the GraphGuard analysis pipeline.
    """

    target = state["target_path"]

    # fail fast if the target path doesn't exist
    if not os.path.exists(target):
        return {
            "error":        f"target path does not exist: {target}",
            "source_files": [],
            "parsed_ast":   {},
        }

    source_files = collect_python_files(target)
    print(f"[parser] found {len(source_files)} Python files in {target}")

    parsed_ast = {}
    for filepath in source_files:
        print(f"[parser] parsing {filepath}")
        parsed_ast[filepath] = parse_file(filepath)

    return {
        "source_files": source_files,
        "parsed_ast":   parsed_ast,
        "error":        None,
    }
