"""
parser.py — parser_node implementation.

Walks the target path, collects Python source files, and parses them
using the stdlib ast module to extract LangGraph-specific structures.
"""

import ast                  # Python's built-in AST parser — no execution, read-only
import os                   # for walking the directory tree
from graphguard.state import GraphGuardState


def collect_python_files(target_path: str) -> list[str]:
    """
    Recursively collect all .py files under target_path.
    If target_path is a single file, return it directly.
    """

    # if the target is a single file, wrap it in a list
    if os.path.isfile(target_path):
        return [target_path] if target_path.endswith(".py") else []

    # walk the directory tree and collect .py files
    py_files = []
    for root, dirs, files in os.walk(target_path):
        # skip hidden directories and the __pycache__ folder
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for file in files:
            if file.endswith(".py"):  # only collect Python source files
                py_files.append(os.path.join(root, file))

    return sorted(py_files)  # sort for deterministic ordering


def parse_file(filepath: str) -> dict:
    """
    Parse a single Python file with ast and extract LangGraph structures.
    Returns a dict with nodes, tools, state fields, edges, and raw imports.
    """

    # read the source code from disk — no execution, just text
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    # parse the source into an AST tree
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        # return an error entry if the file has invalid syntax
        return {"error": str(e), "filepath": filepath}

    # initialize containers for extracted structures
    result = {
        "filepath":    filepath,   # path to the source file
        "functions":   [],         # all function definitions found
        "classes":     [],         # all class definitions found
        "imports":     [],         # all import statements found
        "calls":       [],         # all function calls found
        "assignments": [],         # all assignments found (catches state fields)
        "strings":     [],         # all string literals (catches prompt templates)
    }

    # walk every node in the AST tree
    for node in ast.walk(tree):

        # collect function definitions — LangGraph nodes are functions
        if isinstance(node, ast.FunctionDef):
            result["functions"].append({
                "name":      node.name,          # function name
                "lineno":    node.lineno,         # line number in source
                "args":      [a.arg for a in node.args.args],  # argument names
                "decorators": [ast.unparse(d) for d in node.decorator_list],  # decorators
            })

        # collect class definitions — State schemas are TypedDicts or BaseModels
        elif isinstance(node, ast.ClassDef):
            result["classes"].append({
                "name":   node.name,             # class name
                "lineno": node.lineno,           # line number
                "bases":  [ast.unparse(b) for b in node.bases],  # base classes
            })

        # collect import statements — reveals dependencies and tool imports
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            result["imports"].append(ast.unparse(node))  # full import as string

        # collect function calls — reveals add_node, add_edge, tool bindings
        elif isinstance(node, ast.Call):
            result["calls"].append({
                "call":   ast.unparse(node),     # full call as string
                "lineno": node.lineno,           # line number
            })

        # collect assignments — reveals state field declarations
        elif isinstance(node, ast.Assign):
            result["assignments"].append({
                "targets": [ast.unparse(t) for t in node.targets],  # left side
                "value":   ast.unparse(node.value),                  # right side
                "lineno":  node.lineno,
            })

        # collect string constants — reveals prompt templates and system prompts
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) > 20:  # only strings long enough to be prompts
                result["strings"].append({
                    "value":  node.value[:200],  # truncate to avoid huge payloads
                    "lineno": node.lineno,
                })

    return result


def parser_node(state: GraphGuardState) -> dict:
    """
    Node 1: walks target_path, parses all .py files, returns structured AST data.
    This is the entry point of the GraphGuard analysis pipeline.
    """

    target = state["target_path"]  # path provided by the user via CLI

    # step 1: collect all Python files in the target
    source_files = collect_python_files(target)
    print(f"[parser] found {len(source_files)} Python files in {target}")

    # step 2: parse each file and collect results
    parsed_ast = {}
    for filepath in source_files:
        print(f"[parser] parsing {filepath}")
        parsed_ast[filepath] = parse_file(filepath)  # keyed by filepath

    # step 3: return state update with collected files and parsed structures
    return {
        "source_files": source_files,  # list of .py paths found
        "parsed_ast":   parsed_ast,    # dict of filepath -> AST structures
        "error":        None,          # no error
    }
