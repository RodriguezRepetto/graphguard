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

# Directories that never contain LangGraph agent code — dependencies, build
# artifacts, and caches. Skipped entirely during os.walk() so we never descend
# into e.g. a node_modules tree with thousands of irrelevant files.
# "public" is deliberately omitted: it can legitimately hold agent-adjacent
# .ts/.js files in some frameworks, so it isn't safe to exclude unconditionally.
_EXCLUDED_DIRS = {
    "node_modules", "dist", "build", ".next", ".nuxt", ".turbo",
    "coverage", ".coverage", "__pycache__", ".git", ".venv", "venv",
    "env", "vendor", ".cache", ".parcel-cache", "out", ".output",
    "storybook-static", ".docusaurus",
}


def collect_source_files(target_path: str, _excluded_found: set | None = None) -> list[str]:
    """
    Recursively collect all .py, .js, .ts, and .mjs files under target_path.
    If target_path is a single file, return it directly (if it has a supported extension).
    Directories in _EXCLUDED_DIRS (and any dotfile directory) are skipped entirely.
    If _excluded_found is given, the basenames of excluded directories actually
    encountered during the walk are added to it.
    """

    if os.path.isfile(target_path):
        return [target_path] if os.path.splitext(target_path)[1].lower() in _SOURCE_EXTS else []

    source_files = []
    for root, dirs, files in os.walk(target_path):
        kept = []
        for d in dirs:
            if d.startswith(".") or d in _EXCLUDED_DIRS:
                if _excluded_found is not None and d in _EXCLUDED_DIRS:
                    _excluded_found.add(d)
                continue
            kept.append(d)
        dirs[:] = kept
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


# Text patterns that indicate a .py file is plausibly LangGraph agent code,
# worth spending tree-parsing and LLM analysis on. Plain substring checks —
# fast, read-only, no AST involved — since this runs before parsing.
_PY_RELEVANCE_PATTERNS = (
    "from langgraph", "import langgraph",
    "from langchain", "import langchain",
    "StateGraph",
    "@tool", "StructuredTool",
    "MemorySaver", "SqliteSaver", "PostgresSaver",
)


def is_langgraph_relevant_py(filepath: str) -> bool:
    """
    Return True if the .py file at filepath contains at least one pattern
    suggesting LangGraph/LangChain agent code. Unreadable files are skipped
    silently (treated as not relevant) rather than raising.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except (OSError, UnicodeDecodeError):
        return False

    return any(pattern in source for pattern in _PY_RELEVANCE_PATTERNS)


def parser_node(state: GraphGuardState) -> dict:
    """
    Node 1: walks target_path, parses all source files, returns structured AST data.
    Python files use the stdlib ast parser; JS/TS files use the tree-sitter parser.
    This is the entry point of the GraphGuard analysis pipeline.
    """
    from graphguard.nodes.parser_js import parse_js_file, is_langgraph_relevant

    target = state["target_path"]

    # fail fast if the target path doesn't exist
    if not os.path.exists(target):
        return {
            "error":        f"target path does not exist: {target}",
            "source_files": [],
            "parsed_ast":   {},
        }

    excluded_dirs_found: set = set()
    all_files = collect_source_files(target, excluded_dirs_found)

    def _is_relevant(filepath: str) -> bool:
        if os.path.splitext(filepath)[1].lower() in _JS_EXTS:
            return is_langgraph_relevant(filepath)
        return is_langgraph_relevant_py(filepath)

    relevant_files = [f for f in all_files if _is_relevant(f)]

    # If nothing matched the relevance filter (e.g. a tiny project with no
    # recognizable LangGraph markers yet), fall back to scanning everything
    # rather than silently producing an empty result.
    source_files = relevant_files if relevant_files else all_files

    found = len(all_files)
    relevant_count = len(source_files)
    excluded_count = found - relevant_count

    print(f"[parser] found {found} source files — {relevant_count} relevant to LangGraph agent analysis")
    if excluded_dirs_found or excluded_count:
        dir_sample = ", ".join(sorted(excluded_dirs_found)[:3])
        suffix = f"{dir_sample} and " if dir_sample else ""
        print(f"[parser] excluded: {suffix}{excluded_count} non-agent files")

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
