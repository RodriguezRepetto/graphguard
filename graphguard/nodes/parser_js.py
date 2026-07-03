"""
parser_js.py — JavaScript and TypeScript parser for GraphGuard.

Uses tree-sitter to parse .js, .ts, and .mjs files and extract
LangGraph-specific structures in the same dict format as parse_file()
in parser.py. Fully self-contained; does not import from parser.py.
"""

import os


def _text(node) -> str:
    """Decode a tree-sitter node's text bytes to a UTF-8 string."""
    return node.text.decode("utf-8", errors="replace")


def _param_names(formal_params_node) -> list[str]:
    """Extract parameter name strings from a formal_parameters node."""
    args = []
    for child in formal_params_node.named_children:
        if child.type == "identifier":
            args.append(_text(child))
        elif child.type in ("required_parameter", "optional_parameter"):
            # TypeScript typed param: first identifier child is the name
            for sc in child.named_children:
                if sc.type == "identifier":
                    args.append(_text(sc))
                    break
        elif child.type in ("rest_pattern", "rest_parameter"):
            # ...rest — the identifier inside
            for sc in child.named_children:
                if sc.type == "identifier":
                    args.append(_text(sc))
                    break
        elif child.type == "assignment_pattern":
            # param = default — first identifier is the name
            for sc in child.named_children:
                if sc.type == "identifier":
                    args.append(_text(sc))
                    break
    return args


def _class_bases(class_decl_node) -> list[str]:
    """Extract base class names from a class_declaration node."""
    bases = []
    for child in class_decl_node.named_children:
        if child.type == "class_heritage":
            for hchild in child.named_children:
                if hchild.type == "extends_clause":
                    # TypeScript: class_heritage > extends_clause > identifier
                    for ec in hchild.named_children:
                        if ec.type in ("identifier", "type_identifier", "member_expression"):
                            bases.append(_text(ec))
                elif hchild.type in ("identifier", "type_identifier", "member_expression"):
                    # JavaScript: class_heritage > identifier
                    bases.append(_text(hchild))
    return bases


def _walk(node, result) -> None:
    """Recursively walk the tree-sitter AST and populate the result dict."""
    t = node.type

    if t == "function_declaration":
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        if name_node:
            result["functions"].append({
                "name":       _text(name_node),
                "lineno":     node.start_point[0] + 1,
                "args":       _param_names(params_node) if params_node else [],
                "decorators": [],
            })

    elif t == "class_declaration":
        name_node = node.child_by_field_name("name")
        if name_node:
            result["classes"].append({
                "name":   _text(name_node),
                "lineno": node.start_point[0] + 1,
                "bases":  _class_bases(node),
            })

    elif t == "import_statement":
        result["imports"].append(_text(node))

    elif t in ("call_expression", "new_expression"):
        result["calls"].append({
            "call":   _text(node),
            "lineno": node.start_point[0] + 1,
        })

    elif t == "lexical_declaration":
        lineno = node.start_point[0] + 1
        for child in node.named_children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                val_node  = child.child_by_field_name("value")
                if name_node:
                    result["assignments"].append({
                        "targets": [_text(name_node)],
                        "value":   _text(val_node) if val_node else "",
                        "lineno":  lineno,
                    })
                    # Arrow function assigned to a variable → also a named function
                    if val_node and val_node.type == "arrow_function":
                        # multi-param: field "parameters" → formal_parameters
                        # single-param: field "parameter" → identifier
                        params_node = val_node.child_by_field_name("parameters")
                        param_node  = val_node.child_by_field_name("parameter")
                        if params_node and params_node.type == "formal_parameters":
                            args = _param_names(params_node)
                        elif param_node and param_node.type == "identifier":
                            args = [_text(param_node)]
                        else:
                            args = []
                        result["functions"].append({
                            "name":       _text(name_node),
                            "lineno":     lineno,
                            "args":       args,
                            "decorators": [],
                        })

    elif t == "assignment_expression":
        left_node  = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if left_node:
            result["assignments"].append({
                "targets": [_text(left_node)],
                "value":   _text(right_node) if right_node else "",
                "lineno":  node.start_point[0] + 1,
            })

    elif t in ("string", "template_string"):
        for child in node.named_children:
            if child.type == "string_fragment":
                val = _text(child)
                if len(val) > 20:
                    result["strings"].append({
                        "value":  val[:200],
                        "lineno": node.start_point[0] + 1,
                    })

    for child in node.children:
        _walk(child, result)


# Text patterns that indicate a .js/.ts/.mjs file is plausibly LangGraph agent
# code, worth spending tree-sitter parsing and LLM analysis on. Plain
# substring checks — fast, read-only, no AST involved — since this runs
# before parsing. "@langchain/" alone covers @langchain/langgraph,
# @langchain/core, and any other @langchain/* package.
_RELEVANCE_PATTERNS = (
    "@langchain/",
    "StateGraph", "Annotation", "MessagesAnnotation",
    "addNode", "addEdge", "setEntryPoint", "compile(",
    "MemorySaver", "SqliteSaver", "PostgresSaver",
    "tool(", "DynamicTool", "StructuredTool",
    "invoke(", "stream(",
    "createReactAgent", "createAgent",
)


def is_langgraph_relevant(filepath: str) -> bool:
    """
    Return True if the .js/.ts/.mjs file at filepath contains at least one
    pattern suggesting LangGraph/LangChain agent code. Unreadable files are
    skipped silently (treated as not relevant) rather than raising.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except (OSError, UnicodeDecodeError):
        return False

    return any(pattern in source for pattern in _RELEVANCE_PATTERNS)


def parse_js_file(filepath: str) -> dict:
    """
    Parse a single .js, .ts, or .mjs file with tree-sitter.
    Returns a dict with the same keys as parse_file() in parser.py:
    filepath, functions, classes, imports, calls, assignments, strings.
    On any error returns {"error": str(e), "filepath": filepath}.
    """
    try:
        import tree_sitter_javascript as tsjs
        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser
    except ImportError as e:
        return {"error": f"tree-sitter not available: {e}", "filepath": filepath}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except (UnicodeDecodeError, PermissionError) as e:
        return {"error": str(e), "filepath": filepath}

    ext = os.path.splitext(filepath)[1].lower()
    try:
        if ext == ".ts":
            language = Language(tsts.language_typescript())
        else:
            language = Language(tsjs.language())

        parser = Parser(language)
        tree = parser.parse(source.encode("utf-8"))
    except Exception as e:
        return {"error": str(e), "filepath": filepath}

    if tree.root_node.has_error:
        return {"error": "syntax error: file contains unparseable tokens", "filepath": filepath}

    result = {
        "filepath":    filepath,
        "functions":   [],
        "classes":     [],
        "imports":     [],
        "calls":       [],
        "assignments": [],
        "strings":     [],
    }

    _walk(tree.root_node, result)

    return result
