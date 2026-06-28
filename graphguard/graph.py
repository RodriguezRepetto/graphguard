"""
graph.py — GraphGuard LangGraph pipeline definition.

Defines the StateGraph that orchestrates the four analysis nodes:
parser -> analyzer -> scorer -> reporter
"""

from langgraph.graph import StateGraph, END

from graphguard.state import GraphGuardState
from graphguard.nodes.parser   import parser_node
from graphguard.nodes.analyzer import analyzer_node
from graphguard.nodes.scorer   import scorer_node
from graphguard.nodes.reporter import reporter_node


def build_graph() -> StateGraph:
    """
    Assembles and compiles the GraphGuard analysis pipeline.
    Returns a compiled LangGraph ready to invoke.
    """

    # initialize the graph with our shared state schema
    graph = StateGraph(GraphGuardState)

    # register each node with its handler function
    graph.add_node("parser",   parser_node)
    graph.add_node("analyzer", analyzer_node)
    graph.add_node("scorer",   scorer_node)
    graph.add_node("reporter", reporter_node)

    # define the linear execution flow
    graph.set_entry_point("parser")
    graph.add_edge("parser",   "analyzer")
    graph.add_edge("analyzer", "scorer")
    graph.add_edge("scorer",   "reporter")
    graph.add_edge("reporter", END)

    return graph.compile()


# module-level compiled graph instance, imported by main.py
app_graph = build_graph()
