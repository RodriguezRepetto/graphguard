"""
vulnerable_agent/agent.py — Intentionally insecure LangGraph agent for testing.

This file contains DELIBERATE security vulnerabilities used to validate
GraphGuard's detection capabilities. Do NOT use this in production.

Vulnerabilities present:
  [ASI01] Prompt injection — user input passed directly to LLM
  [ASI02] Tool misuse — SQL tool with no input validation
  [ASI03] State leakage — sensitive fields exposed to all nodes
  [ASI06] Privilege escalation — admin tool accessible without scope check
  [ASI07] Inter-node validation — raw LLM output passed to next node
"""

import os
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END


# --- VULNERABILITY ASI03: sensitive fields in state visible to all nodes ---
class AgentState(TypedDict):
    user_input:    str        # raw user input, never sanitized
    user_token:    str        # auth token propagated to every node
    db_password:   str        # database password in plain state
    llm_output:    str        # raw LLM output, never validated
    sql_query:     str        # SQL query built from user input
    response:      str        # final response to user


# --- VULNERABILITY ASI01: user input passed directly to LLM prompt ---
def query_handler(state: AgentState) -> dict:
    """
    Handles user queries. Passes raw user input into the LLM prompt
    without any sanitization — classic prompt injection surface.
    """

    # INSECURE: user_input is injected directly into the prompt
    prompt = f"Answer the following: {state['user_input']}"

    # simulated LLM call with unsanitized prompt
    llm_output = f"[LLM response to]: {prompt}"

    return {"llm_output": llm_output}  # raw output, no validation


# --- VULNERABILITY ASI02: SQL tool with no input validation ---
def execute_sql(query: str) -> str:
    """
    Executes a SQL query. Accepts raw string with no parameterization
    or schema validation — SQL injection vector.
    """

    # INSECURE: query built from user-controlled string, no sanitization
    connection_string = f"sqlite:///prod.db?password={os.environ.get('DB_PASS')}"
    return f"Executing: {query} on {connection_string}"


# --- VULNERABILITY ASI06: admin tool with no privilege check ---
def delete_all_records(table: str) -> str:
    """
    Deletes all records from a table. No authorization check performed
    before executing — any node can call this tool.
    """

    # INSECURE: destructive operation with no scope or privilege validation
    return f"DELETE FROM {table}"


# --- VULNERABILITY ASI07: raw LLM output passed directly to SQL tool ---
def sql_executor_node(state: AgentState) -> dict:
    """
    Takes raw LLM output and passes it directly to the SQL executor
    without validating or sanitizing the content first.
    """

    # INSECURE: llm_output used as SQL query with no validation
    raw_query = state["llm_output"]
    result = execute_sql(raw_query)  # direct pass-through, no sanitization

    return {"response": result}


# --- graph definition ---
def build_agent():
    """Builds the vulnerable agent graph."""

    graph = StateGraph(AgentState)

    # register nodes
    graph.add_node("query_handler",   query_handler)
    graph.add_node("sql_executor",    sql_executor_node)

    # define flow — no validation between nodes
    graph.set_entry_point("query_handler")
    graph.add_edge("query_handler", "sql_executor")
    graph.add_edge("sql_executor",  END)

    return graph.compile()


agent = build_agent()
