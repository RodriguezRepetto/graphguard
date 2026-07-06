/**
 * graph.js — LangGraph wiring defined entirely through top-level statements,
 * with no function or class declarations anywhere in the file.
 *
 * Regression fixture for Bug 1: analyzer_node used to skip files whose parsed
 * AST had content only in `assignments`/`calls` because its skip guard only
 * checked `functions` and `classes`. This file reproduces that exact shape —
 * a real-world pattern for small state/graph wiring modules.
 *
 * DO NOT deploy this agent. It exists solely as a scan target for GraphGuard.
 */

import { StateGraph, Annotation, MemorySaver } from "@langchain/langgraph";

// ASI03: sensitive field in shared state — top-level assignment, no function wraps it
const graphState = Annotation.Root({
  messages: Annotation({ reducer: (a, b) => [...a, ...b] }),
  apiToken: Annotation({ reducer: (_, b) => b }),   // secret token kept in shared state
});

const memory = new MemorySaver();

// ASI08: graph wired entirely through chained top-level calls — no function/class declarations
const graph = new StateGraph(graphState)
  .addNode("passthrough", (state) => state)
  .addEdge("__start__", "passthrough")
  .addEdge("passthrough", "__end__")
  .compile({ checkpointer: memory });

export { graph };
