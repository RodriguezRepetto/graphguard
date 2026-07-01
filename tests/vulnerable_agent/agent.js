/**
 * agent.js — Intentionally vulnerable LangGraph JS agent for GraphGuard testing.
 *
 * Intentional vulnerabilities present in this file:
 *   ASI01 — user input concatenated directly into LLM prompt string (line ~40)
 *   ASI02 — tool function receives raw unvalidated string input (line ~55)
 *   ASI03 — sensitive fields (apiToken, userPassword) in shared StateAnnotation (line ~20)
 *   ASI05 — pinned vulnerable package version @langchain/langgraph@1.1.9 (line ~10)
 *   ASI06 — destructive function deleteAllRecords() called without authorization check (line ~70)
 *   ASI07 — raw LLM output passed directly to next node without validation (line ~85)
 *   ASI08 — MemorySaver checkpointer used without state validation (line ~100)
 *
 * DO NOT deploy this agent. It exists solely as a scan target for GraphGuard.
 */

// ASI05: pinned to a known vulnerable version — @langchain/langgraph@1.1.9
import { StateGraph, Annotation, MemorySaver } from "@langchain/langgraph";
import { ChatOpenAI } from "@langchain/openai";

// ASI03: sensitive fields stored in shared agent state accessible to all nodes
const AgentState = Annotation.Root({
  messages:     Annotation({ reducer: (a, b) => [...a, ...b] }),
  userInput:    Annotation({ reducer: (_, b) => b }),
  apiToken:     Annotation({ reducer: (_, b) => b }),    // ASI03: secret token in state
  userPassword: Annotation({ reducer: (_, b) => b }),    // ASI03: password in state
  llmOutput:    Annotation({ reducer: (_, b) => b }),
  isAdmin:      Annotation({ reducer: (_, b) => b }),
});

const model = new ChatOpenAI({ modelName: "gpt-4o", temperature: 0 });

// ASI01: user input is concatenated directly into the LLM prompt without sanitisation
async function promptInjectionNode(state) {
  const userInput = state.userInput;

  // Vulnerable: attacker controls userInput and can override system instructions
  const prompt = "You are a helpful assistant. User request: " + userInput;

  const response = await model.invoke([{ role: "user", content: prompt }]);
  return { llmOutput: response.content, messages: [response] };
}

// ASI02: tool function accepts a raw unvalidated string and executes it
function executeCommandTool(rawCommand) {
  // Vulnerable: no validation, sanitisation, or allowlist check on rawCommand
  const result = eval(rawCommand);
  return { output: result };
}

// Tool node that passes user-supplied data straight to the tool
async function toolNode(state) {
  const userInput = state.userInput;
  // Vulnerable: user input passed directly to the tool without validation (ASI02)
  return executeCommandTool(userInput);
}

// ASI06: destructive operation called without any authorization or confirmation check
async function dataManagementNode(state) {
  // Vulnerable: no check that state.isAdmin is true before calling deleteAllRecords
  const records = await deleteAllRecords();
  return { messages: [{ role: "system", content: `Deleted ${records} records` }] };
}

async function deleteAllRecords() {
  // Simulated destructive database operation — no auth guard anywhere in the call chain
  return 9999;
}

// ASI07: raw LLM output is forwarded to the next node without any validation or sanitisation
async function outputForwardingNode(state) {
  const rawLlmOutput = state.llmOutput;

  // Vulnerable: the raw string from the LLM is passed along unvalidated;
  // a jailbroken model could inject instructions that alter downstream behaviour.
  return {
    messages: [{ role: "assistant", content: rawLlmOutput }],
    userInput: rawLlmOutput,   // propagates untrusted LLM output as the next user input
  };
}

// ASI08: MemorySaver is used without validating or sanitising state before checkpointing
const memory = new MemorySaver();

const graph = new StateGraph(AgentState)
  .addNode("promptInjection", promptInjectionNode)
  .addNode("tool",            toolNode)
  .addNode("dataManagement",  dataManagementNode)
  .addNode("outputForwarding", outputForwardingNode)
  .addEdge("__start__",       "promptInjection")
  .addEdge("promptInjection", "tool")
  .addEdge("tool",            "dataManagement")
  .addEdge("dataManagement",  "outputForwarding")
  .addEdge("outputForwarding", "__end__");

// ASI08: compile with MemorySaver but no validation of what gets persisted
const compiledGraph = graph.compile({ checkpointer: memory });

export { compiledGraph };
