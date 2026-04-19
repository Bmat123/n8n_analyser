/**
 * @n8n-analyzer/core — public API
 */

// ─── Analysis engine ──────────────────────────────────────────────────────────
export { analyzeWorkflow } from "./analyzer/index.js";
export { enhanceWithAI, suggestFix } from "./analyzer/ai.js";
export { ALL_RULES } from "./analyzer/rules/index.js";
export { toSarif } from "./sarif.js";

// ─── Graph engine ─────────────────────────────────────────────────────────────
export { buildPropertyGraph, classifyNode } from "./graph/builder.js";
export { runGraphPatterns } from "./graph/patterns.js";
export { runLLMEscalation } from "./graph/llm.js";
export {
  toAdjacencyListText,
  toAdjacencyMap,
  toMermaid,
  enumerateAllPaths,
  toKnowledgeGraphTriples,
} from "./graph/serialisers.js";
export {
  buildAdjList,
  reachableNodes,
  pathsBetween,
  detectCycles,
  topoSort,
  betweennessCentrality,
  findOrphanedNodes,
} from "./graph/algorithms.js";

// ─── Config ───────────────────────────────────────────────────────────────────
export { buildConfig } from "./config.js";
export type { Config } from "./config.js";

// ─── n8n fetcher ─────────────────────────────────────────────────────────────
export {
  fetchWorkflowFromN8n,
  FetchAuthError,
  FetchNotFoundError,
  FetchTimeoutError,
  FetchValidationError,
  FetchError,
} from "./fetcher.js";

// ─── Graph types ──────────────────────────────────────────────────────────────
export type {
  PropertyGraph,
  GraphNode,
  GraphEdge,
  GraphMetadata,
  GraphViolationInternal,
} from "./graph/types.js";
export { NodeCategory } from "./graph/types.js";
