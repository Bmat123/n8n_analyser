/**
 * Internal type definitions for the graph analysis engine.
 * Only response-surface types are exported from @wflow-analyzer/types.
 */
import type { Severity } from "@wflow-analyzer/types";

// ─── NodeCategory ─────────────────────────────────────────────────────────────

export const NodeCategory = {
  TRIGGER_WEBHOOK:    "trigger:webhook",
  TRIGGER_SCHEDULE:   "trigger:schedule",
  TRIGGER_MANUAL:     "trigger:manual",
  TRIGGER_EVENT:      "trigger:event",
  EXTERNAL_CALL:      "io:external_call",
  DATABASE_READ:      "io:database_read",
  DATABASE_WRITE:     "io:database_write",
  FILESYSTEM:         "io:filesystem",
  EMAIL:              "io:email",
  CHAT:               "io:chat",
  SPREADSHEET:        "io:spreadsheet",
  TRANSFORM:          "logic:transform",
  FILTER:             "logic:filter",
  LOOP:               "logic:loop",
  MERGE:              "logic:merge",
  WAIT:               "logic:wait",
  CODE:               "logic:code",
  EXECUTE_WORKFLOW:   "control:execute_workflow",
  ERROR_TRIGGER:      "control:error_trigger",
  RESPOND_WEBHOOK:    "control:respond_webhook",
  STOP_AND_ERROR:     "control:stop_and_error",
  DANGEROUS:          "danger:exec",
  NOTIFICATION:       "io:notification",
  UNKNOWN:            "unknown",
} as const;

export type NodeCategory = (typeof NodeCategory)[keyof typeof NodeCategory];

// ─── Taint & Schema ───────────────────────────────────────────────────────────

export interface TaintLabel {
  source: "webhook_body" | "webhook_headers" | "external_api" | "database" | "user_input";
  fieldPath?: string;
  pii: boolean;
}

export interface CredentialReference {
  credentialId: string;
  credentialType: string;
  nodeName: string;
}

export interface InferredSchema {
  fields: string[];
  piiFields: string[];
}

// ─── Graph Nodes & Edges ──────────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  name: string;
  type: string;
  category: NodeCategory;
  isTrigger: boolean;
  isTerminal: boolean;
  parameters: Record<string, unknown>;
  credentials: CredentialReference[];
  expressions: string[];
  taintSources: TaintLabel[];
  position: [number, number];
}

export interface GraphEdge {
  id: string;
  sourceName: string;
  targetName: string;
  sourceBranch: number;
  branchType: "main" | "true" | "false" | "error";
  dataSchema?: InferredSchema;
}

// ─── Graph Metadata ───────────────────────────────────────────────────────────

export interface GraphMetadata {
  totalNodes: number;
  totalEdges: number;
  hasCycles: boolean;
  cyclomaticComplexity: number;
  diameter: number;
  triggerNodes: string[];
  terminalNodes: string[];
  orphanedNodes: string[];
  stronglyConnectedComponents: string[][];
}

// ─── Property Graph ───────────────────────────────────────────────────────────

export interface PropertyGraph {
  workflowId: string | null;
  workflowName: string | null;
  /** Keyed by node name (n8n connections reference nodes by name) */
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  metadata: GraphMetadata;
}

// ─── Internal Violation ───────────────────────────────────────────────────────

export interface GraphViolationInternal {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  confidence: "certain" | "probable" | "advisory";
  affectedNodes: string[];
  affectedPath?: string[];
  evidence: string;
  remediation: string;
  escalateToLLM: boolean;
  /** Populated by the LLM layer if escalated */
  llmReasoning?: string;
  llmConfirmed?: boolean;
}
