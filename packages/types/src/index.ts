// ─── Severity & Category ──────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";

export type RuleCategory =
  | "credentials"
  | "network"
  | "data_policy"
  | "dangerous_nodes"
  | "expression_injection"
  | "workflow_hygiene"
  | "supply_chain"
  | "data_flow"
  | "loop_flow";

// ─── n8n Workflow Shape ───────────────────────────────────────────────────────

export interface N8nNode {
  id: string;
  name: string;
  /** e.g. "n8n-nodes-base.httpRequest" */
  type: string;
  position: [number, number];
  parameters: Record<string, unknown>;
  credentials?: Record<string, { id: string; name: string }>;
  disabled?: boolean;
  typeVersion?: number;
}

/**
 * Connections map: sourceNodeName → { main: Array<Array<{ node: string; type: string; index: number }>> }
 * This is the raw shape from n8n workflow exports.
 */
export type N8nConnections = Record<
  string,
  {
    main?: Array<
      Array<{
        node: string;
        type: string;
        index: number;
      }>
    >;
  }
>;

export interface N8nWorkflow {
  id?: string;
  name?: string;
  active?: boolean;
  nodes: N8nNode[];
  connections: N8nConnections;
  settings?: Record<string, unknown>;
  tags?: Array<{ id: string; name: string }>;
}

// ─── Rule Definition ──────────────────────────────────────────────────────────

export interface RuleDefinition {
  id: string;
  severity: Severity;
  category: RuleCategory;
  title: string;
  description: string;
  remediation: string;
}

// ─── Violation ────────────────────────────────────────────────────────────────

export interface ViolationNode {
  id: string;
  name: string;
  type: string;
  position: [number, number];
}

export interface Violation {
  ruleId: string;
  severity: Severity;
  category: RuleCategory;
  title: string;
  description: string;
  /** The node associated with the violation, if applicable */
  node?: ViolationNode;
  /** JSON-path-style pointer to the offending field, e.g. "parameters.url" */
  field?: string;
  /** Partially redacted value of the offending field */
  evidence?: string;
  remediation: string;
}

// ─── Analysis Report ──────────────────────────────────────────────────────────

export interface ReportSummary {
  totalNodes: number;
  totalViolations: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** Number of rules that ran and produced zero violations */
  passed: number;
}

export interface ReportMetadata {
  analyzerVersion: string;
  rulesetVersion: string;
  nodeTypesFound: string[];
}

export interface AiAnalysis {
  /** High-level narrative summary of the security posture */
  summary: string;
  /** Cross-node data flow risks that static rules may have missed */
  dataFlowRisks: string[];
  /** Violations the AI suspects may be false positives, with reasoning */
  falsePositiveNotes: string[];
  /** Ordered list: what to fix first and why */
  remediationPriority: string[];
  /** Architectural suggestions to improve overall security posture */
  suggestedRedesigns: string[];
  confidence: "high" | "medium" | "low";
}

export interface AnalysisReport {
  workflowId: string | null;
  workflowName: string | null;
  analyzedAt: string;
  summary: ReportSummary;
  violations: Violation[];
  passedRules: string[];
  skippedRules: string[];
  metadata: ReportMetadata;
  /** Present only when AI analysis was requested and succeeded */
  aiAnalysis?: AiAnalysis | null;
  /** Non-fatal warnings, e.g. "AI analysis unavailable" */
  warnings?: string[];
}

// ─── API Request Shapes ───────────────────────────────────────────────────────

export interface N8nApiReference {
  baseUrl: string;
  apiKey: string;
  workflowId: string;
}

/** POST /analyze — Mode A */
export interface AnalyzeWorkflowRequest {
  workflow: N8nWorkflow;
  /** If true and ANTHROPIC_API_KEY is set, attaches aiAnalysis to the report */
  ai?: boolean;
}

/** POST /analyze — Mode B */
export interface AnalyzeN8nRequest {
  n8n: N8nApiReference;
  ai?: boolean;
}

export type AnalyzeRequest = AnalyzeWorkflowRequest | AnalyzeN8nRequest;

/** POST /analyze/batch */
export interface BatchAnalyzeRequest {
  workflows: Array<AnalyzeWorkflowRequest | AnalyzeN8nRequest>;
  ai?: boolean;
}

export type BatchAnalyzeResponse = Array<
  AnalysisReport | { error: string }
>;

// ─── Fix Suggestion ───────────────────────────────────────────────────────────

export interface FixSuggestion {
  /** Plain-English explanation of the fix */
  explanation: string;
  /**
   * Suggested replacement for the node's parameters object.
   * null when the fix cannot be expressed as a parameter patch
   * (e.g. "move this to a credential vault" requires UI action).
   */
  patchedParameters: Record<string, unknown> | null;
  /**
   * true when patchedParameters was applied to the workflow and
   * re-running the rule confirmed the violation is gone.
   */
  verified: boolean;
  /** Human-readable note explaining the verification result */
  verificationNote: string;
}

// ─── Type Guards ──────────────────────────────────────────────────────────────

export function isAnalyzeWorkflowRequest(
  body: AnalyzeRequest
): body is AnalyzeWorkflowRequest {
  return "workflow" in body;
}

export function isAnalyzeN8nRequest(
  body: AnalyzeRequest
): body is AnalyzeN8nRequest {
  return "n8n" in body;
}
