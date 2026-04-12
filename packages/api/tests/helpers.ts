/**
 * Test helpers — minimal workflow / node builders so each test reads like a spec.
 *
 *   const wf = workflow([
 *     httpNode("Call API", { url: "http://example.com" }),
 *   ]);
 *   const violations = run(credentialsRules, wf);
 *   expectRule(violations, "NET-001");
 */

import type {
  N8nWorkflow,
  N8nNode,
  N8nConnections,
  Violation,
} from "@n8n-analyzer/types";
import type { Config } from "../src/config.js";
import type { RuleRunner } from "../src/analyzer/types.js";

// ─── Default test config ──────────────────────────────────────────────────────

export const defaultConfig: Config = {
  port: 3000,
  approvedDbHosts: new Set(),
  approvedEgressHosts: new Set(),
  disabledRules: new Set(),
  severityThreshold: "low",
  redactEvidence: false,       // off so tests can inspect actual matched values
  requestSizeLimit: "5mb",
  geminiApiKey: null,
  n8nFetchTimeoutMs: 5000,
  corsOrigin: "*",
  maxNodesDecompWarning: 20,
  maxNodesHardLimit: 40,
  loopRateLimitExemptions: new Set(),
  includeAdvisory: true,
  currencyFieldNames: new Set(["price", "amount", "total", "cost", "fee", "rate", "tax", "discount", "subtotal"]),
};

// ─── Node builders ────────────────────────────────────────────────────────────

let _nodeIdx = 0;
function nextId() {
  return `node-${++_nodeIdx}`;
}

type NodeOverrides = Partial<Omit<N8nNode, "id" | "parameters">> & {
  parameters?: Record<string, unknown>;
};

function makeNode(
  name: string,
  type: string,
  parameters: Record<string, unknown> = {},
  overrides: NodeOverrides = {}
): N8nNode {
  return {
    id: nextId(),
    name,
    type,
    position: [0, 0],
    parameters,
    ...overrides,
  };
}

export const B = "n8n-nodes-base.";

export function httpNode(
  name: string,
  params: Record<string, unknown> = {},
  overrides: NodeOverrides = {}
): N8nNode {
  return makeNode(name, `${B}httpRequest`, params, overrides);
}

export function webhookNode(
  name: string,
  params: Record<string, unknown> = {},
  overrides: NodeOverrides = {}
): N8nNode {
  return makeNode(name, `${B}webhook`, params, overrides);
}

export function setNode(
  name: string,
  params: Record<string, unknown> = {},
  overrides: NodeOverrides = {}
): N8nNode {
  return makeNode(name, `${B}set`, params, overrides);
}

export function codeNode(
  name: string,
  jsCode: string,
  overrides: NodeOverrides = {}
): N8nNode {
  return makeNode(name, `${B}code`, { jsCode }, overrides);
}

export function scheduleNode(name = "Schedule"): N8nNode {
  return makeNode(name, `${B}scheduleTrigger`, {});
}

export function errorTriggerNode(name = "Error Handler"): N8nNode {
  return makeNode(name, `${B}errorTrigger`, {});
}

export function respondToWebhookNode(
  name: string,
  params: Record<string, unknown> = {},
  overrides: NodeOverrides = {}
): N8nNode {
  return makeNode(name, `${B}respondToWebhook`, params, overrides);
}

export function executeWorkflowNode(
  name: string,
  workflowId: string | { __rl: true; value: string; mode: string }
): N8nNode {
  return makeNode(name, `${B}executeWorkflow`, { workflowId });
}

export function slackNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}slack`, params);
}

export function googleSheetsNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}googleSheets`, params);
}

export function communityNode(
  name: string,
  namespace: string,
  params: Record<string, unknown> = {},
  overrides: NodeOverrides = {}
): N8nNode {
  return makeNode(name, namespace, params, overrides);
}

export function postgresNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}postgres`, params);
}

export function mysqlNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}mySql`, params);
}

export function ifNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}if`, params);
}

export function switchNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}switch`, params);
}

export function waitNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}wait`, params);
}

export function splitInBatchesNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}splitInBatches`, params);
}

export function stickyNoteNode(name: string): N8nNode {
  return makeNode(name, `${B}stickyNote`, {});
}

export function mergeNode(
  name: string,
  params: Record<string, unknown> = {}
): N8nNode {
  return makeNode(name, `${B}merge`, params);
}

export function genericNode(
  name: string,
  type: string,
  params: Record<string, unknown> = {},
  overrides: NodeOverrides = {}
): N8nNode {
  return makeNode(name, type, params, overrides);
}

// ─── Workflow builder ─────────────────────────────────────────────────────────

/**
 * Build a minimal workflow from a node list.
 * Pass `connections` to add explicit edges; otherwise the workflow is
 * a disconnected bag of nodes (sufficient for most single-node rule tests).
 */
export function workflow(
  nodes: N8nNode[],
  options: {
    connections?: N8nConnections;
    name?: string;
    active?: boolean;
    id?: string;
  } = {}
): N8nWorkflow {
  return {
    id: options.id ?? "wf-test",
    name: options.name ?? "Test Workflow",
    active: options.active ?? false,
    nodes,
    connections: options.connections ?? {},
  };
}

/**
 * Chain nodes left-to-right: A → B → C → ...
 */
export function chain(...nodes: N8nNode[]): N8nConnections {
  const connections: N8nConnections = {};
  for (let i = 0; i < nodes.length - 1; i++) {
    connections[nodes[i].name] = {
      main: [[{ node: nodes[i + 1].name, type: "main", index: 0 }]],
    };
  }
  return connections;
}

// ─── Rule runner ──────────────────────────────────────────────────────────────

export function run(
  rules: RuleRunner[],
  wf: N8nWorkflow,
  cfg: Config = defaultConfig
): Violation[] {
  return rules.flatMap((r) => r.run({ workflow: wf, config: cfg }));
}

// ─── Assertions ───────────────────────────────────────────────────────────────

/** Assert that at least one violation with the given ruleId is present. */
export function expectRule(violations: Violation[], ruleId: string): Violation {
  const match = violations.find((v) => v.ruleId === ruleId);
  if (!match) {
    throw new Error(
      `Expected rule ${ruleId} to fire but it did not.\nViolations found: [${violations.map((v) => v.ruleId).join(", ")}]`
    );
  }
  return match;
}

/** Assert that NO violation with the given ruleId is present. */
export function expectNoRule(violations: Violation[], ruleId: string): void {
  const match = violations.find((v) => v.ruleId === ruleId);
  if (match) {
    throw new Error(
      `Expected rule ${ruleId} NOT to fire, but it did.\nEvidence: ${match.evidence ?? "(none)"}\nDescription: ${match.description}`
    );
  }
}

/** Assert exactly N violations for a given ruleId. */
export function expectRuleCount(
  violations: Violation[],
  ruleId: string,
  count: number
): void {
  const matches = violations.filter((v) => v.ruleId === ruleId);
  if (matches.length !== count) {
    throw new Error(
      `Expected ${count} violation(s) for ${ruleId} but got ${matches.length}.\nViolations: ${JSON.stringify(matches.map((v) => v.description), null, 2)}`
    );
  }
}
