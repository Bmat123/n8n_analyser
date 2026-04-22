import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  NodeType,
  CHAT_NODE_TYPES,
  CLOUD_WRITE_NODE_TYPES,
  getTerminalNodes,
  isTriggerNode,
} from "../utils.js";

// ─── OP-001 — Execution saving disabled ───────────────────────────────────────

const op001: RuleRunner = {
  definition: {
    id: "OP-001",
    severity: "high",
    category: "observability",
    title: "Execution data saving is disabled on a multi-node workflow",
    description:
      "Disabling execution data saving makes it impossible to debug failures after the fact, audit what data was processed, or verify correct operation.",
    remediation:
      "Enable execution saving in workflow settings. If storage is a concern, configure a shorter retention period rather than disabling saving entirely.",
  },
  run({ workflow }) {
    const settings = (workflow as unknown as Record<string, unknown>).settings as Record<string, unknown> | undefined;
    if (!settings) return [];

    const savingDisabled =
      settings.saveDataSuccessExecution === "none" ||
      settings.saveExecutionProgress === false;
    if (!savingDisabled) return [];

    const nonTriggerCount = workflow.nodes.filter((n) => !isTriggerNode(n.type)).length;
    if (nonTriggerCount <= 10) return [];

    return [
      {
        ruleId: "OP-001",
        severity: "high",
        category: "observability",
        title: "Execution saving disabled on a complex workflow",
        description: `This workflow has ${workflow.nodes.length} nodes but execution data saving is disabled (saveDataSuccessExecution=${JSON.stringify(settings.saveDataSuccessExecution)}, saveExecutionProgress=${JSON.stringify(settings.saveExecutionProgress)}). Failed executions cannot be debugged after the fact.`,
        evidence: `saveDataSuccessExecution=${settings.saveDataSuccessExecution ?? "default"}, saveExecutionProgress=${settings.saveExecutionProgress ?? "default"}`,
        remediation: op001.definition.remediation,
      },
    ];
  },
};

// ─── OP-002 — Error workflow has no alerting node ─────────────────────────────

const ERROR_WORKFLOW_NAME_PATTERNS = /error|fail|handler|alert/i;

const ALERTING_NODE_TYPES = new Set<string>([
  NodeType.SLACK,
  NodeType.TELEGRAM,
  NodeType.DISCORD,
  NodeType.MICROSOFT_TEAMS,
  NodeType.GMAIL,
  NodeType.EMAIL_SEND,
  NodeType.SEND_EMAIL,
  NodeType.HTTP_REQUEST, // could be a webhook alert
  ...CHAT_NODE_TYPES,
  ...CLOUD_WRITE_NODE_TYPES,
]);

const op002: RuleRunner = {
  definition: {
    id: "OP-002",
    severity: "medium",
    category: "observability",
    title: "Error workflow contains no alerting or notification node",
    description:
      "An error workflow that performs no alerting provides no operational value. When a production workflow fails silently, no one is notified.",
    remediation:
      "Add at minimum a Slack or email node that sends: the workflow name that failed, the node that failed, the error message, and a link to the execution.",
  },
  run({ workflow }) {
    // Only apply to workflows that appear to be error handlers (name heuristic)
    const name = workflow.name ?? "";
    if (!ERROR_WORKFLOW_NAME_PATTERNS.test(name)) return [];

    const hasAlerting = workflow.nodes.some(
      (n) => !n.disabled && ALERTING_NODE_TYPES.has(n.type)
    );
    if (hasAlerting) return [];

    return [
      {
        ruleId: "OP-002",
        severity: "medium",
        category: "observability",
        title: "Error workflow has no alerting node",
        description: `Workflow "${name}" appears to be an error handler but contains no alerting node (Slack, email, Teams, HTTP webhook, etc.). Failed executions will go unnoticed.`,
        evidence: `Node types present: ${[...new Set(workflow.nodes.map((n) => n.type))].join(", ")}`,
        remediation: op002.definition.remediation,
        confidence: "probable",
      },
    ];
  },
};

// ─── OP-005 — Workflow always exits success ───────────────────────────────────

const op005: RuleRunner = {
  definition: {
    id: "OP-005",
    severity: "medium",
    category: "observability",
    title: "Workflow has no mechanism to distinguish success from failure",
    description:
      "All terminal nodes return the same static response regardless of what happened. Operators and downstream consumers have no way to detect partial failures or empty runs.",
    remediation:
      "Terminal nodes should include execution metadata: how many records were processed, how many succeeded, how many failed, and any error summaries.",
  },
  run({ workflow }) {
    // Only meaningful if there are branches (IF / Switch)
    const hasBranching = workflow.nodes.some(
      (n) => !n.disabled && (n.type === NodeType.IF || n.type === NodeType.SWITCH)
    );
    if (!hasBranching) return [];

    const terminals = getTerminalNodes(workflow).filter((n) => !n.disabled);
    if (terminals.length === 0) return [];

    // Check if ALL terminal nodes are Set or RespondToWebhook returning static ok
    const allStaticSuccess = terminals.every((n) => {
      if (n.type === NodeType.SET) return true;
      if (n.type === NodeType.RESPOND_TO_WEBHOOK) {
        // Check if the response body contains a static ok:true
        const body = JSON.stringify(n.parameters);
        return /["']ok["']\s*:\s*true/.test(body) || /["']success["']\s*:\s*true/.test(body);
      }
      return false;
    });

    if (!allStaticSuccess) return [];

    // Suppress if graph is empty — avoid false positives on disconnected nodes
    if (Object.keys(workflow.connections).length === 0) return [];

    return [
      {
        ruleId: "OP-005",
        severity: "medium",
        category: "observability",
        title: "Workflow always exits with the same success response",
        description: `All ${terminals.length} terminal node(s) (${terminals.map((n) => `"${n.name}"`).join(", ")}) return a static success response. With branching logic present, some paths may represent failures that are indistinguishable from success.`,
        evidence: terminals.map((n) => n.name).join(", "),
        remediation: op005.definition.remediation,
        confidence: "probable",
      },
    ];
  },
};

// ─── OP-006 — Console.log in Code node ───────────────────────────────────────

const CONSOLE_PATTERN = /console\.(log|warn|error|info)\s*\(/;

const op006: RuleRunner = {
  definition: {
    id: "OP-006",
    severity: "low",
    category: "observability",
    title: "console.log statements found in Code node",
    description:
      "console.log in production Code nodes pollutes execution logs, can inadvertently capture PII or sensitive values, and makes meaningful log entries hard to find.",
    remediation:
      "Remove all console.log/warn/error/info statements before activating the workflow in production.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;
      if (node.type !== NodeType.CODE && node.type !== NodeType.FUNCTION && node.type !== NodeType.FUNCTION_ITEM) continue;

      const code =
        (node.parameters.jsCode as string | undefined) ??
        (node.parameters.functionCode as string | undefined) ??
        (node.parameters.code as string | undefined) ?? "";

      if (!CONSOLE_PATTERN.test(code)) continue;

      const matches = code.match(new RegExp(CONSOLE_PATTERN.source, "g")) ?? [];
      violations.push({
        ruleId: "OP-006",
        severity: "low",
        category: "observability",
        title: `console.log found in Code node "${node.name}"`,
        description: `Node "${node.name}" contains ${matches.length} console statement(s). These pollute execution logs and may inadvertently capture sensitive data in log output.`,
        node: { id: node.id, name: node.name, type: node.type, position: node.position },
        field: "parameters.jsCode",
        evidence: matches.slice(0, 3).join(", "),
        remediation: op006.definition.remediation,
      });
    }
    return violations;
  },
};

export const observabilityRules: RuleRunner[] = [op001, op002, op005, op006];
