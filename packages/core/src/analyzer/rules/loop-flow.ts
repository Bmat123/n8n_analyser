import type { RuleRunner } from "../types.js";
import { NodeType } from "../utils.js";

// ─── LF-001 ───────────────────────────────────────────────────────────────────

/**
 * Returns true if the cron expression fires more than once per minute.
 * Supports both 5-field (standard) and 6-field (with leading seconds) cron.
 */
function isSuperFrequentCron(expr: string): boolean {
  const fields = expr.trim().split(/\s+/);

  // 6-field cron has a leading seconds field — any value other than "0" means
  // it can fire multiple times per minute (e.g. "* * * * * *" = every second)
  if (fields.length === 6) {
    const secondsField = fields[0];
    // "0" = only fires at second 0, i.e. once per minute — not flagged
    if (secondsField !== "0") return true;
  }

  return false;
}

/**
 * Returns true if the n8n Schedule Trigger interval rule fires on a
 * seconds-based cadence (always sub-minute).
 */
function hasSecondsInterval(rule: unknown): boolean {
  if (!rule || typeof rule !== "object") return false;
  const r = rule as Record<string, unknown>;
  const intervals = Array.isArray(r.interval) ? r.interval : [];

  return intervals.some((item: unknown) => {
    if (!item || typeof item !== "object") return false;
    const i = item as Record<string, unknown>;
    return i.field === "seconds";
  });
}

const lf001: RuleRunner = {
  definition: {
    id: "LF-001",
    severity: "high",
    category: "loop_flow",
    title: "Trigger fires at sub-minute frequency",
    description:
      "A Schedule Trigger or Cron node is configured to fire more than once per minute (seconds-based interval or 6-field cron with a non-zero seconds field). Extremely high trigger frequency can exhaust n8n worker threads, overwhelm downstream APIs, and generate enormous execution log volume.",
    remediation:
      "Increase the trigger interval to at least one minute unless sub-minute frequency is a hard requirement. For high-frequency polling, consider using an event-driven trigger (webhook) instead, or batching operations.",
  },
  run({ workflow }) {
    const violations = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      if (node.type === NodeType.SCHEDULE_TRIGGER) {
        if (hasSecondsInterval(node.parameters.rule)) {
          violations.push({
            ruleId: "LF-001",
            severity: "high" as const,
            category: "loop_flow" as const,
            title: `Schedule Trigger "${node.name}" fires at sub-minute frequency`,
            description: `Node "${node.name}" uses a seconds-based interval. This can fire many times per minute, exhausting worker capacity.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: "parameters.rule.interval",
            remediation: lf001.definition.remediation,
          });
        }
      }

      if (node.type === NodeType.CRON) {
        // n8n's legacy Cron node stores the expression in parameters.triggerTimes.item
        const items = (node.parameters as Record<string, unknown>).triggerTimes;
        if (items && typeof items === "object") {
          const arr = (items as Record<string, unknown>).item;
          if (Array.isArray(arr)) {
            for (const item of arr) {
              if (!item || typeof item !== "object") continue;
              const i = item as Record<string, unknown>;
              const expr = typeof i.expression === "string" ? i.expression :
                           typeof i.value === "string" ? i.value : null;
              if (expr && isSuperFrequentCron(expr)) {
                violations.push({
                  ruleId: "LF-001",
                  severity: "high" as const,
                  category: "loop_flow" as const,
                  title: `Cron node "${node.name}" fires at sub-minute frequency`,
                  description: `Node "${node.name}" uses the cron expression "${expr}" which fires more than once per minute.`,
                  node: { id: node.id, name: node.name, type: node.type, position: node.position },
                  field: "parameters.triggerTimes",
                  evidence: expr,
                  remediation: lf001.definition.remediation,
                });
                break;
              }
            }
          }
        }
      }
    }

    return violations;
  },
};

// ─── LF-002 ───────────────────────────────────────────────────────────────────

/**
 * Extracts the target workflow ID from an Execute Workflow node's parameters.
 * n8n supports two formats:
 *   v1: parameters.workflowId = "123"
 *   v2: parameters.workflowId = { __rl: true, value: "123", mode: "id" }
 */
function extractTargetWorkflowId(params: Record<string, unknown>): string | null {
  const raw = params.workflowId;
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    if (typeof obj.value === "string") return obj.value;
  }
  return null;
}

const lf002: RuleRunner = {
  definition: {
    id: "LF-002",
    severity: "medium",
    category: "loop_flow",
    title: "Execute Workflow node calls the same workflow (direct self-recursion)",
    description:
      "An Execute Workflow node targets the current workflow's own ID. Unless there is an explicit base case that terminates the recursion, this creates an infinite execution loop that will exhaust worker threads and fill execution logs.",
    remediation:
      "Add a termination condition before the Execute Workflow node (e.g. an IF node that checks a counter or flag). If the intent is a queue-style loop, consider using n8n's built-in Loop Over Items node or a dedicated queue service instead.",
  },
  run({ workflow }) {
    const currentId = workflow.id;
    if (!currentId) return []; // can't compare without a known ID

    return workflow.nodes
      .filter((n) => !n.disabled && n.type === NodeType.EXECUTE_WORKFLOW)
      .filter((n) => extractTargetWorkflowId(n.parameters) === currentId)
      .map((n) => ({
        ruleId: "LF-002",
        severity: "medium" as const,
        category: "loop_flow" as const,
        title: `Execute Workflow node "${n.name}" calls this workflow recursively`,
        description: `Node "${n.name}" targets workflow ID "${currentId}", which is this workflow itself. Without a termination condition this will recurse indefinitely.`,
        node: { id: n.id, name: n.name, type: n.type, position: n.position },
        field: "parameters.workflowId",
        evidence: currentId,
        remediation: lf002.definition.remediation,
      }));
  },
};

export const loopFlowRules: RuleRunner[] = [lf001, lf002];
