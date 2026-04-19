import type { Violation } from "@n8n-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  NodeType,
  DB_NODE_TYPES,
  getStringParam,
  buildAdjacencyList,
  buildReverseAdjacencyList,
  getDownstreamNodes,
  getUpstreamNodes,
  buildNodeMap,
  isTriggerNode,
} from "../utils.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const NON_IDEMPOTENT_METHODS = new Set(["POST", "DELETE", "PATCH"]);
const IDEMPOTENCY_HEADER_NAMES = new Set([
  "idempotency-key",
  "x-idempotency-key",
  "x-request-id",
  "x-correlation-id",
]);

const DB_WRITE_OPERATIONS = new Set(["insert", "update", "delete", "upsert", "executeQuery"]);

function isDbWriteNode(node: { type: string; parameters: Record<string, unknown> }): boolean {
  if (!DB_NODE_TYPES.has(node.type)) return false;
  const op = getStringParam(node.parameters, "operation") ?? "";
  const query = getStringParam(node.parameters, "query") ?? "";
  if (DB_WRITE_OPERATIONS.has(op.toLowerCase())) return true;
  // Detect raw SQL writes
  const upperQuery = query.toUpperCase().trim();
  return (
    upperQuery.startsWith("INSERT") ||
    upperQuery.startsWith("UPDATE") ||
    upperQuery.startsWith("DELETE")
  );
}

function getHttpMethod(params: Record<string, unknown>): string {
  return (
    (getStringParam(params, "requestMethod") ?? getStringParam(params, "method") ?? "GET")
  ).toUpperCase();
}

function hasIdempotencyHeader(params: Record<string, unknown>): boolean {
  const headerGroups = [
    (params.headerParameters as Record<string, unknown> | undefined)?.parameters,
    (params.headerParameters as Record<string, unknown> | undefined)?.values,
    (params.headers as Record<string, unknown> | undefined)?.parameters,
  ];
  for (const group of headerGroups) {
    if (!Array.isArray(group)) continue;
    for (const h of group) {
      const name = (h as Record<string, unknown>).name;
      if (typeof name === "string" && IDEMPOTENCY_HEADER_NAMES.has(name.toLowerCase())) {
        return true;
      }
    }
  }
  return false;
}

const STATUS_CHECK_KEYWORDS = /statusCode|statuscode|status_code|\$json\.success|\$json\.error|\$json\.ok|\bstatus\b/i;

// ─── REL-001 — No timeout on HTTP Request ─────────────────────────────────────

const rel001: RuleRunner = {
  definition: {
    id: "REL-001",
    severity: "medium",
    category: "reliability",
    title: "HTTP Request node has no explicit timeout configured",
    description:
      "Without an explicit timeout, n8n falls back to the global instance timeout. If the target API hangs, the execution context is held open, blocking a worker thread until the global timeout fires.",
    remediation:
      "Set an explicit timeout on the HTTP Request node (typically 5,000–30,000 ms depending on the API). This ensures the workflow fails fast instead of hanging indefinitely.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;
      const timeout = node.parameters.timeout;
      if (timeout === undefined || timeout === null || timeout === 0 || timeout === "") {
        violations.push({
          ruleId: "REL-001",
          severity: "medium",
          category: "reliability",
          title: `HTTP Request node "${node.name}" has no timeout set`,
          description: `Node "${node.name}" makes an HTTP request with no explicit timeout. If the target server is slow or unresponsive, this execution will hang until the global n8n timeout fires.`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          field: "parameters.timeout",
          evidence: String(timeout ?? "not set"),
          remediation: rel001.definition.remediation,
        });
      }
    }
    return violations;
  },
};

// ─── REL-002 — Retry with no backoff ──────────────────────────────────────────

const rel002: RuleRunner = {
  definition: {
    id: "REL-002",
    severity: "medium",
    category: "reliability",
    title: "Retry on failure configured with no wait interval",
    description:
      "Retrying immediately with no backoff hammers a rate-limited or temporarily unavailable API, accelerating the failure and potentially triggering an IP ban.",
    remediation:
      "Set waitBetweenTries to at least 1,000 ms. For external APIs, prefer exponential backoff.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;
      if (node.parameters.retryOnFail !== true) continue;
      const wait = node.parameters.waitBetweenTries;
      if (wait === undefined || wait === null || wait === 0 || wait === "") {
        violations.push({
          ruleId: "REL-002",
          severity: "medium",
          category: "reliability",
          title: `HTTP Request "${node.name}" retries with no backoff`,
          description: `Node "${node.name}" has retryOnFail enabled but waitBetweenTries is ${JSON.stringify(wait ?? "not set")}. Immediate retries flood the target API.`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          field: "parameters.waitBetweenTries",
          evidence: String(wait ?? "not set"),
          remediation: rel002.definition.remediation,
        });
      }
    }
    return violations;
  },
};

// ─── REL-004 — DB insert with no upstream dedup ───────────────────────────────

const rel004: RuleRunner = {
  definition: {
    id: "REL-004",
    severity: "medium",
    category: "reliability",
    title: "Database insert node with no upstream deduplication check",
    description:
      "Workflows triggered by webhooks or schedules can fire multiple times for the same event. Without a prior existence check, duplicate records accumulate silently.",
    remediation:
      "Add a SELECT lookup before the INSERT to check for an existing record, or use an UPSERT / INSERT ... ON CONFLICT DO NOTHING pattern in your query.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    const reverseGraph = buildReverseAdjacencyList(workflow.connections);
    const nodeMap = buildNodeMap(workflow);

    for (const node of workflow.nodes) {
      if (node.disabled || !DB_NODE_TYPES.has(node.type)) continue;

      const op = (getStringParam(node.parameters, "operation") ?? "").toLowerCase();
      const query = (getStringParam(node.parameters, "query") ?? "").toUpperCase().trim();
      const isInsert = op === "insert" || query.startsWith("INSERT");
      if (!isInsert) continue;

      // Check upstream (up to 5 hops) for any IF node or DB SELECT
      const upstream = getUpstreamNodes(node.name, reverseGraph, 5);
      const hasDedup = [...upstream].some((name) => {
        const n = nodeMap.get(name);
        if (!n) return false;
        if (n.type === NodeType.IF || n.type === NodeType.FILTER) return true;
        if (DB_NODE_TYPES.has(n.type)) {
          const upOp = (getStringParam(n.parameters, "operation") ?? "").toLowerCase();
          return upOp === "select" || upOp === "find" || upOp === "findOne";
        }
        return false;
      });

      if (!hasDedup) {
        violations.push({
          ruleId: "REL-004",
          severity: "medium",
          category: "reliability",
          title: `Database INSERT in "${node.name}" has no upstream deduplication`,
          description: `Node "${node.name}" performs an INSERT with no upstream IF node or SELECT check. Duplicate executions will create duplicate records.`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          field: "parameters.operation",
          evidence: op || "INSERT",
          remediation: rel004.definition.remediation,
          confidence: "probable",
        });
      }
    }
    return violations;
  },
};

// ─── DQ-001 — continueOnFail overuse ─────────────────────────────────────────

const dq001: RuleRunner = {
  definition: {
    id: "DQ-001",
    severity: "high",
    category: "reliability",
    title: "'Continue on Error' overused — silent failures likely",
    description:
      "Using 'Continue on Error' broadly causes silent data corruption and makes workflows appear successful when they have partially failed.",
    remediation:
      "Use 'Continue on Error' only on nodes where failure is a known, handled business case. Add explicit IF nodes after critical operations to check for failure conditions.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    const nonTriggerNodes = workflow.nodes.filter(
      (n) => !n.disabled && !isTriggerNode(n.type)
    );
    if (nonTriggerNodes.length === 0) return [];

    const continueOnFailNodes = nonTriggerNodes.filter(
      (n) => n.parameters.continueOnFail === true || (n as unknown as Record<string, unknown>).continueOnFail === true
    );

    // Sub-check (a): >30% of non-trigger nodes
    const ratio = continueOnFailNodes.length / nonTriggerNodes.length;
    if (ratio > 0.3 && continueOnFailNodes.length >= 2) {
      violations.push({
        ruleId: "DQ-001",
        severity: "high",
        category: "reliability",
        title: `'Continue on Error' set on ${continueOnFailNodes.length}/${nonTriggerNodes.length} nodes (${Math.round(ratio * 100)}%)`,
        description: `${continueOnFailNodes.length} out of ${nonTriggerNodes.length} non-trigger nodes have 'Continue on Error' enabled. This masks failures and allows the workflow to report success when it has silently failed.`,
        evidence: continueOnFailNodes.map((n) => n.name).join(", "),
        remediation: dq001.definition.remediation,
      });
    }

    // Sub-check (b): DB write or non-idempotent HTTP with continueOnFail
    for (const node of continueOnFailNodes) {
      const isCritical =
        isDbWriteNode({ type: node.type, parameters: node.parameters }) ||
        (node.type === NodeType.HTTP_REQUEST &&
          NON_IDEMPOTENT_METHODS.has(getHttpMethod(node.parameters)));
      if (isCritical) {
        violations.push({
          ruleId: "DQ-001",
          severity: "high",
          category: "reliability",
          title: `'Continue on Error' on critical node "${node.name}"`,
          description: `Node "${node.name}" is a data-mutating operation (${node.type}) with 'Continue on Error' enabled. A failure here will be silently swallowed, potentially corrupting data.`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          field: "continueOnFail",
          evidence: "true",
          remediation: dq001.definition.remediation,
        });
      }
    }

    return violations;
  },
};

// ─── DQ-002 — HTTP Request with no downstream status check ───────────────────

const dq002: RuleRunner = {
  definition: {
    id: "DQ-002",
    severity: "high",
    category: "reliability",
    title: "HTTP Request node has no downstream response validation",
    description:
      "Many APIs return 200 OK with { 'success': false, 'error': '...' } in the body. Without a downstream IF or Code node checking the response, the workflow treats every API call as successful.",
    remediation:
      "Add an IF node immediately after the HTTP Request that checks the response body, e.g. {{ $json.success === true }} or the equivalent field for the target API.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    const graph = buildAdjacencyList(workflow.connections);
    const nodeMap = buildNodeMap(workflow);

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;

      const downstream = getDownstreamNodes(node.name, graph, 1);
      const hasCheck = [...downstream].some((name) => {
        const n = nodeMap.get(name);
        if (!n || n.disabled) return false;
        if (n.type === NodeType.IF || n.type === NodeType.SWITCH) return true;
        // Code node containing status-check keywords
        if (n.type === NodeType.CODE || n.type === NodeType.FUNCTION) {
          const code =
            getStringParam(n.parameters, "jsCode") ??
            getStringParam(n.parameters, "functionCode") ??
            getStringParam(n.parameters, "code") ?? "";
          return STATUS_CHECK_KEYWORDS.test(code);
        }
        return false;
      });

      if (!hasCheck) {
        violations.push({
          ruleId: "DQ-002",
          severity: "high",
          category: "reliability",
          title: `HTTP Request "${node.name}" has no downstream response check`,
          description: `Node "${node.name}" makes an HTTP request but none of its immediate downstream nodes validate the response body. API errors returned as 200 OK will be silently ignored.`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          evidence: [...downstream].join(", ") || "(no downstream nodes)",
          remediation: dq002.definition.remediation,
          confidence: "probable",
        });
      }
    }
    return violations;
  },
};

// ─── DQ-008 — Retry on non-idempotent method without idempotency key ─────────

const dq008: RuleRunner = {
  definition: {
    id: "DQ-008",
    severity: "high",
    category: "reliability",
    title: "Retry configured on a non-idempotent HTTP method",
    description:
      "Retrying POST, DELETE, or PATCH without an idempotency key creates duplicate records or duplicate side-effects — double charges, double emails, etc.",
    remediation:
      "Add an Idempotency-Key header with a stable value (e.g. derived from the input record ID), switch to PUT with a known resource ID, or remove the retry and handle failures explicitly.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;
      if (node.parameters.retryOnFail !== true) continue;
      const method = getHttpMethod(node.parameters);
      if (!NON_IDEMPOTENT_METHODS.has(method)) continue;
      if (hasIdempotencyHeader(node.parameters)) continue;

      violations.push({
        ruleId: "DQ-008",
        severity: "high",
        category: "reliability",
        title: `Retry on ${method} "${node.name}" without idempotency key`,
        description: `Node "${node.name}" uses retryOnFail on a ${method} request with no Idempotency-Key header. Each retry may create a duplicate record or trigger a duplicate side-effect.`,
        node: { id: node.id, name: node.name, type: node.type, position: node.position },
        field: "parameters.retryOnFail",
        evidence: `method=${method}, retryOnFail=true`,
        remediation: dq008.definition.remediation,
      });
    }
    return violations;
  },
};

// ─── OP-003 — DB write with no error workflow ─────────────────────────────────

const op003: RuleRunner = {
  definition: {
    id: "OP-003",
    severity: "medium",
    category: "reliability",
    title: "Workflow writes to a database but has no error handler attached",
    description:
      "Data write failures that go undetected cause data loss, inconsistency, or silent corruption. Without an error workflow, there is no way to be alerted or to trigger compensating actions.",
    remediation:
      "Attach an error workflow in the workflow settings. The error workflow should alert (Slack, email) and log the failure context including the workflow name, node, and error message.",
  },
  run({ workflow }) {
    const hasDbWrite = workflow.nodes.some(
      (n) => !n.disabled && isDbWriteNode({ type: n.type, parameters: n.parameters })
    );
    if (!hasDbWrite) return [];

    const settings = (workflow as unknown as Record<string, unknown>).settings as Record<string, unknown> | undefined;
    const hasErrorWorkflow = settings?.errorWorkflow && settings.errorWorkflow !== "";
    if (hasErrorWorkflow) return [];

    return [
      {
        ruleId: "OP-003",
        severity: "medium",
        category: "reliability",
        title: "Database write workflow has no error handler",
        description:
          "This workflow writes to a database but has no error workflow attached in the workflow settings. Failed writes will be silently lost with no alerting or compensating action.",
        remediation: op003.definition.remediation,
      },
    ];
  },
};

export const reliabilityRules: RuleRunner[] = [rel001, rel002, rel004, dq001, dq002, dq008, op003];
