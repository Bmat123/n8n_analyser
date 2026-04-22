import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  NodeType,
  DB_NODE_TYPES,
  buildPortedAdjacencyList,
  buildNodeMap,
  getLoopBodyNodes,
  getStringParam,
  getUpstreamNodes,
  buildReverseAdjacencyList,
  tryParseUrl,
} from "../utils.js";

// ─── DQ-003 — Unthrottled loop with HTTP Request ──────────────────────────────

const dq003: RuleRunner = {
  definition: {
    id: "DQ-003",
    severity: "high",
    category: "performance",
    title: "Loop contains HTTP Request node with no rate limiting",
    description:
      "Iterating over items and firing an HTTP request per item with no delay will saturate the target API's rate limit, resulting in 429 errors or an IP ban.",
    remediation:
      "Add a Wait node inside the loop with an interval appropriate for the target API's rate limit (e.g. 100ms for 10 req/s limits).",
  },
  run({ workflow, config }) {
    const violations: Violation[] = [];
    const portedGraph = buildPortedAdjacencyList(workflow.connections);
    const loopBodies = getLoopBodyNodes(workflow, portedGraph);

    for (const [loopName, bodyNodeNames] of loopBodies) {
      if (config.loopRateLimitExemptions.has(loopName)) continue;

      const httpNodes = [...bodyNodeNames].filter((name) => {
        const n = workflow.nodes.find((n) => n.name === name);
        return n && !n.disabled && n.type === NodeType.HTTP_REQUEST;
      });
      if (httpNodes.length === 0) continue;

      const hasWait = [...bodyNodeNames].some((name) => {
        const n = workflow.nodes.find((n) => n.name === name);
        return n && !n.disabled && n.type === NodeType.WAIT;
      });
      if (hasWait) continue;

      violations.push({
        ruleId: "DQ-003",
        severity: "high",
        category: "performance",
        title: `Loop "${loopName}" has HTTP Request(s) with no rate limiting`,
        description: `Loop node "${loopName}" contains HTTP Request node(s) (${httpNodes.join(", ")}) but no Wait node. Each loop iteration fires immediately, which will exhaust API rate limits.`,
        evidence: `HTTP nodes in loop: ${httpNodes.join(", ")}`,
        remediation: dq003.definition.remediation,
      });
    }
    return violations;
  },
};

// ─── DQ-004 — Full table scan in database query ───────────────────────────────

const SELECT_ALL_PATTERN = /^\s*SELECT\s+\*/i;
const WHERE_PATTERN = /\bWHERE\b/i;
const LIMIT_PATTERN = /\bLIMIT\b/i;

const dq004: RuleRunner = {
  definition: {
    id: "DQ-004",
    severity: "high",
    category: "performance",
    title: "Database query node may perform a full table scan",
    description:
      "Fetching an entire table on every execution causes memory exhaustion and slow execution as data grows. Always filter to a relevant time window and add a LIMIT safety cap.",
    remediation:
      "Add a WHERE clause filtering to a relevant window (e.g. WHERE created_at > NOW() - INTERVAL '1 hour') and a LIMIT clause as a safety cap.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !DB_NODE_TYPES.has(node.type)) continue;

      const op = (getStringParam(node.parameters, "operation") ?? "").toLowerCase();
      const query = (getStringParam(node.parameters, "query") ?? "").trim();

      // Only check SELECT operations
      const isSelect = op === "select" || op === "find" || op === "findOne" ||
        SELECT_ALL_PATTERN.test(query);
      if (!isSelect) continue;

      const hasWhere = WHERE_PATTERN.test(query);
      const hasLimit = LIMIT_PATTERN.test(query);

      // For raw queries, check for both WHERE and LIMIT
      if (query) {
        if (!hasWhere || !hasLimit) {
          violations.push({
            ruleId: "DQ-004",
            severity: "high",
            category: "performance",
            title: `Database query "${node.name}" may perform a full table scan`,
            description: `Node "${node.name}" executes a SELECT query${!hasWhere ? " with no WHERE clause" : ""}${!hasLimit ? " and no LIMIT clause" : ""}. On large tables this causes memory exhaustion and full table scans.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: "parameters.query",
            evidence: query.slice(0, 120),
            remediation: dq004.definition.remediation,
          });
        }
      } else if (op === "select" || op === "find") {
        // No raw query — check query parameters for missing filters
        const limit = node.parameters.limit;
        if (!limit) {
          violations.push({
            ruleId: "DQ-004",
            severity: "high",
            category: "performance",
            title: `Database SELECT in "${node.name}" has no limit`,
            description: `Node "${node.name}" performs a SELECT with operation="${op}" but no limit is configured. This may return the entire table.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: "parameters.limit",
            evidence: `operation=${op}, limit=not set`,
            remediation: dq004.definition.remediation,
          });
        }
      }
    }
    return violations;
  },
};

// ─── PERF-001 — N+1 query pattern ────────────────────────────────────────────

const perf001: RuleRunner = {
  definition: {
    id: "PERF-001",
    severity: "high",
    category: "performance",
    title: "Database query node is inside a loop",
    description:
      "Querying the database once per item in a loop is the N+1 query anti-pattern. For 1,000 items this means 1,000 round-trips to the database.",
    remediation:
      "Collect all IDs from the loop input, execute a single SELECT ... WHERE id IN (...) query outside the loop, and join the results in a Set node.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    const portedGraph = buildPortedAdjacencyList(workflow.connections);
    const loopBodies = getLoopBodyNodes(workflow, portedGraph);

    for (const [loopName, bodyNodeNames] of loopBodies) {
      const dbNodes = [...bodyNodeNames].filter((name) => {
        const n = workflow.nodes.find((n) => n.name === name);
        return n && !n.disabled && DB_NODE_TYPES.has(n.type);
      });
      if (dbNodes.length === 0) continue;

      violations.push({
        ruleId: "PERF-001",
        severity: "high",
        category: "performance",
        title: `N+1 query: database node(s) inside loop "${loopName}"`,
        description: `Loop "${loopName}" contains database node(s) (${dbNodes.join(", ")}). Each loop iteration fires a separate database query, creating the N+1 anti-pattern.`,
        evidence: `DB nodes in loop: ${dbNodes.join(", ")}`,
        remediation: perf001.definition.remediation,
      });
    }
    return violations;
  },
};

// ─── PERF-002 — Polling interval too aggressive ───────────────────────────────

// Parse a cron expression's minimum interval in seconds
function cronMinIntervalSeconds(cron: string): number {
  // Simple heuristic: split and check seconds/minutes fields
  const parts = cron.trim().split(/\s+/);
  if (parts.length < 5) return Infinity;

  const seconds = parts.length === 6 ? parts[0] : "0";
  const minutes = parts.length === 6 ? parts[1] : parts[0];

  // If seconds field is not 0 or *, interval is sub-minute
  if (seconds !== "0" && seconds !== "*") return 0;
  // If minutes is */N, the interval is N minutes
  const everyN = minutes.match(/^\*\/(\d+)$/);
  if (everyN) return parseInt(everyN[1], 10) * 60;
  // If minutes is a single number (e.g. "0"), it runs once per hour at that minute
  if (/^\d+$/.test(minutes)) return 3600;
  // If minutes is *, it runs every minute
  if (minutes === "*") return 60;
  return Infinity;
}

const perf002: RuleRunner = {
  definition: {
    id: "PERF-002",
    severity: "medium",
    category: "performance",
    title: "Schedule trigger fires more frequently than once per minute",
    description:
      "Sub-minute polling creates extremely high execution volume and credential usage. Near-real-time processing should use a webhook-based trigger instead.",
    remediation:
      "Switch to a webhook-based trigger for near-real-time processing. If polling is unavoidable, the minimum sensible interval is 1 minute.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;
      if (node.type !== NodeType.SCHEDULE_TRIGGER && node.type !== NodeType.CRON) continue;

      // Check interval-based config (scheduleTrigger uses rule array)
      const rules = node.parameters.rule as Record<string, unknown> | undefined;
      const interval = rules?.interval as number | undefined;

      if (typeof interval === "number" && interval < 60) {
        violations.push({
          ruleId: "PERF-002",
          severity: "medium",
          category: "performance",
          title: `Schedule trigger "${node.name}" fires every ${interval}s (< 1 minute)`,
          description: `Node "${node.name}" is configured to run every ${interval} seconds. Sub-minute polling creates very high execution volume.`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          field: "parameters.rule.interval",
          evidence: `interval=${interval}s`,
          remediation: perf002.definition.remediation,
        });
        continue;
      }

      // Check cron expression
      const cronExpression =
        getStringParam(node.parameters, "triggerTimes", "item") ??
        getStringParam(node.parameters, "cronExpression") ??
        getStringParam(node.parameters, "expression");
      if (cronExpression) {
        const minInterval = cronMinIntervalSeconds(cronExpression);
        if (minInterval < 60) {
          violations.push({
            ruleId: "PERF-002",
            severity: "medium",
            category: "performance",
            title: `Schedule trigger "${node.name}" fires sub-minute`,
            description: `Node "${node.name}" has a cron expression that triggers more than once per minute: "${cronExpression}".`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: "parameters.cronExpression",
            evidence: cronExpression,
            remediation: perf002.definition.remediation,
          });
        }
      }
    }
    return violations;
  },
};

// ─── PERF-003 — Large dataset without pagination (advisory) ──────────────────

const PAGINATION_PARAMS = /[?&](page|offset|cursor|after|before|per_page|limit|pageSize|page_size|skip)=/i;

const perf003: RuleRunner = {
  definition: {
    id: "PERF-003",
    severity: "low",
    category: "performance",
    title: "API call fetches potentially unbounded result set with no pagination",
    description:
      "APIs that return large datasets will return all records in a single response if no pagination parameters are sent, causing memory exhaustion.",
    remediation:
      "Always implement pagination: use the Split In Batches node with a loop, passing page or cursor parameters on each iteration.",
  },
  run({ workflow, config }) {
    if (!config.includeAdvisory) return [];

    const violations: Violation[] = [];
    const reverseGraph = buildReverseAdjacencyList(workflow.connections);
    const nodeMap = buildNodeMap(workflow);
    const portedGraph = buildPortedAdjacencyList(workflow.connections);
    const loopBodies = getLoopBodyNodes(workflow, portedGraph);

    // Build a set of all nodes that are inside any loop body
    const allLoopBodyNodes = new Set<string>();
    for (const bodyNames of loopBodies.values()) {
      for (const name of bodyNames) allLoopBodyNodes.add(name);
    }

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;

      // Skip nodes already inside a loop (they're likely part of pagination)
      if (allLoopBodyNodes.has(node.name)) continue;

      const url = getStringParam(node.parameters, "url") ?? "";
      if (PAGINATION_PARAMS.test(url)) continue;

      // Check upstream (up to 5 hops) for a loop/split node
      const upstream = getUpstreamNodes(node.name, reverseGraph, 5);
      const hasUpstreamLoop = [...upstream].some((name) => {
        const n = nodeMap.get(name);
        return n && (n.type === NodeType.SPLIT_IN_BATCHES || n.type === NodeType.LOOP_OVER_ITEMS);
      });
      if (hasUpstreamLoop) continue;

      violations.push({
        ruleId: "PERF-003",
        severity: "low",
        category: "performance",
        title: `HTTP Request "${node.name}" may fetch an unbounded result set`,
        description: `Node "${node.name}" makes an HTTP request with no pagination parameters in the URL and is not inside a pagination loop. If the API returns large datasets, this will cause memory exhaustion.`,
        node: { id: node.id, name: node.name, type: node.type, position: node.position },
        field: "parameters.url",
        evidence: url.slice(0, 120) || "(dynamic URL)",
        remediation: perf003.definition.remediation,
        confidence: "advisory",
      });
    }
    return violations;
  },
};

// ─── PERF-004 — Redundant repeated API calls to same endpoint ────────────────

const perf004: RuleRunner = {
  definition: {
    id: "PERF-004",
    severity: "low",
    category: "performance",
    title: "Same external endpoint called multiple times in the same workflow",
    description:
      "Multiple calls to the same endpoint for the same data waste API quota and add latency. Fetch the data once and reference the stored value downstream.",
    remediation:
      "Fetch the data once, store the result in a Set node, and reference the stored value downstream using {{ $node[\"Set\"].json.fieldName }}.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    // Map: normalised host+path → list of node names
    const endpointMap = new Map<string, string[]>();

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;

      const url = getStringParam(node.parameters, "url") ?? "";
      const parsed = tryParseUrl(url);
      if (!parsed) continue; // skip dynamic URLs

      const key = `${parsed.hostname}${parsed.pathname}`;
      if (!endpointMap.has(key)) endpointMap.set(key, []);
      endpointMap.get(key)!.push(node.name);
    }

    for (const [endpoint, nodeNames] of endpointMap) {
      if (nodeNames.length <= 1) continue;

      violations.push({
        ruleId: "PERF-004",
        severity: "low",
        category: "performance",
        title: `Endpoint "${endpoint}" called ${nodeNames.length} times`,
        description: `The endpoint "${endpoint}" is called by ${nodeNames.length} HTTP Request nodes: ${nodeNames.join(", ")}. Duplicate calls waste API quota and add latency.`,
        evidence: nodeNames.join(", "),
        remediation: perf004.definition.remediation,
      });
    }
    return violations;
  },
};

export const performanceRules: RuleRunner[] = [dq003, dq004, perf001, perf002, perf003, perf004];
