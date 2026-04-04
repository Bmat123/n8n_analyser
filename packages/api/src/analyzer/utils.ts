/**
 * Shared utilities for the rule engine.
 * No rule-specific logic lives here — only pure helpers.
 */

import type { N8nNode, N8nWorkflow, N8nConnections } from "@n8n-analyzer/types";

// ─── Parameter Walker ─────────────────────────────────────────────────────────

export interface ParamEntry {
  /** Dot-notation path, e.g. "parameters.url" or "parameters.headers[0].value" */
  path: string;
  value: string;
}

/**
 * Recursively walks all string leaf values in a node's parameters object.
 * Yields { path, value } for every string found.
 */
export function* walkStringParams(
  obj: unknown,
  prefix = "parameters"
): Generator<ParamEntry> {
  if (typeof obj === "string") {
    yield { path: prefix, value: obj };
    return;
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      yield* walkStringParams(obj[i], `${prefix}[${i}]`);
    }
    return;
  }
  if (obj !== null && typeof obj === "object") {
    for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
      yield* walkStringParams(val, `${prefix}.${key}`);
    }
  }
}

/** Walk all string params in a node */
export function* walkNodeParams(node: N8nNode): Generator<ParamEntry> {
  yield* walkStringParams(node.parameters, "parameters");
}

// ─── Evidence Redaction ───────────────────────────────────────────────────────

/**
 * Redacts a matched secret string.
 * Keeps the first 4 characters visible so the type of secret is identifiable.
 */
export function redactEvidence(value: string, redact: boolean): string {
  if (!redact) return value;
  const prefix = value.slice(0, 4);
  return `${prefix}****REDACTED****`;
}

// ─── URL Utilities ────────────────────────────────────────────────────────────

/** Safely parse a URL, returning null on failure */
export function tryParseUrl(raw: string): URL | null {
  try {
    // n8n expressions aren't valid URLs — skip them
    if (raw.includes("{{") || raw.includes("$json")) return null;
    if (!raw.match(/^https?:\/\//i)) return null;
    return new URL(raw);
  } catch {
    return null;
  }
}

/** Returns the hostname portion of a URL string, or null */
export function extractHostname(raw: string): string | null {
  const u = tryParseUrl(raw);
  return u ? u.hostname.toLowerCase() : null;
}

// ─── IP Range Helpers ─────────────────────────────────────────────────────────

const PRIVATE_IP_PATTERNS = [
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
  /^127\./,
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^169\.254\./,
  /^fc[0-9a-f]{2}:/i, // IPv6 ULA
];

const PRIVATE_HOSTNAME_SUFFIXES = [".internal", ".local", ".svc.cluster.local"];
const PRIVATE_HOSTNAME_EXACT = new Set(["localhost", "127.0.0.1", "::1"]);

export function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase();
  if (PRIVATE_HOSTNAME_EXACT.has(h)) return true;
  if (PRIVATE_HOSTNAME_SUFFIXES.some((s) => h.endsWith(s))) return true;
  return PRIVATE_IP_PATTERNS.some((re) => re.test(h));
}

// ─── n8n Expression Helpers ───────────────────────────────────────────────────

/** True if the value is entirely a single n8n expression (fully dynamic) */
export function isFullyDynamicExpression(value: string): boolean {
  return /^\s*=?\s*\{\{[\s\S]+\}\}\s*$/.test(value);
}

/** Extracts all n8n expression strings from a value like "hello {{ $json.name }}" */
export function extractExpressions(value: string): string[] {
  const matches = value.match(/\{\{[\s\S]+?\}\}/g);
  return matches ?? [];
}

// ─── Node Type Helpers ────────────────────────────────────────────────────────

const BASE = "n8n-nodes-base.";

export const NodeType = {
  WEBHOOK: `${BASE}webhook`,
  HTTP_REQUEST: `${BASE}httpRequest`,
  SET: `${BASE}set`,
  CODE: `${BASE}code`,
  FUNCTION: `${BASE}function`,
  FUNCTION_ITEM: `${BASE}functionItem`,
  EXECUTE_COMMAND: `${BASE}executeCommand`,
  SSH: `${BASE}ssh`,
  POSTGRES: `${BASE}postgres`,
  MYSQL: `${BASE}mysql`,
  MONGODB: `${BASE}mongoDb`,
  REDIS: `${BASE}redis`,
  ERROR_TRIGGER: `${BASE}errorTrigger`,
  IF: `${BASE}if`,
  SWITCH: `${BASE}switch`,
  FILTER: `${BASE}filter`,
  READ_WRITE_FILE: `${BASE}readWriteFile`,
  READ_BINARY_FILE: `${BASE}readBinaryFile`,
  WRITE_BINARY_FILE: `${BASE}writeBinaryFile`,
  // Supply chain / data flow
  RESPOND_TO_WEBHOOK: `${BASE}respondToWebhook`,
  EXECUTE_WORKFLOW: `${BASE}executeWorkflow`,
  GOOGLE_SHEETS: `${BASE}googleSheets`,
  AIRTABLE: `${BASE}airtable`,
  GMAIL: `${BASE}gmail`,
  EMAIL_SEND: `${BASE}emailSend`,
  SEND_EMAIL: `${BASE}sendEmail`,
  SLACK: `${BASE}slack`,
  TELEGRAM: `${BASE}telegram`,
  DISCORD: `${BASE}discord`,
  MICROSOFT_TEAMS: `${BASE}microsoftTeams`,
  SCHEDULE_TRIGGER: `${BASE}scheduleTrigger`,
  CRON: `${BASE}cron`,
} as const;

export const CODE_NODE_TYPES = new Set<string>([
  NodeType.CODE,
  NodeType.FUNCTION,
  NodeType.FUNCTION_ITEM,
]);

export const DB_NODE_TYPES = new Set<string>([
  NodeType.POSTGRES,
  NodeType.MYSQL,
  NodeType.MONGODB,
  NodeType.REDIS,
]);

export const SANITIZATION_NODE_TYPES = new Set<string>([
  NodeType.IF,
  NodeType.SWITCH,
  NodeType.SET,
  NodeType.FILTER,
]);

export const CHAT_NODE_TYPES = new Set<string>([
  NodeType.SLACK,
  NodeType.TELEGRAM,
  NodeType.DISCORD,
  NodeType.MICROSOFT_TEAMS,
]);

export const CLOUD_WRITE_NODE_TYPES = new Set<string>([
  NodeType.GOOGLE_SHEETS,
  NodeType.AIRTABLE,
  NodeType.GMAIL,
  NodeType.EMAIL_SEND,
  NodeType.SEND_EMAIL,
]);

/** Official n8n node namespace prefixes — everything else is a community node */
export const OFFICIAL_NODE_PREFIXES = [
  "n8n-nodes-base.",
  "@n8n/n8n-nodes-langchain.",
  "n8n-nodes-langchain.",
  "@n8n_io/",
];

export const TRIGGER_TYPE_SUFFIXES = ["trigger", "Trigger"];

// Node types that act as workflow entry points but don't end with "Trigger"
const KNOWN_TRIGGER_TYPES = new Set<string>([NodeType.WEBHOOK]);

export function isTriggerNode(type: string): boolean {
  if (KNOWN_TRIGGER_TYPES.has(type)) return true;
  return TRIGGER_TYPE_SUFFIXES.some((s) => type.endsWith(s));
}

export function isExternalDataNode(type: string): boolean {
  return (
    type === NodeType.WEBHOOK ||
    type === NodeType.HTTP_REQUEST ||
    DB_NODE_TYPES.has(type)
  );
}

// ─── Connection Graph ─────────────────────────────────────────────────────────

/**
 * Builds a node-name → downstream node-names adjacency list from n8n connections.
 */
export function buildAdjacencyList(
  connections: N8nConnections
): Map<string, Set<string>> {
  const graph = new Map<string, Set<string>>();

  for (const [sourceName, outputs] of Object.entries(connections)) {
    if (!graph.has(sourceName)) graph.set(sourceName, new Set());

    for (const outputGroup of outputs.main ?? []) {
      for (const conn of outputGroup) {
        graph.get(sourceName)!.add(conn.node);
        if (!graph.has(conn.node)) graph.set(conn.node, new Set());
      }
    }
  }
  return graph;
}

/**
 * BFS from a start node through the adjacency list.
 * Calls visitor(nodeName, depth) for each reachable node.
 * Stops traversing a branch if visitor returns false.
 */
export function bfsFrom(
  graph: Map<string, Set<string>>,
  startNode: string,
  visitor: (nodeName: string, depth: number) => boolean | void
): void {
  const visited = new Set<string>();
  const queue: Array<{ name: string; depth: number }> = [
    { name: startNode, depth: 0 },
  ];

  while (queue.length > 0) {
    const { name, depth } = queue.shift()!;
    if (visited.has(name)) continue;
    visited.add(name);

    const continueTraversal = visitor(name, depth);
    if (continueTraversal === false) continue;

    for (const neighbour of graph.get(name) ?? []) {
      if (!visited.has(neighbour)) {
        queue.push({ name: neighbour, depth: depth + 1 });
      }
    }
  }
}

/**
 * Returns true if every path from startNode to targetNode passes through
 * at least one node in the sanitizationSet.
 */
export function hasSanitizationBetween(
  graph: Map<string, Set<string>>,
  startNode: string,
  targetNode: string,
  sanitizationSet: Set<string>
): boolean {
  // DFS: find if there's any path to targetNode that has NO sanitization node
  function dfs(
    current: string,
    sawSanitization: boolean,
    visited: Set<string>
  ): boolean {
    if (current === targetNode) return sawSanitization;
    if (visited.has(current)) return true; // treat cycle as sanitized
    visited.add(current);

    const neighbours = graph.get(current) ?? new Set();
    if (neighbours.size === 0) return true; // dead end, not relevant

    for (const next of neighbours) {
      const nextSanitized =
        sawSanitization || sanitizationSet.has(next);
      if (!dfs(next, nextSanitized, new Set(visited))) return false;
    }
    return true;
  }

  return dfs(startNode, false, new Set());
}

// ─── Misc ─────────────────────────────────────────────────────────────────────

/** Safely get a nested string value from an object by dot-path */
export function getStringParam(
  params: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  let cur: unknown = params;
  for (const key of keys) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return typeof cur === "string" ? cur : undefined;
}

/** Return node objects indexed by name for quick lookup */
export function buildNodeMap(workflow: N8nWorkflow): Map<string, N8nNode> {
  const m = new Map<string, N8nNode>();
  for (const n of workflow.nodes) m.set(n.name, n);
  return m;
}
