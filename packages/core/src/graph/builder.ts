/**
 * Graph Builder — converts n8n workflow JSON into a PropertyGraph.
 * Pure function, no side effects.
 */
import type { N8nWorkflow, N8nNode } from "@wflow-analyzer/types";
import {
  NodeCategory,
  type PropertyGraph,
  type GraphNode,
  type GraphEdge,
  type GraphMetadata,
  type CredentialReference,
  type InferredSchema,
  type TaintLabel,
} from "./types.js";
import { tarjanSCC, computeCyclomaticComplexity, computeDiameter } from "./algorithms.js";

// ─── Node Classification ──────────────────────────────────────────────────────

const DB_WRITE_OPS = new Set(["insert", "update", "delete", "upsert", "create", "set", "remove", "replace"]);
const DB_TYPES = new Set([
  "n8n-nodes-base.postgres",
  "n8n-nodes-base.mysql",
  "n8n-nodes-base.mongoDb",
  "n8n-nodes-base.mongoDbV2",
  "n8n-nodes-base.redis",
]);

export function classifyNode(type: string, params: Record<string, unknown>): NodeCategory {
  const op = (params.operation as string | undefined)?.toLowerCase() ?? "";
  const t = type.toLowerCase();

  if (type === "n8n-nodes-base.webhook") return NodeCategory.TRIGGER_WEBHOOK;
  if (type === "n8n-nodes-base.scheduleTrigger" || type === "n8n-nodes-base.cron") return NodeCategory.TRIGGER_SCHEDULE;
  if (type === "n8n-nodes-base.manualTrigger") return NodeCategory.TRIGGER_MANUAL;
  if (type === "n8n-nodes-base.errorTrigger") return NodeCategory.ERROR_TRIGGER;
  if (type === "n8n-nodes-base.httpRequest") return NodeCategory.EXTERNAL_CALL;

  if (DB_TYPES.has(type)) {
    const query = (params.query as string | undefined)?.toUpperCase() ?? "";
    const isWrite = DB_WRITE_OPS.has(op) ||
      query.startsWith("INSERT") || query.startsWith("UPDATE") ||
      query.startsWith("DELETE") || query.startsWith("CREATE");
    return isWrite ? NodeCategory.DATABASE_WRITE : NodeCategory.DATABASE_READ;
  }

  if (type === "n8n-nodes-base.if" || type === "n8n-nodes-base.switch" || type === "n8n-nodes-base.filter")
    return NodeCategory.FILTER;
  if (type === "n8n-nodes-base.splitInBatches" || type === "n8n-nodes-base.loopOverItems")
    return NodeCategory.LOOP;
  if (type === "n8n-nodes-base.code" || type === "n8n-nodes-base.function" || type === "n8n-nodes-base.functionItem")
    return NodeCategory.CODE;
  if (type === "n8n-nodes-base.executeCommand" || type === "n8n-nodes-base.ssh")
    return NodeCategory.DANGEROUS;
  if (type === "n8n-nodes-base.slack" || type === "n8n-nodes-base.telegram" ||
      type === "n8n-nodes-base.discord" || type === "n8n-nodes-base.microsoftTeams")
    return NodeCategory.CHAT;
  if (type === "n8n-nodes-base.gmail" || type === "n8n-nodes-base.emailSend" || type === "n8n-nodes-base.sendEmail")
    return NodeCategory.EMAIL;
  if (type === "n8n-nodes-base.googleSheets" || type === "n8n-nodes-base.airtable")
    return NodeCategory.SPREADSHEET;
  if (type === "n8n-nodes-base.executeWorkflow") return NodeCategory.EXECUTE_WORKFLOW;
  if (type === "n8n-nodes-base.respondToWebhook") return NodeCategory.RESPOND_WEBHOOK;
  if (type === "n8n-nodes-base.stopAndError") return NodeCategory.STOP_AND_ERROR;
  if (type === "n8n-nodes-base.set" || type === "n8n-nodes-base.renameKeys") return NodeCategory.TRANSFORM;
  if (type === "n8n-nodes-base.merge") return NodeCategory.MERGE;
  if (type === "n8n-nodes-base.wait") return NodeCategory.WAIT;
  if (type === "n8n-nodes-base.readWriteFile" || type === "n8n-nodes-base.readBinaryFile" ||
      type === "n8n-nodes-base.writeBinaryFile") return NodeCategory.FILESYSTEM;
  if (type === "n8n-nodes-base.stickyNote") return NodeCategory.UNKNOWN;

  if (t.endsWith("trigger")) return NodeCategory.TRIGGER_EVENT;
  return NodeCategory.UNKNOWN;
}

// ─── Expression Extraction ────────────────────────────────────────────────────

function extractAllExpressions(obj: unknown): string[] {
  const results: string[] = [];
  function walk(v: unknown) {
    if (typeof v === "string") {
      const matches = v.match(/\{\{[\s\S]+?\}\}/g);
      if (matches) results.push(...matches);
    } else if (Array.isArray(v)) {
      v.forEach(walk);
    } else if (v !== null && typeof v === "object") {
      Object.values(v as Record<string, unknown>).forEach(walk);
    }
  }
  walk(obj);
  return results;
}

// ─── PII Detection ────────────────────────────────────────────────────────────

const PII_FIELD_RE = /email|phone|mobile|address|postcode|zip|ssn|passport|dob|birth|surname|lastname|firstname|name|gender|nationality|credit|card|iban|bsb|account/i;

function inferPiiFields(fields: string[]): string[] {
  return fields.filter((f) => PII_FIELD_RE.test(f));
}

// ─── Schema Inference from Set Nodes ─────────────────────────────────────────

function inferSchemaFromSetNode(node: N8nNode): string[] | null {
  if (node.type !== "n8n-nodes-base.set") return null;
  const values = node.parameters.values as Record<string, unknown> | undefined;
  if (!values) return null;
  const fields: string[] = [];
  for (const group of Object.values(values)) {
    if (!Array.isArray(group)) continue;
    for (const entry of group) {
      const name = (entry as Record<string, unknown>).name;
      if (typeof name === "string" && name) fields.push(name);
    }
  }
  return fields.length > 0 ? fields : null;
}

// ─── Main Builder ─────────────────────────────────────────────────────────────

export function buildPropertyGraph(workflow: N8nWorkflow): PropertyGraph {
  const wf = workflow as unknown as Record<string, unknown>;
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  // Build adjacency list for metadata computation
  const adj = new Map<string, string[]>();

  // Pass 1: build GraphNode entries
  for (const n of workflow.nodes) {
    if (n.type === "n8n-nodes-base.stickyNote") continue;

    const category = classifyNode(n.type, n.parameters);
    const isTrigger =
      category === NodeCategory.TRIGGER_WEBHOOK ||
      category === NodeCategory.TRIGGER_SCHEDULE ||
      category === NodeCategory.TRIGGER_MANUAL ||
      category === NodeCategory.TRIGGER_EVENT ||
      category === NodeCategory.ERROR_TRIGGER;

    const credentials: CredentialReference[] = Object.entries(n.credentials ?? {}).map(
      ([credType, ref]) => ({
        credentialId: ref.id,
        credentialType: credType,
        nodeName: n.name,
      })
    );

    const taintSources: TaintLabel[] = [];
    if (category === NodeCategory.TRIGGER_WEBHOOK) {
      taintSources.push({ source: "webhook_body", pii: false });
    }

    nodes.set(n.name, {
      id: n.id,
      name: n.name,
      type: n.type,
      category,
      isTrigger,
      isTerminal: false, // set in pass 3
      parameters: n.parameters,
      credentials,
      expressions: extractAllExpressions(n.parameters),
      taintSources,
      position: n.position,
    });

    adj.set(n.name, []);
  }

  // Pass 2: build GraphEdge entries + adjacency list
  // Also infer schemas from Set nodes and propagate to outgoing edges
  const nodeSchemas = new Map<string, string[] | null>(); // nodeName → field list
  for (const n of workflow.nodes) {
    nodeSchemas.set(n.name, inferSchemaFromSetNode(n));
  }

  let edgeCounter = 0;
  for (const [sourceName, outputs] of Object.entries(workflow.connections)) {
    const outGroups = outputs.main ?? [];
    outGroups.forEach((group, portIndex) => {
      for (const conn of group) {
        const targetName = conn.node;
        const edge: GraphEdge = {
          id: `e${edgeCounter++}`,
          sourceName,
          targetName,
          sourceBranch: portIndex,
          branchType: portIndex === 0 ? "main" : portIndex === 1 ? "false" : "error",
        };

        // Propagate schema from source Set node
        const schema = nodeSchemas.get(sourceName);
        if (schema) {
          edge.dataSchema = {
            fields: schema,
            piiFields: inferPiiFields(schema),
          };
        }

        edges.push(edge);
        adj.get(sourceName)?.push(targetName);
        if (!adj.has(targetName)) adj.set(targetName, []);
      }
    });
  }

  // Pass 3: mark terminal nodes
  const hasOutgoing = new Set(edges.map((e) => e.sourceName));
  for (const [name, node] of nodes) {
    node.isTerminal = !hasOutgoing.has(name);
  }

  // Metadata
  const sccs = tarjanSCC(adj);
  const cycles = sccs.filter((scc) => scc.length > 1);
  const triggerNodes = [...nodes.values()].filter((n) => n.isTrigger).map((n) => n.name);
  const terminalNodes = [...nodes.values()].filter((n) => n.isTerminal).map((n) => n.name);

  // Orphaned: no incoming and no outgoing edges, excluding triggers
  const hasIncoming = new Set(edges.map((e) => e.targetName));
  const orphanedNodes = [...nodes.keys()].filter(
    (name) => !hasIncoming.has(name) && !hasOutgoing.has(name) && !nodes.get(name)!.isTrigger
  );

  const cc = computeCyclomaticComplexity(nodes.size, edges.length, triggerNodes.length || 1);
  const diameter = computeDiameter(adj);

  const metadata: GraphMetadata = {
    totalNodes: nodes.size,
    totalEdges: edges.length,
    hasCycles: cycles.length > 0,
    cyclomaticComplexity: cc,
    diameter,
    triggerNodes,
    terminalNodes,
    orphanedNodes,
    stronglyConnectedComponents: sccs,
  };

  return {
    workflowId: (wf.id as string | undefined) ?? null,
    workflowName: (wf.name as string | undefined) ?? null,
    nodes,
    edges,
    metadata,
  };
}
