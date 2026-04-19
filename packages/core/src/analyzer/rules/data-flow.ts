import type { Violation } from "@n8n-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  walkNodeParams,
  NodeType,
  DB_NODE_TYPES,
  CHAT_NODE_TYPES,
  CLOUD_WRITE_NODE_TYPES,
  buildAdjacencyList,
  hasSanitizationBetween,
  bfsFrom,
} from "../utils.js";

// ─── DF-001 ───────────────────────────────────────────────────────────────────

// Matches an expression that echoes the entire $json object with no field selection:
//   ={{ $json }}  or  ={{ $json | json }}  or  ={{ JSON.stringify($json) }}
// Does NOT match  ={{ $json.email }}  (that's a specific field — intentional)
const FULL_JSON_ECHO_REGEX =
  /=\{\{\s*(?:\$json|JSON\.stringify\s*\(\s*\$json\s*\)|Object\.keys\s*\(\s*\$json\s*\))\s*\}\}/i;

const df001: RuleRunner = {
  definition: {
    id: "DF-001",
    severity: "high",
    category: "data_flow",
    title: "Webhook response echoes the entire inbound payload",
    description:
      "A Respond to Webhook node returns the full $json object as its response body. This reflects every field — including any sensitive data the workflow processed — back to the caller. If the workflow handles PII or secrets, the caller receives them in the response.",
    remediation:
      "Build an explicit response object using only the fields the caller needs: { \"status\": \"ok\", \"id\": \"{{ $json.id }}\" }. Never echo $json directly in a webhook response.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.RESPOND_TO_WEBHOOK) continue;

      for (const { path, value } of walkNodeParams(node)) {
        if (FULL_JSON_ECHO_REGEX.test(value)) {
          violations.push({
            ruleId: "DF-001",
            severity: "high",
            category: "data_flow",
            title: `Webhook response node "${node.name}" echoes full payload`,
            description: `Node "${node.name}" uses \`$json\` as the response body, reflecting the entire processed payload back to the webhook caller.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: value.slice(0, 120),
            remediation: df001.definition.remediation,
          });
          break; // one per node
        }
      }
    }

    return violations;
  },
};

// ─── DF-002 ───────────────────────────────────────────────────────────────────

const df002: RuleRunner = {
  definition: {
    id: "DF-002",
    severity: "high",
    category: "data_flow",
    title: "Database data flows to a cloud write destination without field filtering",
    description:
      "A database node (Postgres, MySQL, MongoDB, Redis) is connected to a cloud write destination (Google Sheets, Airtable, email) without a Set node between them to filter which fields are forwarded. This can result in entire database rows — including PII, internal IDs, and sensitive fields — being copied to a third-party SaaS service.",
    remediation:
      "Add a Set node between the database node and the cloud destination. Explicitly select only the fields that should be written. Apply data minimisation: forward the minimum necessary fields.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    const dbNodes = workflow.nodes.filter(
      (n) => !n.disabled && DB_NODE_TYPES.has(n.type)
    );
    const cloudWriteNodes = workflow.nodes.filter(
      (n) => !n.disabled && CLOUD_WRITE_NODE_TYPES.has(n.type)
    );

    if (dbNodes.length === 0 || cloudWriteNodes.length === 0) return [];

    const graph = buildAdjacencyList(workflow.connections);

    // Set nodes are the field-filtering "sanitisation" nodes for this rule
    const setNodeNames = new Set<string>();
    for (const n of workflow.nodes) {
      if (!n.disabled && n.type === NodeType.SET) setNodeNames.add(n.name);
    }

    for (const dbNode of dbNodes) {
      for (const cloudNode of cloudWriteNodes) {
        // hasSanitizationBetween returns true when ALL paths have a Set node.
        // We fire when it returns false: at least one path has no Set filter.
        if (!hasSanitizationBetween(graph, dbNode.name, cloudNode.name, setNodeNames)) {
          violations.push({
            ruleId: "DF-002",
            severity: "high",
            category: "data_flow",
            title: `Unfiltered DB data from "${dbNode.name}" flows to "${cloudNode.name}"`,
            description: `Database node "${dbNode.name}" is connected to cloud write node "${cloudNode.name}" (${cloudNode.type}) without a Set node between them. Full database rows may be forwarded to a third-party service.`,
            node: {
              id: cloudNode.id,
              name: cloudNode.name,
              type: cloudNode.type,
              position: cloudNode.position,
            },
            remediation: df002.definition.remediation,
          });
        }
      }
    }

    return violations;
  },
};

// ─── DF-003 ───────────────────────────────────────────────────────────────────

const CHAT_NODE_NAMES: Record<string, string> = {
  [NodeType.SLACK]: "Slack",
  [NodeType.TELEGRAM]: "Telegram",
  [NodeType.DISCORD]: "Discord",
  [NodeType.MICROSOFT_TEAMS]: "Microsoft Teams",
};

const df003: RuleRunner = {
  definition: {
    id: "DF-003",
    severity: "medium",
    category: "data_flow",
    title: "Database or webhook data flows into a chat message",
    description:
      "A chat node (Slack, Telegram, Discord, Teams) is downstream of a database read or webhook trigger. This is a common accidental data exfiltration pattern: 'notify me' workflows that end up piping full DB records or webhook payloads into a chat message, potentially leaking PII or internal data to chat platforms that may not be authorised to store it.",
    remediation:
      "Add a Set node before the chat node to select only the fields that should appear in the notification. Avoid forwarding raw $json objects into message text. Review whether the chat platform's data retention policies are compatible with the data being sent.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    const sourceCandidates = workflow.nodes.filter(
      (n) => !n.disabled && (DB_NODE_TYPES.has(n.type) || n.type === NodeType.WEBHOOK)
    );
    const chatNodes = workflow.nodes.filter(
      (n) => !n.disabled && CHAT_NODE_TYPES.has(n.type)
    );

    if (sourceCandidates.length === 0 || chatNodes.length === 0) return [];

    const graph = buildAdjacencyList(workflow.connections);

    // Build a quick lookup of chat node names for reachability check
    const chatNodeNames = new Set(chatNodes.map((n) => n.name));
    // Map chat node name → node object for violation building
    const chatNodeByName = new Map(chatNodes.map((n) => [n.name, n]));

    for (const sourceNode of sourceCandidates) {
      // BFS from source node; if we reach a chat node, fire
      bfsFrom(graph, sourceNode.name, (nodeName) => {
        if (!chatNodeNames.has(nodeName)) return; // keep traversing
        const chatNode = chatNodeByName.get(nodeName)!;

        // Avoid duplicate violations for the same source→chat pair
        const alreadyReported = violations.some(
          (v) =>
            v.ruleId === "DF-003" &&
            v.node?.name === chatNode.name &&
            v.description.includes(sourceNode.name)
        );
        if (alreadyReported) return;

        const chatLabel = CHAT_NODE_NAMES[chatNode.type] ?? chatNode.type;
        violations.push({
          ruleId: "DF-003",
          severity: "medium",
          category: "data_flow",
          title: `Data from "${sourceNode.name}" flows into ${chatLabel} message`,
          description: `${chatLabel} node "${chatNode.name}" is downstream of "${sourceNode.name}" (${sourceNode.type}). Data from databases or webhooks forwarded to chat platforms may expose PII or internal fields to an unauthorised audience.`,
          node: {
            id: chatNode.id,
            name: chatNode.name,
            type: chatNode.type,
            position: chatNode.position,
          },
          remediation: df003.definition.remediation,
        });
      });
    }

    return violations;
  },
};

export const dataFlowRules: RuleRunner[] = [df001, df002, df003];
