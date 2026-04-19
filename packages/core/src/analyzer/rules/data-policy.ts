import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  walkNodeParams,
  NodeType,
  DB_NODE_TYPES,
  CODE_NODE_TYPES,
  isExternalDataNode,
  getStringParam,
  extractHostname,
  isPrivateHost,
  isFullyDynamicExpression,
} from "../utils.js";

// ─── DP-001 ───────────────────────────────────────────────────────────────────

const dp001: RuleRunner = {
  definition: {
    id: "DP-001",
    severity: "high",
    category: "data_policy",
    title: "Webhook trigger has no authentication",
    description:
      "A Webhook trigger node has authentication set to 'none', creating an unauthenticated public endpoint. Anyone who knows the URL can trigger the workflow.",
    remediation:
      "Enable authentication on the Webhook node (Header Auth, Basic Auth, or JWT). Rotate the webhook URL after enabling authentication.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.WEBHOOK) continue;

      const auth = node.parameters.authentication;
      // n8n defaults to no auth when the field is absent
      if (auth === "none" || auth === undefined || auth === null || auth === "") {
        violations.push({
          ruleId: "DP-001",
          severity: "high",
          category: "data_policy",
          title: "Webhook trigger has no authentication",
          description: `Webhook node "${node.name}" accepts unauthenticated requests (authentication: ${JSON.stringify(auth ?? "none")}).`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          field: "parameters.authentication",
          evidence: String(auth ?? "none"),
          remediation: dp001.definition.remediation,
        });
      }
    }

    return violations;
  },
};

// ─── DP-002 ───────────────────────────────────────────────────────────────────

const PII_FIELD_NAMES = [
  "email", "firstName", "lastName", "phone", "ssn",
  "nationalId", "dateOfBirth", "iban", "creditCard", "passport",
  "first_name", "last_name", "date_of_birth", "credit_card",
  "national_id",
];

// Build a regex that matches any $json.<piiField> or $node["..."].json.<piiField>
const PII_EXPR_REGEX = new RegExp(
  `\\$(?:json|node\\[["'][^"']+["']\\]\\.json)\\.(?:${PII_FIELD_NAMES.join("|")})\\b`,
  "gi"
);

const dp002: RuleRunner = {
  definition: {
    id: "DP-002",
    severity: "high",
    category: "data_policy",
    title: "PII field detected in outbound HTTP request",
    description:
      "An HTTP Request node appears to send PII fields (email, phone, SSN, etc.) to an external endpoint. Ensure this transfer is authorised, encrypted, and compliant with applicable data protection regulations.",
    remediation:
      "Confirm the target endpoint is authorised to receive this PII. Ensure the connection uses HTTPS. Consider pseudonymising or minimising PII before transmission.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;

      // Only flag POST / PUT / PATCH requests — GET requests wouldn't normally carry a body
      const method = (
        getStringParam(node.parameters, "requestMethod") ??
        getStringParam(node.parameters, "method") ??
        "GET"
      ).toUpperCase();

      if (!["POST", "PUT", "PATCH"].includes(method)) continue;

      for (const { path, value } of walkNodeParams(node)) {
        PII_EXPR_REGEX.lastIndex = 0;
        const match = PII_EXPR_REGEX.exec(value);
        if (match) {
          violations.push({
            ruleId: "DP-002",
            severity: "high",
            category: "data_policy",
            title: `PII field "${match[0]}" sent to external HTTP endpoint`,
            description: `Node "${node.name}" references PII expression "${match[0]}" in its ${method} request body/headers.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: match[0],
            remediation: dp002.definition.remediation,
          });
        }
      }
    }

    return violations;
  },
};

// ─── DP-003 ───────────────────────────────────────────────────────────────────

const dp003: RuleRunner = {
  definition: {
    id: "DP-003",
    severity: "medium",
    category: "data_policy",
    title: "Database node uses a host not in the approved list",
    description:
      "A database node (Postgres, MySQL, MongoDB, Redis) connects to a host that is not in the APPROVED_DB_HOSTS list. This may indicate an unapproved or shadow data store.",
    remediation:
      "Add the hostname to the APPROVED_DB_HOSTS environment variable if it is an authorised data store. Otherwise, investigate why the workflow is connecting to this host.",
  },
  run({ workflow, config }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !DB_NODE_TYPES.has(node.type)) continue;

      // n8n stores DB host in parameters.host or via a named credential
      const host =
        getStringParam(node.parameters, "host") ??
        getStringParam(node.parameters, "server") ??
        null;

      // If no static host is present, skip (credential-referenced connections
      // can't be inspected statically)
      if (!host) continue;

      const normHost = host.toLowerCase().trim();

      // Normalise the approved set to lowercase at comparison time
      // (config.approvedDbHosts is pre-lowercased by parseCommaSeparatedSet,
      // but tests may inject raw Sets — normalise defensively here)
      const approved = config.approvedDbHosts;
      const approvedNorm = new Set([...approved].map((h) => h.toLowerCase()));
      if (approvedNorm.size > 0 && approvedNorm.has(normHost)) continue;

      violations.push({
        ruleId: "DP-003",
        severity: "medium",
        category: "data_policy",
        title: `Database node connects to unapproved host: "${host}"`,
        description: `Node "${node.name}" (${node.type}) connects to "${host}" which is not in the APPROVED_DB_HOSTS list.`,
        node: { id: node.id, name: node.name, type: node.type, position: node.position },
        field: "parameters.host",
        evidence: host,
        remediation: dp003.definition.remediation,
      });
    }

    return violations;
  },
};

// ─── DP-004 ───────────────────────────────────────────────────────────────────

const CONSOLE_LOG_REGEX = /console\.(log|error|warn|info|debug)\s*\(/;
const CODE_PARAM_KEYS = ["jsCode", "functionCode", "code"];

const dp004: RuleRunner = {
  definition: {
    id: "DP-004",
    severity: "medium",
    category: "data_policy",
    title: "console.log in Code node — potential data leakage into execution logs",
    description:
      "A Code/Function node contains console.log (or console.error/warn/info/debug) calls. These statements write to n8n execution logs which may be stored, exported, or accessed by operators, potentially exposing sensitive data.",
    remediation:
      "Remove console.log statements from production code. If debugging is needed, use a dedicated logging node or remove the statements before activation.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !CODE_NODE_TYPES.has(node.type)) continue;

      for (const paramKey of CODE_PARAM_KEYS) {
        const code = getStringParam(node.parameters, paramKey);
        if (!code) continue;

        const match = code.match(CONSOLE_LOG_REGEX);
        if (match) {
          violations.push({
            ruleId: "DP-004",
            severity: "medium",
            category: "data_policy",
            title: `console.${match[1]}() found in Code node`,
            description: `Node "${node.name}" contains a console.${match[1]}() call that may leak data into execution logs.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: `parameters.${paramKey}`,
            evidence: match[0],
            remediation: dp004.definition.remediation,
          });
          break; // one violation per node
        }
      }
    }

    return violations;
  },
};

// ─── DP-005 ───────────────────────────────────────────────────────────────────

const dp005: RuleRunner = {
  definition: {
    id: "DP-005",
    severity: "low",
    category: "data_policy",
    title: "No error handler node — failed executions may expose raw data in logs",
    description:
      "The workflow processes external data but has no Error Trigger node. Without an error handler, failed executions surface raw node inputs/outputs in n8n's execution log, potentially exposing PII or credentials.",
    remediation:
      "Add an Error Trigger workflow that handles failures gracefully: send alerts via a non-data-logging channel and avoid logging raw payloads.",
  },
  run({ workflow }) {
    const hasExternalData = workflow.nodes.some(
      (n) => !n.disabled && isExternalDataNode(n.type)
    );
    if (!hasExternalData) return [];

    const hasErrorHandler = workflow.nodes.some(
      (n) => !n.disabled && n.type === NodeType.ERROR_TRIGGER
    );
    if (hasErrorHandler) return [];

    return [
      {
        ruleId: "DP-005",
        severity: "low",
        category: "data_policy",
        title: "No error handler in workflow that processes external data",
        description:
          "This workflow processes external data (HTTP requests, webhooks, or database queries) but has no Error Trigger node. Unhandled failures may expose raw data in execution logs.",
        remediation: dp005.definition.remediation,
      },
    ];
  },
};

// ─── DP-006 ───────────────────────────────────────────────────────────────────

const dp006: RuleRunner = {
  definition: {
    id: "DP-006",
    severity: "medium",
    category: "data_policy",
    title: "HTTP Request contacts host not in the approved egress list",
    description:
      "An HTTP Request node sends data to a hostname that is not in the APPROVED_EGRESS_HOSTS allowlist. When the list is configured, every outbound HTTP destination must be explicitly approved to prevent unintended data exfiltration to third parties.",
    remediation:
      "Add the hostname to the APPROVED_EGRESS_HOSTS environment variable if the destination is authorised. If the endpoint is genuinely required, ensure it is covered by a data processing agreement. Leave APPROVED_EGRESS_HOSTS empty to disable this rule.",
  },
  run({ workflow, config }) {
    // Rule is opt-in — skip entirely if no allowlist is configured
    if (config.approvedEgressHosts.size === 0) return [];

    const violations: Violation[] = [];
    const approved = new Set([...config.approvedEgressHosts].map((h) => h.toLowerCase()));

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;

      // Track hosts already reported for this node to avoid duplicate violations
      const reportedHosts = new Set<string>();

      for (const { path, value } of walkNodeParams(node)) {
        // Skip purely dynamic expressions — NET-004 covers those
        if (isFullyDynamicExpression(value)) continue;

        const host = extractHostname(value);
        if (!host) continue;

        // Private/internal hosts are covered by NET-003
        if (isPrivateHost(host)) continue;

        if (!approved.has(host) && !reportedHosts.has(host)) {
          reportedHosts.add(host);
          violations.push({
            ruleId: "DP-006",
            severity: "medium",
            category: "data_policy",
            title: `HTTP Request contacts unapproved host: "${host}"`,
            description: `Node "${node.name}" sends data to "${host}" which is not in the APPROVED_EGRESS_HOSTS allowlist.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: host,
            remediation: dp006.definition.remediation,
          });
        }
      }
    }

    return violations;
  },
};

export const dataPolicyRules: RuleRunner[] = [dp001, dp002, dp003, dp004, dp005, dp006];
