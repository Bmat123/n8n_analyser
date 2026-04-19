import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  walkNodeParams,
  NodeType,
  CODE_NODE_TYPES,
  SANITIZATION_NODE_TYPES,
  buildAdjacencyList,
  hasSanitizationBetween,
} from "../utils.js";

// ─── EXP-001 ──────────────────────────────────────────────────────────────────

// Expressions that reference raw webhook input
const WEBHOOK_INPUT_REGEX =
  /\$json\.(?:body|query|headers|params)\b|\$input\.(?:body|query)/;

const exp001: RuleRunner = {
  definition: {
    id: "EXP-001",
    severity: "high",
    category: "expression_injection",
    title: "Unsanitised webhook input flows directly into a Code or Execute Command node",
    description:
      "Raw webhook body/query data ($json.body.*) is passed directly to a Code or Execute Command node without any intermediate sanitisation node (IF, Switch, Set, or Filter). Untrusted input reaching executable code is a critical injection vector.",
    remediation:
      "Add an IF or Set node between the webhook and the code/command node that validates and sanitises the input. Never pass raw $json.body values directly into eval-like contexts.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    const webhookNodes = workflow.nodes.filter(
      (n) => !n.disabled && n.type === NodeType.WEBHOOK
    );
    if (webhookNodes.length === 0) return [];

    const dangerousNodes = workflow.nodes.filter(
      (n) =>
        !n.disabled &&
        (CODE_NODE_TYPES.has(n.type) || n.type === NodeType.EXECUTE_COMMAND)
    );
    if (dangerousNodes.length === 0) return [];

    const graph = buildAdjacencyList(workflow.connections);

    // Build sanitisation node name set
    const sanitizationNames = new Set<string>();
    for (const n of workflow.nodes) {
      if (SANITIZATION_NODE_TYPES.has(n.type)) {
        sanitizationNames.add(n.name);
      }
    }

    for (const webhookNode of webhookNodes) {
      for (const dangerousNode of dangerousNodes) {
        // Check if the dangerous node's code actually references webhook input
        let referencesWebhookInput = false;
        for (const { value } of walkNodeParams(dangerousNode)) {
          if (WEBHOOK_INPUT_REGEX.test(value)) {
            referencesWebhookInput = true;
            break;
          }
        }
        if (!referencesWebhookInput) continue;

        // Check if there is a sanitisation node on every path between them
        const sanitized = hasSanitizationBetween(
          graph,
          webhookNode.name,
          dangerousNode.name,
          sanitizationNames
        );

        if (!sanitized) {
          violations.push({
            ruleId: "EXP-001",
            severity: "high",
            category: "expression_injection",
            title: `Unsanitised webhook input reaches "${dangerousNode.name}"`,
            description: `Webhook "${webhookNode.name}" feeds raw input (via $json.body or similar) into node "${dangerousNode.name}" (${dangerousNode.type}) without any sanitisation node in between.`,
            node: {
              id: dangerousNode.id,
              name: dangerousNode.name,
              type: dangerousNode.type,
              position: dangerousNode.position,
            },
            remediation: exp001.definition.remediation,
          });
        }
      }
    }

    return violations;
  },
};

// ─── EXP-002 ──────────────────────────────────────────────────────────────────

// SQL keywords combined with an n8n expression interpolation
const SQL_KEYWORD_REGEX =
  /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b/i;
const JSON_EXPR_IN_SQL_REGEX = /\$json\.[a-zA-Z_][a-zA-Z0-9_.[\]"]*/;

const DB_NODE_TYPES_WITH_QUERIES = new Set<string>([
  NodeType.POSTGRES,
  NodeType.MYSQL,
]);

const exp002: RuleRunner = {
  definition: {
    id: "EXP-002",
    severity: "medium",
    category: "expression_injection",
    title: "n8n expression interpolated directly into SQL query — SQL injection risk",
    description:
      "A database node's query string appears to interpolate an n8n expression ($json.*) directly into SQL. If the referenced field originates from external input, this is a SQL injection vulnerability.",
    remediation:
      "Use parameterised queries / prepared statements instead of string interpolation. In n8n's Postgres/MySQL nodes, use the 'Query Parameters' field to pass values safely.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      // Check DB nodes with query fields
      if (DB_NODE_TYPES_WITH_QUERIES.has(node.type)) {
        for (const { path, value } of walkNodeParams(node)) {
          if (SQL_KEYWORD_REGEX.test(value) && JSON_EXPR_IN_SQL_REGEX.test(value)) {
            const match = JSON_EXPR_IN_SQL_REGEX.exec(value)!;
            violations.push({
              ruleId: "EXP-002",
              severity: "medium",
              category: "expression_injection",
              title: `SQL query in "${node.name}" interpolates expression: ${match[0]}`,
              description: `Node "${node.name}" builds a SQL query string using direct expression interpolation. If "${match[0]}" originates from external input, SQL injection is possible.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: value.slice(0, 120),
              remediation: exp002.definition.remediation,
            });
          }
        }
      }

      // Also check Code nodes that construct SQL
      if (CODE_NODE_TYPES.has(node.type)) {
        for (const { path, value } of walkNodeParams(node)) {
          if (SQL_KEYWORD_REGEX.test(value) && JSON_EXPR_IN_SQL_REGEX.test(value)) {
            const match = JSON_EXPR_IN_SQL_REGEX.exec(value)!;
            violations.push({
              ruleId: "EXP-002",
              severity: "medium",
              category: "expression_injection",
              title: `Code node "${node.name}" constructs SQL with expression interpolation`,
              description: `Code in node "${node.name}" builds a SQL string interpolating "${match[0]}". Use parameterised queries to prevent injection.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: value.slice(0, 120),
              remediation: exp002.definition.remediation,
            });
          }
        }
      }
    }

    return violations;
  },
};

// ─── EXP-003 ──────────────────────────────────────────────────────────────────

// Matches $env.VARIABLE_NAME anywhere in a parameter string
const ENV_ACCESS_REGEX = /\$env\.[A-Za-z_][A-Za-z0-9_]*/g;

const exp003: RuleRunner = {
  definition: {
    id: "EXP-003",
    severity: "critical",
    category: "expression_injection",
    title: "Workflow reads host environment variable via $env.*",
    description:
      "An n8n expression uses $env.<VARIABLE> to read a host environment variable. If that variable contains a secret (API key, DB password, etc.) and the node output is sent to an HTTP endpoint, chat, email, or logged, the secret is exfiltrated.",
    remediation:
      "Never reference $env.* in workflow expressions. Store secrets in n8n's credential vault and reference them via $credentials.*. If the env var is non-sensitive, document why.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      const seen = new Set<string>();
      for (const { path, value } of walkNodeParams(node)) {
        ENV_ACCESS_REGEX.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = ENV_ACCESS_REGEX.exec(value)) !== null) {
          const envRef = match[0];
          if (seen.has(envRef)) continue;
          seen.add(envRef);

          violations.push({
            ruleId: "EXP-003",
            severity: "critical",
            category: "expression_injection",
            title: `Environment variable exposed via expression: ${envRef}`,
            description: `Node "${node.name}" reads the host environment variable "${envRef}" in an expression. If this value reaches an HTTP response, log, or external service, it constitutes secret exfiltration.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: envRef,
            remediation: exp003.definition.remediation,
          });
        }
      }
    }

    return violations;
  },
};

// ─── EXP-004 ──────────────────────────────────────────────────────────────────

interface SandboxEscapePattern {
  regex: RegExp;
  label: string;
}

const SANDBOX_ESCAPE_PATTERNS: SandboxEscapePattern[] = [
  {
    regex: /__proto__/,
    label: "__proto__ access (prototype pollution)",
  },
  {
    // constructor["constructor"] or constructor.constructor
    regex: /constructor\s*(?:\[\s*['"]constructor['"]\s*\]|\.constructor)/,
    label: "constructor.constructor (Function constructor escape)",
  },
  {
    // process.env inside an expression template — not in a code node (SC-003 covers that)
    regex: /\{\{[^}]*process\.env[^}]*\}\}/,
    label: "process.env inside expression template",
  },
];

const exp004: RuleRunner = {
  definition: {
    id: "EXP-004",
    severity: "high",
    category: "expression_injection",
    title: "Potential sandbox escape in n8n expression",
    description:
      "A node parameter contains an expression pattern associated with JavaScript sandbox escapes or prototype pollution (__proto__, constructor.constructor, or process.env in a template). In older or misconfigured n8n versions these can execute arbitrary code.",
    remediation:
      "Remove the expression and replace it with a safe alternative. If the pattern is intentional and your n8n version is confirmed patched, add a suppression comment and document the rationale.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      for (const { path, value } of walkNodeParams(node)) {
        for (const { regex, label } of SANDBOX_ESCAPE_PATTERNS) {
          if (regex.test(value)) {
            violations.push({
              ruleId: "EXP-004",
              severity: "high",
              category: "expression_injection",
              title: `Sandbox escape pattern in "${node.name}": ${label}`,
              description: `Node "${node.name}" contains the pattern "${label}" in field ${path}. This is a known JavaScript sandbox escape technique.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: value.slice(0, 120),
              remediation: exp004.definition.remediation,
            });
            break; // one violation per field per node; first pattern wins
          }
        }
      }
    }

    return violations;
  },
};

export const expressionInjectionRules: RuleRunner[] = [exp001, exp002, exp003, exp004];
