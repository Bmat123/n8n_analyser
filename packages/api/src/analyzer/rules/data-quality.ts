import type { Violation } from "@n8n-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  NodeType,
  buildAdjacencyList,
  buildNodeMap,
  getDownstreamNodes,
  extractExpressions,
  getStringParam,
} from "../utils.js";

// ─── DQ-009 — No input validation on webhook ──────────────────────────────────

const VALIDATION_CODE_KEYWORDS = /throw|error|validate|schema|required|missing|invalid/i;

const dq009: RuleRunner = {
  definition: {
    id: "DQ-009",
    severity: "medium",
    category: "data_quality",
    title: "Webhook trigger has no schema validation node immediately downstream",
    description:
      "Webhook payloads from external systems are untrusted and may be malformed, incomplete, or contain unexpected types. Without validation, bad data flows silently through the workflow.",
    remediation:
      "Add an IF node immediately after the webhook to check that required fields are present and of the expected type. Return a 400 response via a Respond to Webhook node for invalid payloads.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    const graph = buildAdjacencyList(workflow.connections);
    const nodeMap = buildNodeMap(workflow);

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.WEBHOOK) continue;

      const downstream = getDownstreamNodes(node.name, graph, 2);
      const hasValidation = [...downstream].some((name) => {
        const n = nodeMap.get(name);
        if (!n || n.disabled) return false;
        if (n.type === NodeType.IF || n.type === NodeType.SWITCH || n.type === NodeType.FILTER) return true;
        if (n.type === NodeType.CODE || n.type === NodeType.FUNCTION) {
          const code =
            getStringParam(n.parameters, "jsCode") ??
            getStringParam(n.parameters, "functionCode") ??
            getStringParam(n.parameters, "code") ?? "";
          return VALIDATION_CODE_KEYWORDS.test(code);
        }
        return false;
      });

      if (!hasValidation) {
        violations.push({
          ruleId: "DQ-009",
          severity: "medium",
          category: "data_quality",
          title: `Webhook "${node.name}" has no downstream input validation`,
          description: `Webhook node "${node.name}" has no IF node, Filter, or validation Code node within 2 hops downstream. Malformed or incomplete payloads will flow unchecked into the workflow.`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          evidence: [...downstream].join(", ") || "(no downstream nodes)",
          remediation: dq009.definition.remediation,
          confidence: "probable",
        });
      }
    }
    return violations;
  },
};

// ─── DQ-010 — Date/time expression without timezone ───────────────────────────

const DATE_KEYWORDS = /new Date\s*\(\)|Date\.now\s*\(\)|\.toISOString\s*\(\)|moment\s*\(|luxon|\$now|\$today/;
const TIMEZONE_HINTS = /UTC|Europe\/|America\/|Asia\/|Africa\/|Pacific\/|\.setZone\s*\(|\.utc\s*\(\)|getTimezoneOffset|toUTC\s*\(|\.toUTC/i;

const dq010: RuleRunner = {
  definition: {
    id: "DQ-010",
    severity: "medium",
    category: "data_quality",
    title: "Date or time expression used without explicit timezone specification",
    description:
      "n8n instances run in server timezone which may differ from your users' timezone or the database's stored timezone. Timezone-naive date operations produce incorrect results across regions.",
    remediation:
      "Always specify timezones explicitly. Use DateTime.now().setZone('Europe/Berlin') with Luxon, or always store and compare in UTC with explicit conversion at display time.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      function* walkParams(obj: unknown, prefix: string): Generator<{ path: string; value: string }> {
        if (typeof obj === "string") { yield { path: prefix, value: obj }; return; }
        if (Array.isArray(obj)) { for (let i = 0; i < obj.length; i++) yield* walkParams(obj[i], `${prefix}[${i}]`); return; }
        if (obj !== null && typeof obj === "object") { for (const [k, v] of Object.entries(obj as Record<string, unknown>)) yield* walkParams(v, `${prefix}.${k}`); }
      }

      for (const { path, value } of walkParams(node.parameters, "parameters")) {
        const expressions = extractExpressions(value);
        for (const expr of expressions) {
          if (!DATE_KEYWORDS.test(expr)) continue;
          if (TIMEZONE_HINTS.test(expr)) continue;

          violations.push({
            ruleId: "DQ-010",
            severity: "medium",
            category: "data_quality",
            title: `Timezone-naive date expression in node "${node.name}"`,
            description: `Node "${node.name}" uses a date/time expression without an explicit timezone. The result depends on the server's system timezone, which may not match the intended timezone.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: expr.slice(0, 120),
            remediation: dq010.definition.remediation,
            confidence: "probable",
          });
          break; // one violation per parameter path
        }
      }
    }
    return violations;
  },
};

// ─── DQ-012 — Currency arithmetic without rounding ───────────────────────────

const ARITHMETIC_OPS = /[*/]|(?<![=!<>])[+\-](?![=])/;
const ROUNDING_GUARDS = /Math\.round|Math\.floor|Math\.ceil|\.toFixed|\.toPrecision/;

function buildCurrencyPattern(fieldNames: Set<string>): RegExp {
  const escaped = [...fieldNames].map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
  return new RegExp(`\\$json\\.(?:${escaped})|\\.(?:${escaped})\\b`, "i");
}

const dq012: RuleRunner = {
  definition: {
    id: "DQ-012",
    severity: "medium",
    category: "data_quality",
    title: "Floating point arithmetic on a currency value without rounding",
    description:
      "JavaScript floating point arithmetic on currency values produces results like 29.999999999997. This corrupts financial records, breaks equality comparisons, and causes rounding errors that accumulate at scale.",
    remediation:
      "Always round: Math.round(price * quantity * 100) / 100 or use .toFixed(2) for display values.",
  },
  run({ workflow, config }) {
    if (config.currencyFieldNames.size === 0) return [];

    const violations: Violation[] = [];
    const currencyPattern = buildCurrencyPattern(config.currencyFieldNames);

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      function* walkParams(obj: unknown, prefix: string): Generator<{ path: string; value: string }> {
        if (typeof obj === "string") { yield { path: prefix, value: obj }; return; }
        if (Array.isArray(obj)) { for (let i = 0; i < obj.length; i++) yield* walkParams(obj[i], `${prefix}[${i}]`); return; }
        if (obj !== null && typeof obj === "object") { for (const [k, v] of Object.entries(obj as Record<string, unknown>)) yield* walkParams(v, `${prefix}.${k}`); }
      }

      for (const { path, value } of walkParams(node.parameters, "parameters")) {
        const expressions = extractExpressions(value);
        for (const expr of expressions) {
          if (!currencyPattern.test(expr)) continue;
          if (!ARITHMETIC_OPS.test(expr)) continue;
          if (ROUNDING_GUARDS.test(expr)) continue;

          violations.push({
            ruleId: "DQ-012",
            severity: "medium",
            category: "data_quality",
            title: `Currency arithmetic without rounding in node "${node.name}"`,
            description: `Node "${node.name}" performs arithmetic on what appears to be a currency field without Math.round or .toFixed. Floating point errors will corrupt monetary values.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: expr.slice(0, 120),
            remediation: dq012.definition.remediation,
            confidence: "probable",
          });
          break; // one per field
        }
      }
    }
    return violations;
  },
};

// ─── DQ-013 — Hardcoded business logic values ────────────────────────────────

const BUSINESS_RULE_FIELDS = /discount|threshold|limit|rate|tier|level|minimum|maximum|min|max|quota|budget/i;
const NUMERIC_COMPARISON = /[><=!]=?\s*\d+(\.\d+)?|\d+(\.\d+)?\s*[><=!]=/;
const RAW_NUMERIC = /^\d+(\.\d+)?$/;

/** Check a condition entry object (value1/value2 pair) for hardcoded business thresholds */
function conditionEntryHasHardcodedThreshold(entry: Record<string, unknown>): string | null {
  const v1 = String(entry.value1 ?? entry.leftValue ?? "");
  const v2 = String(entry.value2 ?? entry.rightValue ?? "");
  // value1 references a business field AND value2 is a raw number
  if (BUSINESS_RULE_FIELDS.test(v1) && RAW_NUMERIC.test(v2.trim()) && v2.trim() !== "") {
    return `${v1.slice(0, 60)} vs ${v2}`;
  }
  // Either side has a numeric comparison expression with a business field
  for (const v of [v1, v2]) {
    if (!BUSINESS_RULE_FIELDS.test(v)) continue;
    const exprs = v.match(/\{\{[\s\S]+?\}\}/g) ?? [];
    for (const expr of exprs) {
      if (NUMERIC_COMPARISON.test(expr)) return expr.slice(0, 80);
    }
  }
  return null;
}

const dq013: RuleRunner = {
  definition: {
    id: "DQ-013",
    severity: "low",
    category: "data_quality",
    title: "Hardcoded business rule constants detected in node conditions",
    description:
      "Hardcoded business rules embedded in workflow conditions are invisible to non-technical stakeholders and require workflow edits to change. Tax rates, discount thresholds, and tier boundaries should live in a config source.",
    remediation:
      "Move constants to a Set node at the top of the workflow that defines all constants in one place, or fetch configuration from a Google Sheet or environment variable.",
  },
  run({ workflow, config }) {
    if (!config.includeAdvisory) return [];

    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      // IF/Filter nodes: scan condition entries as pairs
      if (node.type === NodeType.IF || node.type === NodeType.FILTER) {
        const conditions = node.parameters.conditions as Record<string, unknown> | undefined;
        if (!conditions) continue;
        for (const group of Object.values(conditions)) {
          if (!Array.isArray(group)) continue;
          for (const entry of group) {
            if (typeof entry !== "object" || entry === null) continue;
            const evidence = conditionEntryHasHardcodedThreshold(entry as Record<string, unknown>);
            if (!evidence) continue;
            violations.push({
              ruleId: "DQ-013",
              severity: "low",
              category: "data_quality",
              title: `Hardcoded business constant in node "${node.name}"`,
              description: `Node "${node.name}" compares against a hardcoded numeric threshold in a business-rule context. These values should be configurable.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              evidence,
              remediation: dq013.definition.remediation,
              confidence: "advisory",
            });
            break;
          }
        }
        continue;
      }

      // Code/Function nodes: scan expressions for numeric comparisons involving business fields
      if (node.type !== NodeType.CODE && node.type !== NodeType.FUNCTION) continue;
      const code =
        (node.parameters.jsCode as string | undefined) ??
        (node.parameters.functionCode as string | undefined) ??
        (node.parameters.code as string | undefined) ?? "";
      if (!BUSINESS_RULE_FIELDS.test(code)) continue;
      if (!NUMERIC_COMPARISON.test(code)) continue;

      violations.push({
        ruleId: "DQ-013",
        severity: "low",
        category: "data_quality",
        title: `Hardcoded business constant in Code node "${node.name}"`,
        description: `Code node "${node.name}" compares a business-rule-sounding field against a hardcoded numeric literal. These values should be configurable.`,
        node: { id: node.id, name: node.name, type: node.type, position: node.position },
        evidence: code.slice(0, 120),
        remediation: dq013.definition.remediation,
        confidence: "advisory",
      });
    }
    return violations;
  },
};

export const dataQualityRules: RuleRunner[] = [dq009, dq010, dq012, dq013];
