import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import { NodeType, isTriggerNode, extractExpressions } from "../utils.js";

// ─── DQ-005 — Monolithic workflow ─────────────────────────────────────────────

const dq005: RuleRunner = {
  definition: {
    id: "DQ-005",
    severity: "medium",
    category: "maintainability",
    title: "Workflow has too many nodes with no sub-workflow decomposition",
    description:
      "Large monolithic workflows are hard to debug, test, and maintain. They lack clear boundaries of responsibility and make it difficult to identify which part failed.",
    remediation:
      "Decompose into sub-workflows by logical responsibility: Fetch Data, Transform & Validate, Write to Destinations, Notify. Each sub-workflow should have a single clear purpose.",
  },
  run({ workflow, config }) {
    // Exclude trigger nodes and sticky notes from the count
    const countableNodes = workflow.nodes.filter(
      (n) => !isTriggerNode(n.type) && n.type !== NodeType.STICKY_NOTE
    );
    const count = countableNodes.length;
    if (count <= config.maxNodesDecompWarning) return [];

    const hasSubWorkflow = workflow.nodes.some(
      (n) => !n.disabled && n.type === NodeType.EXECUTE_WORKFLOW
    );

    // Hard limit — escalate to high regardless of sub-workflow usage
    if (count > config.maxNodesHardLimit) {
      return [
        {
          ruleId: "DQ-005",
          severity: "high",
          category: "maintainability",
          title: `Workflow is very large: ${count} nodes`,
          description: `This workflow has ${count} non-trigger nodes, exceeding the hard limit of ${config.maxNodesHardLimit}. At this size, debugging and maintenance become extremely difficult.`,
          evidence: `${count} nodes (limit: ${config.maxNodesHardLimit})`,
          remediation: dq005.definition.remediation,
        },
      ];
    }

    // Medium threshold — only fire if no sub-workflows present
    if (!hasSubWorkflow) {
      return [
        {
          ruleId: "DQ-005",
          severity: "medium",
          category: "maintainability",
          title: `Workflow has ${count} nodes with no sub-workflow decomposition`,
          description: `This workflow has ${count} non-trigger nodes (threshold: ${config.maxNodesDecompWarning}) and no Execute Workflow nodes. Consider splitting it into focused sub-workflows.`,
          evidence: `${count} nodes (threshold: ${config.maxNodesDecompWarning})`,
          remediation: dq005.definition.remediation,
        },
      ];
    }

    return [];
  },
};

// ─── DQ-006 — Default node names ─────────────────────────────────────────────

const DEFAULT_NAME_PATTERNS = [
  /^HTTP Request\d*$/,
  /^Set\d*$/,
  /^IF\d*$/,
  /^If\d*$/,
  /^Code\d*$/,
  /^Switch\d*$/,
  /^Merge\d*$/,
  /^Function\d*$/,
  /^Function Item\d*$/,
  /^Execute Workflow\d*$/,
  /^Edit Fields\d*$/,
];

const dq006: RuleRunner = {
  definition: {
    id: "DQ-006",
    severity: "medium",
    category: "maintainability",
    title: "Multiple nodes using default auto-generated names",
    description:
      "Node names are the primary navigation aid when debugging a workflow. Default names like 'HTTP Request1' or 'Set3' provide no information about what the node does.",
    remediation:
      "Rename every node to describe what it does in business terms: 'Fetch Open Invoices', 'Filter Overdue > 30 Days', 'Send Reminder Email'. This makes the canvas self-documenting.",
  },
  run({ workflow }) {
    const defaultNamedNodes = workflow.nodes.filter((n) =>
      DEFAULT_NAME_PATTERNS.some((re) => re.test(n.name))
    );
    if (defaultNamedNodes.length <= 3) return [];

    return [
      {
        ruleId: "DQ-006",
        severity: "medium",
        category: "maintainability",
        title: `${defaultNamedNodes.length} nodes have default auto-generated names`,
        description: `${defaultNamedNodes.length} nodes still use default names (e.g. "${defaultNamedNodes[0].name}"). These names provide no information about what each node does.`,
        evidence: defaultNamedNodes.map((n) => n.name).join(", "),
        remediation: dq006.definition.remediation,
      },
    ];
  },
};

// ─── DQ-007 — No sticky notes ─────────────────────────────────────────────────

const dq007: RuleRunner = {
  definition: {
    id: "DQ-007",
    severity: "low",
    category: "maintainability",
    title: "Workflow has no documentation sticky notes",
    description:
      "Without sticky notes, the workflow's purpose, trigger conditions, and dependencies are invisible to anyone reading the canvas for the first time.",
    remediation:
      "Add at least one sticky note explaining the business purpose, trigger conditions, expected inputs/outputs, and any external API contracts or dependencies.",
  },
  run({ workflow }) {
    const nonTrivialNodes = workflow.nodes.filter(
      (n) => n.type !== NodeType.STICKY_NOTE
    );
    if (nonTrivialNodes.length <= 5) return [];

    const hasStickyNote = workflow.nodes.some(
      (n) => n.type === NodeType.STICKY_NOTE
    );
    if (hasStickyNote) return [];

    return [
      {
        ruleId: "DQ-007",
        severity: "low",
        category: "maintainability",
        title: "No sticky notes in a workflow with multiple nodes",
        description: `This workflow has ${nonTrivialNodes.length} nodes but no sticky note documentation. Anyone reading this workflow must reverse-engineer its purpose from the node structure alone.`,
        evidence: `${nonTrivialNodes.length} nodes, 0 sticky notes`,
        remediation: dq007.definition.remediation,
      },
    ];
  },
};

// ─── DQ-011 — No workflow description ────────────────────────────────────────

const dq011: RuleRunner = {
  definition: {
    id: "DQ-011",
    severity: "low",
    category: "maintainability",
    title: "Workflow has no description",
    description:
      "A missing description makes it impossible to understand a workflow's purpose without reading every node. In large n8n instances with many workflows, undescribed workflows become unmaintainable.",
    remediation:
      "Add a workflow description covering: what it does, who owns it, what triggers it, what systems it touches, and when it was last reviewed.",
  },
  run({ workflow }) {
    const meta = (workflow as unknown as Record<string, unknown>).meta as Record<string, unknown> | undefined;
    const description = meta?.description;
    if (description && typeof description === "string" && description.trim() !== "") return [];

    return [
      {
        ruleId: "DQ-011",
        severity: "low",
        category: "maintainability",
        title: "Workflow has no description set",
        description: `Workflow "${workflow.name ?? "(unnamed)"}" has no description. Add one in workflow Settings → Description.`,
        remediation: dq011.definition.remediation,
      },
    ];
  },
};

// ─── OP-004 — Workflow name suggests copy/draft ───────────────────────────────

const COPY_DRAFT_PATTERN = /\b(v\d+|final|copy|\(copy\)|new|test|temp|old|backup|use this|\- \d+)\b/i;

const op004: RuleRunner = {
  definition: {
    id: "OP-004",
    severity: "low",
    category: "maintainability",
    title: "Workflow name suggests it is a copy, draft, or version",
    description:
      "Names containing 'copy', 'v2', 'final', 'test', 'temp', etc. suggest the workflow is not the canonical production version. Running multiple near-identical versions creates confusion about which is authoritative.",
    remediation:
      "Give the workflow a canonical name describing its function. Use n8n's built-in version history for change tracking. Archive or delete deprecated versions.",
  },
  run({ workflow }) {
    const name = workflow.name ?? "";
    if (!COPY_DRAFT_PATTERN.test(name)) return [];

    return [
      {
        ruleId: "OP-004",
        severity: "low",
        category: "maintainability",
        title: `Workflow name suggests copy or draft: "${name}"`,
        description: `The workflow name "${name}" contains a pattern suggesting it is not the canonical production version. This makes it unclear which version is authoritative.`,
        evidence: name,
        remediation: op004.definition.remediation,
      },
    ];
  },
};

// ─── MAINT-001 — Credential sprawl ───────────────────────────────────────────

const maint001: RuleRunner = {
  definition: {
    id: "MAINT-001",
    severity: "medium",
    category: "maintainability",
    title: "Multiple distinct credentials used for the same external service",
    description:
      "Multiple credentials for the same service type typically means different team members created their own personal credentials. When a key needs rotation, every credential must be updated individually.",
    remediation:
      "Consolidate to a single shared service account credential per external system. Update all nodes to use the shared credential.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    // Map: credentialType → Set of credential IDs used
    const credMap = new Map<string, Set<string>>();

    for (const node of workflow.nodes) {
      if (node.disabled || !node.credentials) continue;
      for (const [credType, credRef] of Object.entries(node.credentials)) {
        const credId = typeof credRef === "object" && credRef !== null
          ? (credRef as Record<string, unknown>).id as string
          : String(credRef);
        if (!credId) continue;
        if (!credMap.has(credType)) credMap.set(credType, new Set());
        credMap.get(credType)!.add(credId);
      }
    }

    for (const [credType, ids] of credMap) {
      if (ids.size > 1) {
        violations.push({
          ruleId: "MAINT-001",
          severity: "medium",
          category: "maintainability",
          title: `${ids.size} different credentials used for "${credType}"`,
          description: `The credential type "${credType}" is used with ${ids.size} distinct credential IDs across this workflow. When rotating keys, every credential must be updated separately.`,
          evidence: `${ids.size} distinct IDs for ${credType}`,
          remediation: maint001.definition.remediation,
        });
      }
    }
    return violations;
  },
};

// ─── MAINT-002 — Deep expression chains ──────────────────────────────────────

const EXPRESSION_DEPTH_LIMIT = 5;

function countPropertyDepth(expr: string): number {
  // Count dot-accessor depth within the expression content
  // Strip bracket accessors like [0] and ["key"] and count remaining dots
  const stripped = expr.replace(/\[["']?[^"'\]]+["']?\]/g, "");
  const dots = (stripped.match(/\./g) ?? []).length;
  return dots;
}

const maint002: RuleRunner = {
  definition: {
    id: "MAINT-002",
    severity: "low",
    category: "maintainability",
    title: "Expression contains deeply nested property access chain",
    description:
      "Deep property chains break silently when upstream API responses change structure. A chain 6 levels deep is fragile and difficult to read.",
    remediation:
      "Add a Set node immediately after the HTTP Request to extract and rename the fields you need into a flat structure, then reference the flat fields downstream.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      for (const { path, value } of (function* () {
        // Re-use walkStringParams logic inline to avoid circular import issues
        function* walk(obj: unknown, prefix: string): Generator<{ path: string; value: string }> {
          if (typeof obj === "string") { yield { path: prefix, value: obj }; return; }
          if (Array.isArray(obj)) { for (let i = 0; i < obj.length; i++) yield* walk(obj[i], `${prefix}[${i}]`); return; }
          if (obj !== null && typeof obj === "object") { for (const [k, v] of Object.entries(obj as Record<string, unknown>)) yield* walk(v, `${prefix}.${k}`); }
        }
        yield* walk(node.parameters, "parameters");
      })()) {
        const expressions = extractExpressions(value);
        for (const expr of expressions) {
          const depth = countPropertyDepth(expr);
          if (depth > EXPRESSION_DEPTH_LIMIT) {
            violations.push({
              ruleId: "MAINT-002",
              severity: "low",
              category: "maintainability",
              title: `Deep expression chain (depth ${depth}) in node "${node.name}"`,
              description: `Node "${node.name}" contains an expression with property access depth ${depth}: ${expr.slice(0, 100)}. Deep chains break silently when the upstream API schema changes.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: expr.slice(0, 120),
              remediation: maint002.definition.remediation,
            });
            break; // one violation per parameter field is enough
          }
        }
      }
    }
    return violations;
  },
};

export const maintainabilityRules: RuleRunner[] = [
  dq005, dq006, dq007, dq011, op004, maint001, maint002,
];
