import type { Violation } from "@n8n-analyzer/types";
import type { RuleRunner } from "../types.js";
import { isTriggerNode, buildAdjacencyList } from "../utils.js";

// ─── HYG-001 ──────────────────────────────────────────────────────────────────

const hyg001: RuleRunner = {
  definition: {
    id: "HYG-001",
    severity: "low",
    category: "workflow_hygiene",
    title: "Active workflow has no trigger node",
    description:
      "The workflow is marked as active but contains no trigger node. Without a trigger, the workflow can never execute automatically.",
    remediation:
      "Add a trigger node (Webhook, Schedule, etc.) or deactivate the workflow if it is intended to be called only via Execute Workflow.",
  },
  run({ workflow }) {
    if (!workflow.active) return [];

    const hasTrigger = workflow.nodes.some(
      (n) => !n.disabled && isTriggerNode(n.type)
    );
    if (hasTrigger) return [];

    return [
      {
        ruleId: "HYG-001",
        severity: "low",
        category: "workflow_hygiene",
        title: "Active workflow has no trigger node",
        description:
          "The workflow is active but has no trigger node — it can never execute automatically.",
        remediation: hyg001.definition.remediation,
      },
    ];
  },
};

// ─── HYG-002 ──────────────────────────────────────────────────────────────────

const hyg002: RuleRunner = {
  definition: {
    id: "HYG-002",
    severity: "low",
    category: "workflow_hygiene",
    title: "Orphaned nodes detected",
    description:
      "One or more non-trigger nodes have no connections to the rest of the workflow. Orphaned nodes are dead code: they consume visual space, may confuse reviewers, and can hide stale or dangerous logic.",
    remediation:
      "Remove orphaned nodes or connect them to the main workflow. If they are disabled intentionally, consider deleting them to keep the workflow clean.",
  },
  run({ workflow }) {
    if (workflow.nodes.length === 0) return [];

    const graph = buildAdjacencyList(workflow.connections);

    // Collect all node names that appear in at least one connection (as source or target)
    const connectedNames = new Set<string>();
    for (const [source, targets] of graph.entries()) {
      if (targets.size > 0) {
        connectedNames.add(source);
        for (const t of targets) connectedNames.add(t);
      }
    }

    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;
      // Trigger nodes with no connections are normal
      if (isTriggerNode(node.type)) continue;
      // A node with connections (as source or target) is not orphaned
      if (connectedNames.has(node.name)) continue;

      violations.push({
        ruleId: "HYG-002",
        severity: "low",
        category: "workflow_hygiene",
        title: `Orphaned node: "${node.name}"`,
        description: `Node "${node.name}" (${node.type}) has no connections and is not reachable from any trigger.`,
        node: { id: node.id, name: node.name, type: node.type, position: node.position },
        remediation: hyg002.definition.remediation,
      });
    }

    return violations;
  },
};

// ─── HYG-003 ──────────────────────────────────────────────────────────────────

const DEFAULT_NAMES = new Set([
  "my workflow",
  "untitled",
  "untitled workflow",
  "new workflow",
  "",
]);

const hyg003: RuleRunner = {
  definition: {
    id: "HYG-003",
    severity: "low",
    category: "workflow_hygiene",
    title: "Workflow has a default or empty name",
    description:
      "The workflow name is a default placeholder (e.g. 'My workflow', 'Untitled'). Meaningful names are essential for auditability and incident response.",
    remediation:
      "Give the workflow a descriptive name that reflects its purpose, the team that owns it, and the data it processes.",
  },
  run({ workflow }) {
    const name = (workflow.name ?? "").trim().toLowerCase();
    if (!DEFAULT_NAMES.has(name)) return [];

    return [
      {
        ruleId: "HYG-003",
        severity: "low",
        category: "workflow_hygiene",
        title: `Workflow has default name: "${workflow.name ?? "(empty)"}"`,
        description: `The workflow is named "${workflow.name ?? "(empty)"}" which is a default placeholder name. Rename it to something descriptive.`,
        evidence: workflow.name ?? "",
        remediation: hyg003.definition.remediation,
      },
    ];
  },
};

export const hygieneRules: RuleRunner[] = [hyg001, hyg002, hyg003];
