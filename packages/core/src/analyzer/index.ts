import type { N8nWorkflow, AnalysisReport, Violation, Severity } from "@n8n-analyzer/types";
import type { Config } from "../config.js";
import { ALL_RULES } from "./rules/index.js";

const ANALYZER_VERSION = "1.0.0";
const RULESET_VERSION = "1.0.0";

const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

export async function analyzeWorkflow(
  workflow: N8nWorkflow,
  config: Config
): Promise<AnalysisReport> {
  const activeRules = ALL_RULES.filter(
    (r) => !config.disabledRules.has(r.definition.id)
  );
  const skippedRules = ALL_RULES.filter((r) =>
    config.disabledRules.has(r.definition.id)
  ).map((r) => r.definition.id);

  const thresholdIndex = SEVERITY_ORDER.indexOf(config.severityThreshold);

  const allViolations: Violation[] = [];
  const passedRules: string[] = [];

  for (const rule of activeRules) {
    const violations = rule.run({ workflow, config });
    if (violations.length === 0) {
      passedRules.push(rule.definition.id);
    } else {
      allViolations.push(...violations);
    }
  }

  const filteredViolations = allViolations.filter(
    (v) => SEVERITY_ORDER.indexOf(v.severity) >= thresholdIndex
  );

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of filteredViolations) {
    counts[v.severity]++;
  }

  const nodeTypesFound = [
    ...new Set(
      workflow.nodes.map((n) => n.type.split(".").pop() ?? n.type)
    ),
  ];

  return {
    workflowId: workflow.id ?? null,
    workflowName: workflow.name ?? null,
    analyzedAt: new Date().toISOString(),
    summary: {
      totalNodes: workflow.nodes.length,
      totalViolations: filteredViolations.length,
      ...counts,
      passed: passedRules.length,
    },
    violations: filteredViolations,
    passedRules,
    skippedRules,
    metadata: {
      analyzerVersion: ANALYZER_VERSION,
      rulesetVersion: RULESET_VERSION,
      nodeTypesFound,
    },
  };
}
