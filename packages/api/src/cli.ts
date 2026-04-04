/**
 * Quick CLI runner — analyze a workflow JSON file directly without the HTTP server.
 *
 * Usage:
 *   npx tsx src/cli.ts path/to/workflow.json
 *   cat workflow.json | npx tsx src/cli.ts
 */

import { readFileSync } from "fs";
import { analyzeWorkflow } from "./analyzer/index.js";
import { config } from "./config.js";
import type { AnalysisReport, Violation } from "@n8n-analyzer/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "\x1b[31;1m", // bold red
  high: "\x1b[33;1m",     // bold yellow
  medium: "\x1b[33m",     // yellow
  low: "\x1b[36m",        // cyan
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";

function color(sev: string, text: string): string {
  return `${SEVERITY_COLORS[sev] ?? ""}${text}${RESET}`;
}

function badge(sev: string): string {
  const labels: Record<string, string> = {
    critical: "● CRITICAL",
    high:     "▲ HIGH    ",
    medium:   "◆ MEDIUM  ",
    low:      "○ LOW     ",
  };
  return color(sev, labels[sev] ?? sev.toUpperCase());
}

function printReport(report: AnalysisReport): void {
  const { summary, violations, passedRules, metadata } = report;

  console.log();
  console.log(`${BOLD}═══ n8n Workflow Security Report ═══${RESET}`);
  console.log(`${DIM}Workflow : ${report.workflowName ?? "(unnamed)"}${RESET}`);
  console.log(`${DIM}ID       : ${report.workflowId ?? "n/a"}${RESET}`);
  console.log(`${DIM}Analyzed : ${report.analyzedAt}${RESET}`);
  console.log(`${DIM}Nodes    : ${summary.totalNodes}  |  Node types: ${metadata.nodeTypesFound.join(", ")}${RESET}`);
  console.log();

  // Summary bar
  const parts = [];
  if (summary.critical > 0) parts.push(color("critical", `${summary.critical} critical`));
  if (summary.high > 0)     parts.push(color("high",     `${summary.high} high`));
  if (summary.medium > 0)   parts.push(color("medium",   `${summary.medium} medium`));
  if (summary.low > 0)      parts.push(color("low",      `${summary.low} low`));
  if (summary.passed > 0)   parts.push(`${GREEN}${summary.passed} passed${RESET}`);

  console.log(`${BOLD}Summary:${RESET} ${summary.totalViolations} violation(s) — ${parts.join(" · ")}`);
  console.log();

  if (violations.length === 0) {
    console.log(`${GREEN}✓ No violations found.${RESET}`);
  } else {
    // Group by category
    const byCategory = new Map<string, Violation[]>();
    for (const v of violations) {
      const list = byCategory.get(v.category) ?? [];
      list.push(v);
      byCategory.set(v.category, list);
    }

    for (const [category, items] of byCategory) {
      console.log(`${BOLD}─── ${category.toUpperCase().replace("_", " ")} ───${RESET}`);
      for (const v of items) {
        console.log();
        console.log(`  ${badge(v.severity)}  ${BOLD}[${v.ruleId}]${RESET} ${v.title}`);
        if (v.node) {
          console.log(`  ${DIM}Node: "${v.node.name}" (${v.node.type})${RESET}`);
        }
        if (v.field) {
          console.log(`  ${DIM}Field: ${v.field}${RESET}`);
        }
        if (v.evidence) {
          console.log(`  ${DIM}Evidence: ${v.evidence}${RESET}`);
        }
        console.log(`  ${DIM}→ ${v.description}${RESET}`);
        console.log(`  ${DIM}Fix: ${v.remediation}${RESET}`);
      }
      console.log();
    }
  }

  if (passedRules.length > 0) {
    console.log(`${DIM}Passed rules: ${passedRules.join(", ")}${RESET}`);
  }

  if (report.skippedRules.length > 0) {
    console.log(`${DIM}Skipped rules: ${report.skippedRules.join(", ")}${RESET}`);
  }

  console.log();
}

async function main() {
  let raw: string;

  const filePath = process.argv[2];
  if (filePath) {
    try {
      raw = readFileSync(filePath, "utf-8");
    } catch (err) {
      console.error(`Cannot read file: ${filePath}`);
      process.exit(1);
    }
  } else {
    // Read from stdin
    raw = readFileSync("/dev/stdin", "utf-8");
  }

  let workflow: unknown;
  try {
    const parsed = JSON.parse(raw);
    // Support both raw workflow JSON and the { "workflow": {...} } wrapper
    workflow = parsed.workflow ?? parsed;
  } catch {
    console.error("Invalid JSON input");
    process.exit(1);
  }

  const report = await analyzeWorkflow(workflow as never, config);
  printReport(report);

  // Exit with non-zero if critical/high violations found
  if (report.summary.critical > 0 || report.summary.high > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Analyzer error:", err);
  process.exit(2);
});
