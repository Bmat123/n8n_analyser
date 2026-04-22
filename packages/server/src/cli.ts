/**
 * CLI runner — analyze n8n workflow JSON files without the HTTP server.
 *
 * Usage:
 *   npx tsx src/cli.ts path/to/workflow.json
 *   npx tsx src/cli.ts workflows/            # scan all *.json in a directory
 *   cat workflow.json | npx tsx src/cli.ts
 *
 *   # SARIF output (for GitHub Code Scanning / CI):
 *   npx tsx src/cli.ts --format sarif workflows/ > results.sarif
 *
 * Environment variables:
 *   SEVERITY_THRESHOLD   low | medium | high | critical  (default: low)
 *   DISABLED_RULES       comma-separated rule IDs to skip
 *   REDACT_EVIDENCE      true | false  (default: true)
 */

import { readFileSync, readdirSync, statSync, writeFileSync } from "fs";
import { join, relative, extname } from "path";
import { analyzeWorkflow, toSarif } from "@wflow-analyzer/core";
import { config } from "./config.js";
import type { AnalysisReport, Violation } from "@wflow-analyzer/types";

// ─── CLI arg parsing ──────────────────────────────────────────────────────────

function parseArgs(argv: string[]): { format: "text" | "sarif"; output: string | null; paths: string[] } {
  const args = argv.slice(2); // drop "node" and script path
  let format: "text" | "sarif" = "text";
  let output: string | null = null;
  const paths: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--sarif") {
      format = "sarif";
    } else if (arg === "--format") {
      const next = args[i + 1];
      if (next === "sarif" || next === "text") { format = next; i++; }
      else { console.error(`--format requires: sarif | text`); process.exit(1); }
    } else if (arg.startsWith("--format=")) {
      const val = arg.slice("--format=".length);
      if (val === "sarif" || val === "text") { format = val; }
      else { console.error(`Unknown format "${val}". Choose: sarif | text`); process.exit(1); }
    } else if (arg === "--output" || arg === "-o") {
      output = args[++i] ?? null;
      if (!output) { console.error(`--output requires a file path`); process.exit(1); }
    } else if (arg.startsWith("--output=")) {
      output = arg.slice("--output=".length);
    } else if (!arg.startsWith("--")) {
      paths.push(arg);
    }
  }

  return { format, output, paths };
}

// ─── File discovery ───────────────────────────────────────────────────────────

/** Recursively find all .json files under a directory */
function findJsonFiles(dirPath: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dirPath)) {
    const full = join(dirPath, entry);
    if (statSync(full).isDirectory()) {
      results.push(...findJsonFiles(full));
    } else if (extname(entry).toLowerCase() === ".json") {
      results.push(full);
    }
  }
  return results;
}

/** Returns true if parsed JSON looks like an n8n workflow */
function isN8nWorkflow(parsed: unknown): boolean {
  if (!parsed || typeof parsed !== "object") return false;
  const obj = parsed as Record<string, unknown>;
  return Array.isArray(obj.nodes) && typeof obj.connections === "object";
}

interface WorkflowFile {
  filePath: string;
  workflow: unknown;
}

/**
 * Resolve the list of paths into individual workflow files.
 * A path may be:
 *   - a single .json file (used directly)
 *   - a directory (all .json files under it are scanned)
 * Only files that parse as n8n workflows are included.
 */
function resolveWorkflowFiles(paths: string[]): WorkflowFile[] {
  const resolved: WorkflowFile[] = [];

  const addFile = (filePath: string) => {
    let raw: string;
    try {
      raw = readFileSync(filePath, "utf-8");
    } catch {
      console.error(`[skip] Cannot read: ${filePath}`);
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      console.error(`[skip] Invalid JSON: ${filePath}`);
      return;
    }

    // Support both raw workflow JSON and the { "workflow": {...} } wrapper
    const workflow =
      parsed !== null &&
      typeof parsed === "object" &&
      "workflow" in (parsed as Record<string, unknown>)
        ? (parsed as Record<string, unknown>).workflow
        : parsed;

    if (!isN8nWorkflow(workflow)) {
      // Silently skip non-workflow JSON (package.json, tsconfig.json, etc.)
      return;
    }

    resolved.push({ filePath, workflow });
  };

  for (const p of paths) {
    let stat;
    try {
      stat = statSync(p);
    } catch {
      console.error(`Path not found: ${p}`);
      process.exit(1);
    }

    if (stat.isDirectory()) {
      for (const fp of findJsonFiles(p)) addFile(fp);
    } else {
      addFile(p);
    }
  }

  return resolved;
}

// ─── Text report formatting ───────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "\x1b[31;1m",
  high:     "\x1b[33;1m",
  medium:   "\x1b[33m",
  low:      "\x1b[36m",
};
const RESET = "\x1b[0m";
const BOLD  = "\x1b[1m";
const DIM   = "\x1b[2m";
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

function printReport(report: AnalysisReport, filePath?: string): void {
  const { summary, violations, passedRules, metadata } = report;

  console.log();
  console.log(`${BOLD}═══ n8n Workflow Security Report ═══${RESET}`);
  if (filePath) {
    console.log(`${DIM}File     : ${filePath}${RESET}`);
  }
  console.log(`${DIM}Workflow : ${report.workflowName ?? "(unnamed)"}${RESET}`);
  console.log(`${DIM}Analyzed : ${report.analyzedAt}${RESET}`);
  console.log(`${DIM}Nodes    : ${summary.totalNodes}  |  Node types: ${metadata.nodeTypesFound.join(", ")}${RESET}`);
  console.log();

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
    const byCategory = new Map<string, Violation[]>();
    for (const v of violations) {
      const list = byCategory.get(v.category) ?? [];
      list.push(v);
      byCategory.set(v.category, list);
    }

    for (const [category, items] of byCategory) {
      console.log(`${BOLD}─── ${category.toUpperCase().replace(/_/g, " ")} ───${RESET}`);
      for (const v of items) {
        console.log();
        console.log(`  ${badge(v.severity)}  ${BOLD}[${v.ruleId}]${RESET} ${v.title}`);
        if (v.node)     console.log(`  ${DIM}Node: "${v.node.name}" (${v.node.type})${RESET}`);
        if (v.field)    console.log(`  ${DIM}Field: ${v.field}${RESET}`);
        if (v.evidence) console.log(`  ${DIM}Evidence: ${v.evidence}${RESET}`);
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

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const { format, output, paths } = parseArgs(process.argv);

  let workflowFiles: WorkflowFile[];

  if (paths.length === 0) {
    // No paths — read a single workflow from stdin
    let raw: string;
    try {
      raw = readFileSync("/dev/stdin", "utf-8");
    } catch {
      console.error("No input provided. Pass a file path, directory, or pipe JSON via stdin.");
      process.exit(1);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      console.error("Invalid JSON on stdin");
      process.exit(1);
    }

    const workflow =
      parsed !== null &&
      typeof parsed === "object" &&
      "workflow" in (parsed as Record<string, unknown>)
        ? (parsed as Record<string, unknown>).workflow
        : parsed;

    workflowFiles = [{ filePath: "<stdin>", workflow }];
  } else {
    workflowFiles = resolveWorkflowFiles(paths);

    if (workflowFiles.length === 0) {
      console.error("No n8n workflow JSON files found in the specified path(s).");
      process.exit(1);
    }
  }

  // ── Analyze all files ──────────────────────────────────────────────────────

  const results: Array<{ filePath: string; report: AnalysisReport }> = [];

  for (const { filePath, workflow } of workflowFiles) {
    const report = await analyzeWorkflow(workflow as never, config);
    results.push({ filePath, report });
  }

  // ── Output ─────────────────────────────────────────────────────────────────

  if (format === "sarif") {
    // Compute repo-relative paths for SARIF artifact URIs.
    // We use process.cwd() as the root so paths like "workflows/payment.json"
    // are correct when the action runs from the repo root.
    const cwd = process.cwd();
    const sarifInputs = results.map(({ filePath, report }) => ({
      report,
      fileUri:
        filePath === "<stdin>"
          ? "workflow.json"
          : relative(cwd, filePath).replace(/\\/g, "/"),
    }));

    const sarif = toSarif(sarifInputs);
    const sarifJson = JSON.stringify(sarif, null, 2) + "\n";
    if (output) {
      writeFileSync(output, sarifJson, "utf-8");
      console.error(`SARIF written to ${output}`);
    } else {
      process.stdout.write(sarifJson);
    }
  } else {
    // Text output — print each report in sequence
    for (const { filePath, report } of results) {
      printReport(report, workflowFiles.length > 1 ? filePath : undefined);
    }

    // Summary line when scanning multiple files
    if (results.length > 1) {
      const totalCritical = results.reduce((n, r) => n + r.report.summary.critical, 0);
      const totalHigh     = results.reduce((n, r) => n + r.report.summary.high, 0);
      const totalMedium   = results.reduce((n, r) => n + r.report.summary.medium, 0);
      const totalLow      = results.reduce((n, r) => n + r.report.summary.low, 0);
      const totalViol     = results.reduce((n, r) => n + r.report.summary.totalViolations, 0);

      console.log(`${BOLD}═══ Batch summary: ${results.length} workflows ═══${RESET}`);
      console.log(
        `Total violations: ${totalViol}` +
        (totalCritical ? `  ${color("critical", `${totalCritical} critical`)}` : "") +
        (totalHigh     ? `  ${color("high",     `${totalHigh} high`)}` : "") +
        (totalMedium   ? `  ${color("medium",   `${totalMedium} medium`)}` : "") +
        (totalLow      ? `  ${color("low",      `${totalLow} low`)}` : "")
      );
      console.log();
    }
  }

  // ── Exit code ──────────────────────────────────────────────────────────────
  // Exit 1 if any critical or high violations found across any workflow.
  // Exit 0 otherwise (clean or medium/low only).
  const hasBlocker = results.some(
    (r) => r.report.summary.critical > 0 || r.report.summary.high > 0
  );
  process.exit(hasBlocker ? 1 : 0);
}

main().catch((err) => {
  console.error("Analyzer error:", err);
  process.exit(2);
});
