/**
 * SARIF 2.1.0 serializer for the n8n Workflow Security Analyzer.
 *
 * SARIF (Static Analysis Results Interchange Format) is the standard format
 * consumed by GitHub Code Scanning, GitLab SAST, Azure DevOps, and most
 * modern CI security dashboards.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { AnalysisReport, Violation, RuleDefinition } from "@wflow-analyzer/types";
import { ALL_RULES } from "./analyzer/rules/index.js";

// ─── SARIF level mapping ──────────────────────────────────────────────────────

const SEVERITY_TO_LEVEL: Record<string, "error" | "warning" | "note"> = {
  critical: "error",
  high:     "error",
  medium:   "warning",
  low:      "note",
};

// ─── SARIF type shapes (minimal subset) ──────────────────────────────────────

interface SarifMessage        { text: string }
interface SarifArtifactUri    { uri: string; uriBaseId?: string }
interface SarifPhysicalLoc    { artifactLocation: SarifArtifactUri; region?: { startLine: number } }
interface SarifLocation       { physicalLocation: SarifPhysicalLoc; message?: SarifMessage }
interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: SarifMessage;
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
}
interface SarifRule {
  id: string;
  name: string;
  shortDescription: SarifMessage;
  fullDescription: SarifMessage;
  help: SarifMessage;
  properties: { tags: string[]; "security-severity": string };
}
interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}
interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
  artifacts: Array<{ location: SarifArtifactUri; mimeType: string }>;
}
export interface SarifDocument {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

// ─── Security severity score (GitHub uses this for CVSS-like sorting) ────────

const SECURITY_SEVERITY: Record<string, string> = {
  critical: "9.8",
  high:     "7.5",
  medium:   "5.0",
  low:      "2.0",
};

// ─── Build the rule catalogue (driver.rules) ─────────────────────────────────

function buildSarifRule(def: RuleDefinition): SarifRule {
  const tag = def.category.replace(/_/g, "-");
  return {
    id: def.id,
    name: def.title.replace(/\s+/g, "").replace(/[^a-zA-Z0-9]/g, ""),
    shortDescription: { text: def.title },
    fullDescription:  { text: def.description },
    help:             { text: `Remediation: ${def.remediation}` },
    properties: {
      tags: ["security", "n8n", tag],
      "security-severity": SECURITY_SEVERITY[def.severity] ?? "5.0",
    },
  };
}

// ─── Convert a single violation to a SARIF result ────────────────────────────

function buildSarifResult(
  violation: Violation,
  fileUri: string
): SarifResult {
  const level = SEVERITY_TO_LEVEL[violation.severity] ?? "warning";

  // Build a rich message that surfaces everything the human report shows
  const parts: string[] = [violation.description];
  if (violation.node)     parts.push(`Node: "${violation.node.name}" (${violation.node.type})`);
  if (violation.field)    parts.push(`Field: ${violation.field}`);
  if (violation.evidence) parts.push(`Evidence: ${violation.evidence}`);
  parts.push(`Fix: ${violation.remediation}`);

  return {
    ruleId: violation.ruleId,
    level,
    message: { text: parts.join("\n") },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: fileUri,
            uriBaseId: "%SRCROOT%",
          },
          // n8n workflow JSON has no meaningful line numbers for violations.
          // We always point to line 1 so GitHub shows the file-level annotation.
          region: { startLine: 1 },
        },
        message: { text: violation.title },
      },
    ],
    properties: {
      severity: violation.severity,
      category: violation.category,
      ...(violation.node ? { nodeName: violation.node.name, nodeType: violation.node.type } : {}),
      ...(violation.field ? { field: violation.field } : {}),
    },
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface SarifInput {
  report: AnalysisReport;
  /** Repo-relative path to the workflow file, e.g. "workflows/payment.json" */
  fileUri: string;
}

/**
 * Convert one or more analysis reports into a single SARIF document.
 * All reports share the same tool driver (rule catalogue).
 */
export function toSarif(inputs: SarifInput[]): SarifDocument {
  const allRuleDefs = ALL_RULES.map((r) => r.definition);

  // Deduplicate rules by id (same rule can appear across multiple reports)
  const ruleMap = new Map<string, SarifRule>();
  for (const def of allRuleDefs) {
    ruleMap.set(def.id, buildSarifRule(def));
  }

  const results: SarifResult[] = [];
  const artifactUris = new Set<string>();

  for (const { report, fileUri } of inputs) {
    artifactUris.add(fileUri);
    for (const violation of report.violations) {
      results.push(buildSarifResult(violation, fileUri));
    }
  }

  const artifacts = [...artifactUris].map((uri) => ({
    location: { uri, uriBaseId: "%SRCROOT%" },
    mimeType: "application/json",
  }));

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "n8n Workflow Security Analyzer",
            version: "1.0.0",
            informationUri: "https://github.com/Bmat123/n8n_analyser",
            rules: [...ruleMap.values()],
          },
        },
        results,
        artifacts,
      },
    ],
  };
}
