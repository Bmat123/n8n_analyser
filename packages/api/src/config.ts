import { resolve } from "node:path";
import { config as loadEnv } from "dotenv";
// Load .env from the monorepo root before any process.env access
loadEnv({ path: resolve(__dirname, "../../../.env") });

import type { Severity } from "@n8n-analyzer/types";

export interface Config {
  port: number;
  /** Approved database hostnames; suppresses DP-003 for these hosts */
  approvedDbHosts: Set<string>;
  /** Approved external egress hostnames; when non-empty, DP-006 fires for any HTTP Request host not in this list */
  approvedEgressHosts: Set<string>;
  /** Rule IDs to skip globally */
  disabledRules: Set<string>;
  /** Minimum severity included in violation output */
  severityThreshold: Severity;
  /** Partially mask matched secrets in the evidence field */
  redactEvidence: boolean;
  /** Max request body size, e.g. "5mb" */
  requestSizeLimit: string;
  /** If set, enables the AI enhancement layer (Gemini) */
  geminiApiKey: string | null;
  /** Timeout in ms for Mode B n8n API fetch */
  n8nFetchTimeoutMs: number;
  /** CORS origin for the dashboard */
  corsOrigin: string;
  /** Node count threshold before DQ-005 fires at medium severity */
  maxNodesDecompWarning: number;
  /** Node count threshold before DQ-005 escalates to high severity */
  maxNodesHardLimit: number;
  /** Node IDs exempt from the unthrottled-loop HTTP check (DQ-003) */
  loopRateLimitExemptions: Set<string>;
  /** Whether to include advisory/heuristic violations in output */
  includeAdvisory: boolean;
  /** Field names considered currency values for DQ-012 */
  currencyFieldNames: Set<string>;
  /** Whether to run graph-based rules alongside JSON rules */
  enableGraphAnalysis: boolean;
  /** Whether to escalate ambiguous graph violations to the LLM layer */
  enableLlmAnalysis: boolean;
  /** Timeout in ms for LLM calls */
  llmTimeoutMs: number;
  /** Max violations escalated to LLM per workflow */
  maxLlmEscalations: number;
  /** Standard deviations above mean to flag as high centrality */
  centralityStddevThreshold: number;
  /** Cyclomatic complexity threshold for medium severity */
  maxCyclomaticMedium: number;
  /** Cyclomatic complexity threshold for high severity */
  maxCyclomaticHigh: number;
  /** Max paths computed by pathsBetween before truncation */
  graphMaxPathCount: number;
}

const VALID_SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

function parseCommaSeparatedSet(raw: string | undefined): Set<string> {
  if (!raw) return new Set();
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

function parseSeverity(raw: string | undefined): Severity {
  const normalised = (raw ?? "low").toLowerCase();
  if ((VALID_SEVERITIES as string[]).includes(normalised)) {
    return normalised as Severity;
  }
  console.warn(
    `[config] Invalid SEVERITY_THRESHOLD "${raw}", defaulting to "low"`
  );
  return "low";
}

function parseBoolean(raw: string | undefined, defaultValue: boolean): boolean {
  if (raw === undefined) return defaultValue;
  return raw.trim().toLowerCase() !== "false";
}

function parsePort(raw: string | undefined): number {
  const n = parseInt(raw ?? "3000", 10);
  if (isNaN(n) || n < 1 || n > 65535) {
    console.warn(`[config] Invalid PORT "${raw}", defaulting to 3000`);
    return 3000;
  }
  return n;
}

function parseTimeout(raw: string | undefined): number {
  const n = parseInt(raw ?? "5000", 10);
  if (isNaN(n) || n < 0) {
    console.warn(
      `[config] Invalid N8N_FETCH_TIMEOUT_MS "${raw}", defaulting to 5000`
    );
    return 5000;
  }
  return n;
}

function buildConfig(): Config {
  const approvedDbHosts = parseCommaSeparatedSet(
    process.env.APPROVED_DB_HOSTS
  );

  const approvedEgressHosts = parseCommaSeparatedSet(
    process.env.APPROVED_EGRESS_HOSTS
  );

  // Disabled rules are stored as uppercase for case-insensitive matching
  const disabledRules = new Set<string>(
    [...parseCommaSeparatedSet(process.env.DISABLED_RULES)].map((s) =>
      s.toUpperCase()
    )
  );

  const DEFAULT_CURRENCY_FIELDS = "price,amount,total,cost,fee,rate,tax,discount,subtotal";

  return {
    port: parsePort(process.env.PORT),
    approvedDbHosts,
    approvedEgressHosts,
    disabledRules,
    severityThreshold: parseSeverity(process.env.SEVERITY_THRESHOLD),
    redactEvidence: parseBoolean(process.env.REDACT_EVIDENCE, true),
    requestSizeLimit: process.env.REQUEST_SIZE_LIMIT ?? "5mb",
    geminiApiKey: process.env.GEMINI_API_KEY?.trim() || null,
    n8nFetchTimeoutMs: parseTimeout(process.env.N8N_FETCH_TIMEOUT_MS),
    corsOrigin: process.env.CORS_ORIGIN ?? "*",
    maxNodesDecompWarning: parseInt(process.env.MAX_NODES_BEFORE_DECOMP_WARNING ?? "20", 10),
    maxNodesHardLimit: parseInt(process.env.MAX_NODES_HARD_LIMIT ?? "40", 10),
    loopRateLimitExemptions: parseCommaSeparatedSet(process.env.LOOP_RATE_LIMIT_EXEMPTIONS),
    includeAdvisory: parseBoolean(process.env.INCLUDE_ADVISORY, true),
    currencyFieldNames: parseCommaSeparatedSet(process.env.CURRENCY_FIELD_NAMES || DEFAULT_CURRENCY_FIELDS),
    enableGraphAnalysis: parseBoolean(process.env.ENABLE_GRAPH_ANALYSIS, true),
    enableLlmAnalysis: parseBoolean(process.env.ENABLE_LLM_ANALYSIS, false),
    llmTimeoutMs: parseInt(process.env.LLM_TIMEOUT_MS ?? "10000", 10),
    maxLlmEscalations: parseInt(process.env.MAX_LLM_ESCALATIONS ?? "5", 10),
    centralityStddevThreshold: parseFloat(process.env.CENTRALITY_STDDEV_THRESHOLD ?? "2.0"),
    maxCyclomaticMedium: parseInt(process.env.MAX_CYCLOMATIC_MEDIUM ?? "10", 10),
    maxCyclomaticHigh: parseInt(process.env.MAX_CYCLOMATIC_HIGH ?? "20", 10),
    graphMaxPathCount: parseInt(process.env.GRAPH_MAX_PATH_COUNT ?? "1000", 10),
  };
}

export const config: Config = buildConfig();
