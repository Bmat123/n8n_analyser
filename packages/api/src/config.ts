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
  };
}

export const config: Config = buildConfig();
