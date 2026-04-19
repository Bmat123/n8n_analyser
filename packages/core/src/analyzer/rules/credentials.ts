import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  walkNodeParams,
  redactEvidence,
  tryParseUrl,
  NodeType,
} from "../utils.js";

// ─── Secret patterns for SEC-001 ─────────────────────────────────────────────

interface SecretPattern {
  name: string;
  regex: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { name: "OpenAI key", regex: /sk-[a-zA-Z0-9]{20,}/ },
  { name: "OpenAI project key", regex: /sk-proj-[a-zA-Z0-9_-]{20,}/ },
  { name: "Anthropic key", regex: /sk-ant-[a-zA-Z0-9_-]{20,}/ },
  { name: "GitHub PAT (classic)", regex: /ghp_[a-zA-Z0-9]{36}/ },
  { name: "GitHub PAT (fine-grained)", regex: /github_pat_[a-zA-Z0-9_]{82}/ },
  { name: "Slack token", regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/ },
  { name: "AWS access key", regex: /AKIA[0-9A-Z]{16}/ },
  // AWS secret keys always appear in fields named after credentials — the raw
  // pattern is too broad (matches any 40-char alphanumeric string) so it is
  // only applied when the field name looks like a credential (see guard below).
  { name: "AWS secret key", regex: /[a-zA-Z0-9/+]{40}/ },
  { name: "Bearer token", regex: /Bearer\s+[a-zA-Z0-9\-._~+/]{20,}/i },
  {
    name: "Basic auth header",
    regex: /[Bb]asic\s+[a-zA-Z0-9+/]{20,}={0,2}/,
  },
  { name: "Stripe key", regex: /sk_live_[a-zA-Z0-9]{24,}/ },
  { name: "Stripe test key", regex: /sk_test_[a-zA-Z0-9]{24,}/ },
  { name: "Twilio auth token", regex: /[a-f0-9]{32}/ },
  { name: "Generic API key", regex: /api[_-]?key[_-]?[=:]\s*[a-zA-Z0-9_-]{16,}/i },
];

// Field names that commonly hold credentials (for high-entropy generic detection)
const CREDENTIAL_FIELD_NAMES = new Set([
  "password",
  "passwd",
  "secret",
  "token",
  "apikey",
  "api_key",
  "apitoken",
  "api_token",
  "accesstoken",
  "access_token",
  "privatekey",
  "private_key",
  "clientsecret",
  "client_secret",
  "authtoken",
  "auth_token",
  "secretaccesskey",
  "secret_access_key",
  "awssecret",
  "aws_secret",
]);

/**
 * Parameter field names that hold resource/entity identifiers, not credentials.
 * Values in these fields should never be flagged as secrets regardless of entropy
 * or pattern matches — e.g. a Google Sheets spreadsheet ID looks like a 44-char
 * alphanumeric string and would otherwise match the broad AWS secret key pattern.
 */
const RESOURCE_ID_FIELD_NAMES = new Set([
  // Generic
  "id", "nodeid", "executionid", "instanceid",
  // Google Workspace
  "sheetid", "spreadsheetid", "documentid", "fileid", "folderid",
  "calendarid", "formid", "driveid", "presentationid",
  // Airtable
  "baseid", "tableid", "recordid",
  // Communication
  "channelid", "workspaceid", "teamid", "userid", "groupid",
  "organizationid", "orgid", "accountid",
  // Project tools
  "projectid", "boardid", "listid", "cardid", "issueid",
  // n8n
  "workflowid", "webhookid",
]);

function fieldNameIsResourceId(path: string): boolean {
  const last = path.split(".").pop()?.split("[")[0]?.toLowerCase() ?? "";
  return RESOURCE_ID_FIELD_NAMES.has(last);
}

function isHighEntropy(s: string): boolean {
  if (s.length < 20) return false;
  const unique = new Set(s).size;
  return unique > 10; // rough heuristic
}

function fieldNameLooksCredential(path: string): boolean {
  const last = path.split(".").pop()?.split("[")[0]?.toLowerCase() ?? "";
  return CREDENTIAL_FIELD_NAMES.has(last);
}

// ─── SEC-001 ──────────────────────────────────────────────────────────────────

const sec001: RuleRunner = {
  definition: {
    id: "SEC-001",
    severity: "critical",
    category: "credentials",
    title: "Hardcoded secret detected in node parameter",
    description:
      "A string matching a known secret pattern (API key, token, password) was found directly in a node parameter. Secrets must be stored in n8n's credential vault.",
    remediation:
      "Remove the hardcoded secret. Create an n8n credential of the appropriate type and reference it via the Credential selector on the node.",
  },
  run({ workflow, config }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      for (const { path, value } of walkNodeParams(node)) {
        // Skip pure n8n expression references to credential vault
        if (value.includes("$credentials.")) continue;

        // Skip fields that hold resource/entity identifiers — their values are
        // structurally similar to secrets (long alphanumeric strings) but are
        // not sensitive. e.g. Google Sheets spreadsheet IDs, Airtable base IDs.
        if (fieldNameIsResourceId(path)) continue;

        for (const pattern of SECRET_PATTERNS) {
          // The generic AWS secret key pattern is intentionally broad (any 40-char
          // alphanumeric string). Only apply it when the field name itself suggests
          // it holds a credential, to avoid matching spreadsheet IDs etc.
          if (pattern.name === "AWS secret key" && !fieldNameLooksCredential(path)) continue;

          const match = value.match(pattern.regex);
          if (match) {
            violations.push({
              ruleId: "SEC-001",
              severity: "critical",
              category: "credentials",
              title: `Hardcoded ${pattern.name} detected`,
              description: `A string matching a ${pattern.name} pattern was found in node "${node.name}".`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: redactEvidence(match[0], config.redactEvidence),
              remediation: sec001.definition.remediation,
            });
            break; // one violation per param entry is enough
          }
        }

        // Generic high-entropy detection on credential-named fields
        if (fieldNameLooksCredential(path) && isHighEntropy(value)) {
          // Avoid double-reporting if already caught by pattern above
          const alreadyCaught = SECRET_PATTERNS.some((p) => p.regex.test(value));
          if (!alreadyCaught) {
            violations.push({
              ruleId: "SEC-001",
              severity: "critical",
              category: "credentials",
              title: "Possible hardcoded credential in sensitive field",
              description: `Field "${path}" in node "${node.name}" contains a high-entropy string in a credential-named field.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: redactEvidence(value, config.redactEvidence),
              remediation: sec001.definition.remediation,
            });
          }
        }
      }
    }

    return violations;
  },
};

// ─── SEC-002 ──────────────────────────────────────────────────────────────────

const SENSITIVE_QUERY_PARAMS = [
  "api_key", "apikey", "token", "secret", "password",
  "access_token", "auth", "key", "passwd", "pass",
];

const sec002: RuleRunner = {
  definition: {
    id: "SEC-002",
    severity: "high",
    category: "credentials",
    title: "Credential present in URL query string",
    description:
      "A URL contains a sensitive parameter (api_key, token, secret, etc.) in its query string. Query strings are logged by proxies, web servers, and browser history.",
    remediation:
      "Move the credential to an Authorization header or request body. Use n8n's credential vault to inject it securely.",
  },
  run({ workflow, config }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;

      for (const { path, value } of walkNodeParams(node)) {
        const url = tryParseUrl(value);
        if (!url) continue;

        for (const [key] of url.searchParams.entries()) {
          if (SENSITIVE_QUERY_PARAMS.includes(key.toLowerCase())) {
            const rawValue = url.searchParams.get(key) ?? "";
            violations.push({
              ruleId: "SEC-002",
              severity: "high",
              category: "credentials",
              title: `Credential in URL query string: "${key}"`,
              description: `URL parameter "${key}" in node "${node.name}" looks like a credential being passed via query string.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: redactEvidence(`${key}=${rawValue}`, config.redactEvidence),
              remediation: sec002.definition.remediation,
            });
          }
        }
      }
    }

    return violations;
  },
};

// ─── SEC-003 helpers ──────────────────────────────────────────────────────────

interface SetEntry {
  fieldName: string;
  fieldValue: string;
  path: string;
}

/**
 * Extracts user-defined { name, value } pairs from n8n Set node parameters.
 * Handles both the v1 shape (parameters.values.string[]) and
 * the v2 shape (parameters.assignments.assignments[]).
 */
function collectSetEntries(params: Record<string, unknown>): SetEntry[] {
  const entries: SetEntry[] = [];

  // v1: { values: { string: [{ name, value }], number: [...], ... } }
  const values = params.values;
  if (values && typeof values === "object" && !Array.isArray(values)) {
    for (const [typeKey, typeArr] of Object.entries(values as Record<string, unknown>)) {
      if (!Array.isArray(typeArr)) continue;
      typeArr.forEach((item: unknown, idx: number) => {
        if (item && typeof item === "object") {
          const { name, value } = item as Record<string, unknown>;
          if (typeof name === "string" && typeof value === "string") {
            entries.push({ fieldName: name, fieldValue: value, path: `parameters.values.${typeKey}[${idx}].value` });
          }
        }
      });
    }
  }

  // v2: { assignments: { assignments: [{ name, value }] } }
  const assignments = (params.assignments as Record<string, unknown> | undefined)?.assignments;
  if (Array.isArray(assignments)) {
    assignments.forEach((item: unknown, idx: number) => {
      if (item && typeof item === "object") {
        const { name, value } = item as Record<string, unknown>;
        if (typeof name === "string" && typeof value === "string") {
          entries.push({ fieldName: name, fieldValue: value, path: `parameters.assignments.assignments[${idx}].value` });
        }
      }
    });
  }

  return entries;
}

// ─── SEC-003 ──────────────────────────────────────────────────────────────────

const sec003: RuleRunner = {
  definition: {
    id: "SEC-003",
    severity: "medium",
    category: "credentials",
    title: "Credential set in plain Set node value",
    description:
      "A Set node contains a field with a name or value that suggests it is carrying a credential outside of n8n's credential vault.",
    remediation:
      "If this value is a credential, store it in n8n's credential vault and pass it to the consuming node via the Credential selector instead of through data fields.",
  },
  run({ workflow, config }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;
      if (node.type !== NodeType.SET) continue;

      // n8n Set nodes store fields in two shapes depending on version:
      //   v1: parameters.values.string[].{ name, value }
      //   v2: parameters.assignments.assignments[].{ name, value }
      // We inspect both shapes directly to get the user-defined field name.
      const entries = collectSetEntries(node.parameters);

      for (const { fieldName, fieldValue, path } of entries) {
        // Flag if the user-defined field NAME looks like a credential
        if (fieldNameLooksCredential(fieldName.toLowerCase())) {
          violations.push({
            ruleId: "SEC-003",
            severity: "medium",
            category: "credentials",
            title: `Credential-named field in Set node: "${fieldName}"`,
            description: `Set node "${node.name}" sets a field named "${fieldName}" which may be carrying a credential through the workflow data rather than via the credential vault.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: redactEvidence(fieldValue, config.redactEvidence),
            remediation: sec003.definition.remediation,
          });
          continue;
        }

        // Also flag if the field VALUE matches a known secret pattern
        for (const pattern of SECRET_PATTERNS) {
          const match = fieldValue.match(pattern.regex);
          if (match) {
            violations.push({
              ruleId: "SEC-003",
              severity: "medium",
              category: "credentials",
              title: `Secret value found in Set node field "${fieldName}"`,
              description: `Set node "${node.name}" field "${fieldName}" contains a value matching a ${pattern.name} pattern.`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: redactEvidence(match[0], config.redactEvidence),
              remediation: sec003.definition.remediation,
            });
            break;
          }
        }
      }
    }

    return violations;
  },
};

export const credentialsRules: RuleRunner[] = [sec001, sec002, sec003];
