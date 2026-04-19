import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  walkNodeParams,
  NodeType,
  CODE_NODE_TYPES,
  OFFICIAL_NODE_PREFIXES,
  tryParseUrl,
} from "../utils.js";

// ─── SC-001 ───────────────────────────────────────────────────────────────────

// Detects HTTP calls back to n8n's own REST API on localhost
// n8n default port is 5678; the API lives under /api/v1/
const N8N_SELF_API_REGEX =
  /(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?::\d+)?\/api\/v1\//i;
const N8N_DEFAULT_PORT_REGEX = /(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1):5678\b/i;

const sc001: RuleRunner = {
  definition: {
    id: "SC-001",
    severity: "critical",
    category: "supply_chain",
    title: "HTTP Request node calls the n8n API on localhost — potential instance pivot",
    description:
      "An HTTP Request node targets the n8n REST API running on the same host (localhost:5678 or /api/v1/ on a local address). A workflow that can call n8n's own API can read or modify other workflows, list/update credentials, and read execution history — effectively pivoting to full instance control.",
    remediation:
      "Remove this node unless it is explicitly required. If internal n8n API calls are necessary, restrict the n8n API key used (least-privilege) and audit what operations are performed. Consider whether an Execute Workflow node would serve the same purpose without API access.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;

      for (const { path, value } of walkNodeParams(node)) {
        if (N8N_SELF_API_REGEX.test(value) || N8N_DEFAULT_PORT_REGEX.test(value)) {
          violations.push({
            ruleId: "SC-001",
            severity: "critical",
            category: "supply_chain",
            title: `HTTP Request node "${node.name}" calls the local n8n API`,
            description: `Node "${node.name}" makes an HTTP request to the n8n API running on localhost. This allows the workflow to control the n8n instance (read credentials, modify workflows, etc.).`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: value.slice(0, 120),
            remediation: sc001.definition.remediation,
          });
          break; // one violation per node
        }
      }
    }

    return violations;
  },
};

// ─── SC-002 ───────────────────────────────────────────────────────────────────

function isOfficialNode(type: string): boolean {
  return OFFICIAL_NODE_PREFIXES.some((prefix) => type.startsWith(prefix));
}

const sc002: RuleRunner = {
  definition: {
    id: "SC-002",
    severity: "high",
    category: "supply_chain",
    title: "Community (third-party) node detected",
    description:
      "The workflow uses a node from an unofficial namespace. Community nodes are third-party code that executes with the same privileges as n8n itself. A malicious or compromised community node can read credentials, exfiltrate data, or execute arbitrary commands on the host.",
    remediation:
      "Audit the community node's source code before use. Pin to a specific version. Prefer official n8n-nodes-base nodes where an equivalent exists. Run n8n in a container with restricted permissions to limit blast radius.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];
    const reportedTypes = new Set<string>();

    for (const node of workflow.nodes) {
      if (node.disabled) continue;
      if (isOfficialNode(node.type)) continue;
      if (reportedTypes.has(node.type)) continue; // one violation per unique type
      reportedTypes.add(node.type);

      violations.push({
        ruleId: "SC-002",
        severity: "high",
        category: "supply_chain",
        title: `Community node detected: "${node.type}"`,
        description: `Node "${node.name}" uses the unverified namespace "${node.type}". This is not an official n8n node — it is third-party code running with full n8n privileges.`,
        node: { id: node.id, name: node.name, type: node.type, position: node.position },
        evidence: node.type,
        remediation: sc002.definition.remediation,
      });
    }

    return violations;
  },
};

// ─── SC-003 ───────────────────────────────────────────────────────────────────

const CODE_PARAM_KEYS = ["jsCode", "functionCode", "code"];

interface CodeDangerPattern {
  regex: RegExp;
  label: string;
}

const CODE_DANGER_PATTERNS: CodeDangerPattern[] = [
  { regex: /require\s*\(/, label: "require() — dynamic module loading" },
  { regex: /import\s*\(/, label: "import() — dynamic ESM import" },
  { regex: /process\.env\b/, label: "process.env — host environment access" },
  { regex: /child_process/, label: "child_process — subprocess spawning" },
  { regex: /\beval\s*\(/, label: "eval() — arbitrary code execution" },
  { regex: /new\s+Function\s*\(/, label: "new Function() — eval equivalent" },
];

const sc003: RuleRunner = {
  definition: {
    id: "SC-003",
    severity: "high",
    category: "supply_chain",
    title: "Code node contains dangerous runtime patterns",
    description:
      "A Code/Function node contains patterns that can break out of the intended execution scope: dynamic module loading (require/import), direct environment variable access (process.env), subprocess spawning (child_process), or dynamic code evaluation (eval/Function). These are significant escalation vectors on self-hosted n8n.",
    remediation:
      "Remove or replace the dangerous pattern. For environment variables, use n8n credentials. For subprocess operations, use the Execute Command node (which is explicitly audited). For dynamic logic, consider whether a purpose-built n8n node exists.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !CODE_NODE_TYPES.has(node.type)) continue;

      for (const paramKey of CODE_PARAM_KEYS) {
        const code = node.parameters[paramKey];
        if (typeof code !== "string" || !code) continue;

        const found: string[] = [];
        for (const { regex, label } of CODE_DANGER_PATTERNS) {
          if (regex.test(code)) found.push(label);
        }

        if (found.length > 0) {
          violations.push({
            ruleId: "SC-003",
            severity: "high",
            category: "supply_chain",
            title: `Dangerous code pattern in "${node.name}": ${found[0]}`,
            description: `Code node "${node.name}" contains the following dangerous pattern(s): ${found.join("; ")}. These can access host resources beyond n8n's intended sandbox.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: `parameters.${paramKey}`,
            evidence: found.join(", "),
            remediation: sc003.definition.remediation,
          });
          break; // one violation per node
        }
      }
    }

    return violations;
  },
};

// ─── SC-004 ───────────────────────────────────────────────────────────────────

const RAW_CONTENT_HOSTS = new Set([
  "raw.githubusercontent.com",
  "pastebin.com",
  "hastebin.com",
  "paste.ee",
  "gist.github.com",
  "dpaste.com",
  "ghostbin.com",
  "controlc.com",
]);

const sc004: RuleRunner = {
  definition: {
    id: "SC-004",
    severity: "medium",
    category: "supply_chain",
    title: "HTTP Request fetches code or config from a raw-content hosting site",
    description:
      "An HTTP Request node targets a site commonly used to host raw code or configuration (GitHub raw, Pastebin, Hastebin, etc.). Workflows that pull and execute content from these URLs at runtime are vulnerable to supply chain attacks: if the remote content changes, the workflow's behaviour changes.",
    remediation:
      "Store configuration in n8n workflow variables or environment variables, not on external paste sites. If fetching scripts or config at runtime is necessary, pin to a specific commit SHA, verify a checksum, and use a private repository.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== NodeType.HTTP_REQUEST) continue;

      for (const { path, value } of walkNodeParams(node)) {
        const parsed = tryParseUrl(value);
        if (!parsed) continue;

        const host = parsed.hostname.toLowerCase();
        if (RAW_CONTENT_HOSTS.has(host)) {
          violations.push({
            ruleId: "SC-004",
            severity: "medium",
            category: "supply_chain",
            title: `HTTP Request "${node.name}" fetches from raw-content host: ${host}`,
            description: `Node "${node.name}" fetches content from "${host}", a site used to host raw code or config. Content fetched at runtime can be changed by the host at any time.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: value.slice(0, 120),
            remediation: sc004.definition.remediation,
          });
          break; // one violation per node
        }
      }
    }

    return violations;
  },
};

export const supplyChainRules: RuleRunner[] = [sc001, sc002, sc003, sc004];
