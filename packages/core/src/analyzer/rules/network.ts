import type { Violation } from "@wflow-analyzer/types";
import type { RuleRunner } from "../types.js";
import {
  walkNodeParams,
  tryParseUrl,
  extractHostname,
  isPrivateHost,
  isFullyDynamicExpression,
  NodeType,
} from "../utils.js";

function isHttpRequestNode(type: string): boolean {
  return type === NodeType.HTTP_REQUEST;
}

// ─── NET-001 ──────────────────────────────────────────────────────────────────

const net001: RuleRunner = {
  definition: {
    id: "NET-001",
    severity: "high",
    category: "network",
    title: "HTTP Request uses unencrypted HTTP",
    description:
      "An HTTP Request node uses http:// instead of https://. Unencrypted connections expose data in transit and credentials to interception.",
    remediation:
      "Change the URL scheme to https://. If the target server does not support TLS, raise a ticket to have it enabled.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !isHttpRequestNode(node.type)) continue;

      for (const { path, value } of walkNodeParams(node)) {
        if (!value.match(/^https?:\/\//i)) continue;

        const url = tryParseUrl(value);
        if (!url) continue;

        if (url.protocol === "http:") {
          // Exclude localhost/127 — those are flagged by NET-003 as SSRF
          const host = url.hostname.toLowerCase();
          if (!isPrivateHost(host)) {
            violations.push({
              ruleId: "NET-001",
              severity: "high",
              category: "network",
              title: "HTTP Request uses unencrypted HTTP",
              description: `Node "${node.name}" makes an unencrypted HTTP request to "${url.host}".`,
              node: { id: node.id, name: node.name, type: node.type, position: node.position },
              field: path,
              evidence: value,
              remediation: net001.definition.remediation,
            });
          }
        }
      }
    }

    return violations;
  },
};

// ─── NET-002 ──────────────────────────────────────────────────────────────────

const net002: RuleRunner = {
  definition: {
    id: "NET-002",
    severity: "high",
    category: "network",
    title: "SSL certificate verification disabled",
    description:
      "An HTTP Request node has SSL/TLS certificate verification disabled. This makes the connection vulnerable to man-in-the-middle attacks.",
    remediation:
      "Remove allowUnauthorizedCerts or set it to false. If you must connect to a server with a self-signed cert, add the CA certificate to the trusted store instead.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !isHttpRequestNode(node.type)) continue;

      const params = node.parameters;

      // Both parameter locations used across different n8n versions
      const directFlag = params.allowUnauthorizedCerts;
      const optionsFlag =
        params.options &&
        typeof params.options === "object" &&
        (params.options as Record<string, unknown>).allowUnauthorizedCerts;

      if (directFlag === true || optionsFlag === true) {
        violations.push({
          ruleId: "NET-002",
          severity: "high",
          category: "network",
          title: "SSL certificate verification disabled",
          description: `Node "${node.name}" has SSL verification disabled (allowUnauthorizedCerts: true).`,
          node: { id: node.id, name: node.name, type: node.type, position: node.position },
          field: directFlag === true ? "parameters.allowUnauthorizedCerts" : "parameters.options.allowUnauthorizedCerts",
          evidence: "true",
          remediation: net002.definition.remediation,
        });
      }
    }

    return violations;
  },
};

// ─── NET-003 ──────────────────────────────────────────────────────────────────

const net003: RuleRunner = {
  definition: {
    id: "NET-003",
    severity: "medium",
    category: "network",
    title: "HTTP Request targets private/internal network address (SSRF risk)",
    description:
      "An HTTP Request node targets a private IP range or localhost. If this URL is influenced by external input, it may allow SSRF attacks that can reach internal infrastructure.",
    remediation:
      "Verify this internal target is intentional. If the URL can be influenced by inbound data, add strict allowlist validation before it reaches this node.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !isHttpRequestNode(node.type)) continue;

      for (const { path, value } of walkNodeParams(node)) {
        const host = extractHostname(value);
        if (host && isPrivateHost(host)) {
          violations.push({
            ruleId: "NET-003",
            severity: "medium",
            category: "network",
            title: `HTTP Request targets internal address: ${host}`,
            description: `Node "${node.name}" makes a request to internal address "${host}". This may indicate SSRF risk if the URL is derived from external input.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: value,
            remediation: net003.definition.remediation,
          });
        }
      }
    }

    return violations;
  },
};

// ─── NET-004 ──────────────────────────────────────────────────────────────────

const net004: RuleRunner = {
  definition: {
    id: "NET-004",
    severity: "low",
    category: "network",
    title: "HTTP Request URL is fully dynamic — origin cannot be verified statically",
    description:
      "An HTTP Request node's URL is constructed entirely from an n8n expression with no static host component. The destination cannot be verified by static analysis.",
    remediation:
      "If possible, hardcode the base URL (e.g. https://api.example.com) and use expressions only for the path or query parameters.",
  },
  run({ workflow }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled || !isHttpRequestNode(node.type)) continue;

      for (const { path, value } of walkNodeParams(node)) {
        // Only check fields that look like URL fields
        const lowerPath = path.toLowerCase();
        if (!lowerPath.includes("url") && !lowerPath.includes("endpoint")) continue;

        if (isFullyDynamicExpression(value)) {
          violations.push({
            ruleId: "NET-004",
            severity: "low",
            category: "network",
            title: "HTTP Request URL is fully dynamic",
            description: `Node "${node.name}" URL is entirely an expression: the destination cannot be statically verified.`,
            node: { id: node.id, name: node.name, type: node.type, position: node.position },
            field: path,
            evidence: value.slice(0, 80),
            remediation: net004.definition.remediation,
          });
        }
      }
    }

    return violations;
  },
};

export const networkRules: RuleRunner[] = [net001, net002, net003, net004];
