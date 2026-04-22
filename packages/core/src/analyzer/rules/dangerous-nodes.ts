import type { RuleRunner } from "../types.js";
import { NodeType, CODE_NODE_TYPES } from "../utils.js";

// ─── DN-001 ───────────────────────────────────────────────────────────────────

const dn001: RuleRunner = {
  definition: {
    id: "DN-001",
    severity: "critical",
    category: "dangerous_nodes",
    title: "Execute Command node present",
    description:
      "The workflow contains an Execute Command node, which runs arbitrary shell commands on the n8n host. This is a critical risk if the workflow can be triggered by or influenced by untrusted input.",
    remediation:
      "Remove the Execute Command node and replace with purpose-built n8n nodes. If shell execution is genuinely required, run n8n in an isolated container with a minimal, read-only filesystem and no network access from the shell.",
  },
  run({ workflow }) {
    return workflow.nodes
      .filter((n) => !n.disabled && n.type === NodeType.EXECUTE_COMMAND)
      .map((n) => ({
        ruleId: "DN-001",
        severity: "critical" as const,
        category: "dangerous_nodes" as const,
        title: "Execute Command node present",
        description: `Node "${n.name}" executes arbitrary shell commands on the n8n host.`,
        node: { id: n.id, name: n.name, type: n.type, position: n.position },
        remediation: dn001.definition.remediation,
      }));
  },
};

// ─── DN-002 ───────────────────────────────────────────────────────────────────

const dn002: RuleRunner = {
  definition: {
    id: "DN-002",
    severity: "critical",
    category: "dangerous_nodes",
    title: "SSH node present",
    description:
      "The workflow contains an SSH node, which establishes remote shell sessions. A compromise of this workflow grants remote code execution on the SSH target host.",
    remediation:
      "Remove the SSH node. If remote execution is required, use a dedicated API on the target service instead of direct SSH. Ensure SSH credentials are stored in n8n's vault and rotated regularly.",
  },
  run({ workflow }) {
    return workflow.nodes
      .filter((n) => !n.disabled && n.type === NodeType.SSH)
      .map((n) => ({
        ruleId: "DN-002",
        severity: "critical" as const,
        category: "dangerous_nodes" as const,
        title: "SSH node present",
        description: `Node "${n.name}" establishes an SSH session to a remote host.`,
        node: { id: n.id, name: n.name, type: n.type, position: n.position },
        remediation: dn002.definition.remediation,
      }));
  },
};

// ─── DN-003 ───────────────────────────────────────────────────────────────────

const dn003: RuleRunner = {
  definition: {
    id: "DN-003",
    severity: "high",
    category: "dangerous_nodes",
    title: "Code node present — arbitrary code execution",
    description:
      "The workflow contains a Code (or Function) node that executes arbitrary JavaScript. Code nodes have full access to the Node.js runtime environment and should be reviewed manually.",
    remediation:
      "Review the code in this node carefully. Ensure it does not eval() external input, access the filesystem, make network requests, or read environment variables. Consider replacing it with purpose-built n8n nodes.",
  },
  run({ workflow }) {
    return workflow.nodes
      .filter((n) => !n.disabled && CODE_NODE_TYPES.has(n.type))
      .map((n) => ({
        ruleId: "DN-003",
        severity: "high" as const,
        category: "dangerous_nodes" as const,
        title: `Code node present: "${n.name}"`,
        description: `Node "${n.name}" (${n.type}) executes arbitrary JavaScript. Manual review required.`,
        node: { id: n.id, name: n.name, type: n.type, position: n.position },
        remediation: dn003.definition.remediation,
      }));
  },
};

// ─── DN-004 ───────────────────────────────────────────────────────────────────

const FILE_NODE_TYPES = new Set<string>([
  NodeType.READ_WRITE_FILE,
  NodeType.READ_BINARY_FILE,
  NodeType.WRITE_BINARY_FILE,
]);

const dn004: RuleRunner = {
  definition: {
    id: "DN-004",
    severity: "medium",
    category: "dangerous_nodes",
    title: "File system access node present",
    description:
      "The workflow contains a node that reads or writes files on the local filesystem of the n8n host. If the file path is influenced by external input, this may allow path traversal attacks.",
    remediation:
      "Validate and sanitise any file paths derived from external input. Restrict n8n's filesystem access using OS-level permissions or container volume mounts. Prefer object storage (S3, GCS) over local filesystem operations.",
  },
  run({ workflow }) {
    return workflow.nodes
      .filter((n) => !n.disabled && FILE_NODE_TYPES.has(n.type))
      .map((n) => ({
        ruleId: "DN-004",
        severity: "medium" as const,
        category: "dangerous_nodes" as const,
        title: `Filesystem access node: "${n.name}"`,
        description: `Node "${n.name}" (${n.type}) reads or writes files on the n8n host filesystem.`,
        node: { id: n.id, name: n.name, type: n.type, position: n.position },
        remediation: dn004.definition.remediation,
      }));
  },
};

export const dangerousNodesRules: RuleRunner[] = [dn001, dn002, dn003, dn004];
