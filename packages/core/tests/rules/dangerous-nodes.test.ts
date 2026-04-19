import { describe, it } from "vitest";
import { dangerousNodesRules } from "../../src/analyzer/rules/dangerous-nodes.js";
import {
  workflow, scheduleNode, genericNode, codeNode,
  run, expectRule, expectNoRule, expectRuleCount, B,
} from "../helpers.js";

// ─── DN-001: Execute Command ───────────────────────────────────────────────────

describe("DN-001 — Execute Command node", () => {
  it("fires when an executeCommand node is present", () => {
    const wf = workflow([
      scheduleNode(),
      genericNode("Cleanup", `${B}executeCommand`, { command: "rm -rf /tmp/*" }),
    ]);
    expectRule(run(dangerousNodesRules, wf), "DN-001");
  });

  it("produces one violation per executeCommand node", () => {
    const wf = workflow([
      genericNode("Cmd 1", `${B}executeCommand`, { command: "ls" }),
      genericNode("Cmd 2", `${B}executeCommand`, { command: "pwd" }),
    ]);
    expectRuleCount(run(dangerousNodesRules, wf), "DN-001", 2);
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a schedule trigger", () => {
    const wf = workflow([scheduleNode()]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-001");
  });

  it("does NOT fire on a disabled executeCommand node", () => {
    const wf = workflow([
      genericNode("Cmd", `${B}executeCommand`, { command: "echo hi" }, { disabled: true }),
    ]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-001");
  });
});

// ─── DN-002: SSH node ─────────────────────────────────────────────────────────

describe("DN-002 — SSH node", () => {
  it("fires when an SSH node is present", () => {
    const wf = workflow([
      scheduleNode(),
      genericNode("Deploy", `${B}ssh`, { command: "cd /app && git pull" }),
    ]);
    expectRule(run(dangerousNodesRules, wf), "DN-002");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a non-SSH node", () => {
    const wf = workflow([scheduleNode()]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-002");
  });

  it("does NOT fire on a disabled SSH node", () => {
    const wf = workflow([
      genericNode("SSH", `${B}ssh`, {}, { disabled: true }),
    ]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-002");
  });
});

// ─── DN-003: Code node ────────────────────────────────────────────────────────

describe("DN-003 — Code node", () => {
  it("fires on a Code node", () => {
    const wf = workflow([codeNode("Transform", "return items;")]);
    expectRule(run(dangerousNodesRules, wf), "DN-003");
  });

  it("fires on a Function node type", () => {
    const wf = workflow([genericNode("Fn", `${B}function`, { functionCode: "return items;" })]);
    expectRule(run(dangerousNodesRules, wf), "DN-003");
  });

  it("fires on a FunctionItem node type", () => {
    const wf = workflow([genericNode("FnItem", `${B}functionItem`, { functionCode: "return item;" })]);
    expectRule(run(dangerousNodesRules, wf), "DN-003");
  });

  it("produces one violation per code node", () => {
    const wf = workflow([
      codeNode("Step 1", "return items;"),
      codeNode("Step 2", "return items;"),
    ]);
    expectRuleCount(run(dangerousNodesRules, wf), "DN-003", 2);
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on non-code nodes", () => {
    const wf = workflow([scheduleNode()]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-003");
  });

  it("does NOT fire on a disabled code node", () => {
    const wf = workflow([codeNode("Disabled", "return items;", { disabled: true })]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-003");
  });
});

// ─── DN-004: File system access ───────────────────────────────────────────────

describe("DN-004 — filesystem access node", () => {
  const fileTypes = [
    [`${B}readWriteFile`, "Read/Write"],
    [`${B}readBinaryFile`, "Read Binary"],
    [`${B}writeBinaryFile`, "Write Binary"],
  ] as const;

  for (const [type, label] of fileTypes) {
    it(`fires on ${label} node (${type})`, () => {
      const wf = workflow([genericNode(label, type, { filePath: "/data/file.json" })]);
      expectRule(run(dangerousNodesRules, wf), "DN-004");
    });
  }

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a Code node (that is DN-003, not DN-004)", () => {
    const wf = workflow([codeNode("Transform", "return items;")]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-004");
  });

  it("does NOT fire on a disabled file node", () => {
    const wf = workflow([
      genericNode("Disabled", `${B}readWriteFile`, {}, { disabled: true }),
    ]);
    expectNoRule(run(dangerousNodesRules, wf), "DN-004");
  });
});
