import { describe, it } from "vitest";
import { maintainabilityRules } from "../../src/analyzer/rules/maintainability.js";
import {
  workflow,
  httpNode,
  setNode,
  scheduleNode,
  ifNode,
  stickyNoteNode,
  executeWorkflowNode,
  run,
  expectRule,
  expectNoRule,
} from "../helpers.js";

// ─── DQ-005 — Monolithic workflow ─────────────────────────────────────────────

describe("DQ-005 — monolithic workflow", () => {
  it("fires medium when node count exceeds decomp warning threshold and no sub-workflows", () => {
    const nodes = [
      scheduleNode(),
      ...Array.from({ length: 21 }, (_, i) => httpNode(`Node ${i}`)),
    ];
    const wf = workflow(nodes);
    expectRule(run(maintainabilityRules, wf), "DQ-005");
  });

  it("fires high when node count exceeds hard limit", () => {
    const nodes = [
      scheduleNode(),
      ...Array.from({ length: 41 }, (_, i) => httpNode(`Node ${i}`)),
    ];
    const wf = workflow(nodes);
    const v = run(maintainabilityRules, wf).find((v) => v.ruleId === "DQ-005");
    if (!v) throw new Error("DQ-005 did not fire");
    if (v.severity !== "high") throw new Error(`Expected high severity, got ${v.severity}`);
  });

  it("does not fire when count is below threshold", () => {
    const nodes = [scheduleNode(), httpNode("A"), httpNode("B")];
    const wf = workflow(nodes);
    expectNoRule(run(maintainabilityRules, wf), "DQ-005");
  });

  it("does not fire at medium level when sub-workflows are present", () => {
    const nodes = [
      scheduleNode(),
      ...Array.from({ length: 21 }, (_, i) => httpNode(`Node ${i}`)),
      executeWorkflowNode("Sub Workflow", "sub-001"),
    ];
    const wf = workflow(nodes);
    const violations = run(maintainabilityRules, wf).filter((v) => v.ruleId === "DQ-005" && v.severity === "medium");
    if (violations.length > 0) throw new Error("DQ-005 medium should not fire when sub-workflows present");
  });
});

// ─── DQ-006 — Default node names ─────────────────────────────────────────────

describe("DQ-006 — default node names", () => {
  it("fires when more than 3 nodes have default names", () => {
    const wf = workflow([
      httpNode("HTTP Request"),
      httpNode("HTTP Request1"),
      setNode("Set"),
      setNode("Set1"),
      ifNode("IF"),
    ]);
    expectRule(run(maintainabilityRules, wf), "DQ-006");
  });

  it("does not fire when 3 or fewer default-named nodes", () => {
    const wf = workflow([
      httpNode("HTTP Request"),
      httpNode("Fetch Orders"),
      setNode("Set"),
    ]);
    expectNoRule(run(maintainabilityRules, wf), "DQ-006");
  });
});

// ─── DQ-007 — No sticky notes ─────────────────────────────────────────────────

describe("DQ-007 — no sticky notes", () => {
  it("fires when workflow has >5 nodes and no sticky notes", () => {
    const nodes = Array.from({ length: 6 }, (_, i) => httpNode(`Node ${i}`));
    const wf = workflow(nodes);
    expectRule(run(maintainabilityRules, wf), "DQ-007");
  });

  it("does not fire when sticky note is present", () => {
    const nodes = [
      ...Array.from({ length: 6 }, (_, i) => httpNode(`Node ${i}`)),
      stickyNoteNode("Overview"),
    ];
    const wf = workflow(nodes);
    expectNoRule(run(maintainabilityRules, wf), "DQ-007");
  });

  it("does not fire for small workflows (<= 5 nodes)", () => {
    const wf = workflow([httpNode("A"), httpNode("B"), httpNode("C")]);
    expectNoRule(run(maintainabilityRules, wf), "DQ-007");
  });
});

// ─── DQ-011 — No workflow description ────────────────────────────────────────

describe("DQ-011 — workflow has no description", () => {
  it("fires when meta.description is absent", () => {
    const wf = workflow([scheduleNode()]);
    expectRule(run(maintainabilityRules, wf), "DQ-011");
  });

  it("fires when description is empty string", () => {
    const wf = { ...workflow([scheduleNode()]), meta: { description: "  " } };
    expectRule(run(maintainabilityRules, wf), "DQ-011");
  });

  it("does not fire when description is set", () => {
    const wf = { ...workflow([scheduleNode()]), meta: { description: "This workflow syncs orders daily." } };
    expectNoRule(run(maintainabilityRules, wf), "DQ-011");
  });
});

// ─── OP-004 — Copy/draft workflow name ───────────────────────────────────────

describe("OP-004 — copy/draft workflow name", () => {
  it("fires on names containing 'copy'", () => {
    const wf = workflow([scheduleNode()], { name: "Order Sync (copy)" });
    expectRule(run(maintainabilityRules, wf), "OP-004");
  });

  it("fires on names containing 'v2'", () => {
    const wf = workflow([scheduleNode()], { name: "Order Sync v2" });
    expectRule(run(maintainabilityRules, wf), "OP-004");
  });

  it("fires on names containing 'test'", () => {
    const wf = workflow([scheduleNode()], { name: "Webhook test" });
    expectRule(run(maintainabilityRules, wf), "OP-004");
  });

  it("does not fire on canonical names", () => {
    const wf = workflow([scheduleNode()], { name: "Daily Invoice Sync" });
    expectNoRule(run(maintainabilityRules, wf), "OP-004");
  });
});

// ─── MAINT-001 — Credential sprawl ───────────────────────────────────────────

describe("MAINT-001 — multiple credentials for same service", () => {
  it("fires when two different credential IDs are used for the same type", () => {
    const node1 = httpNode("Call A");
    node1.credentials = { httpBasicAuth: { id: "cred-001", name: "Team Cred" } };
    const node2 = httpNode("Call B");
    node2.credentials = { httpBasicAuth: { id: "cred-002", name: "Personal Cred" } };
    const wf = workflow([node1, node2]);
    expectRule(run(maintainabilityRules, wf), "MAINT-001");
  });

  it("does not fire when same credential ID is reused", () => {
    const node1 = httpNode("Call A");
    node1.credentials = { httpBasicAuth: { id: "cred-001", name: "Team Cred" } };
    const node2 = httpNode("Call B");
    node2.credentials = { httpBasicAuth: { id: "cred-001", name: "Team Cred" } };
    const wf = workflow([node1, node2]);
    expectNoRule(run(maintainabilityRules, wf), "MAINT-001");
  });
});

// ─── MAINT-002 — Deep expression chains ──────────────────────────────────────

describe("MAINT-002 — deep expression chains", () => {
  it("fires on expression with more than 5 dot accessors", () => {
    // depth = 6: $json .response .data .results .attributes .meta .value
    const wf = workflow([
      setNode("Transform", {
        values: { string: [{ name: "val", value: "{{ $json.response.data.results.attributes.meta.value }}" }] },
      }),
    ]);
    expectRule(run(maintainabilityRules, wf), "MAINT-002");
  });

  it("does not fire on shallow expressions", () => {
    const wf = workflow([
      setNode("Transform", {
        values: { string: [{ name: "val", value: "{{ $json.user.name }}" }] },
      }),
    ]);
    expectNoRule(run(maintainabilityRules, wf), "MAINT-002");
  });
});
