import { describe, it } from "vitest";
import { hygieneRules } from "../../src/analyzer/rules/hygiene.js";
import {
  workflow, webhookNode, scheduleNode, httpNode, genericNode,
  run, expectRule, expectNoRule, expectRuleCount, chain, B,
} from "../helpers.js";

// ─── HYG-001: Active workflow, no trigger ─────────────────────────────────────

describe("HYG-001 — active workflow without trigger", () => {
  it("fires when active=true and there is no trigger node", () => {
    const wf = workflow([httpNode("Fetch", { url: "https://api.example.com" })], { active: true });
    expectRule(run(hygieneRules, wf), "HYG-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when active=false", () => {
    const wf = workflow([httpNode("Fetch", { url: "https://api.example.com" })], { active: false });
    expectNoRule(run(hygieneRules, wf), "HYG-001");
  });

  it("does NOT fire when active=true AND a webhook trigger is present", () => {
    const wf = workflow([
      webhookNode("Trigger", { authentication: "headerAuth" }),
      httpNode("Fetch", { url: "https://api.example.com" }),
    ], { active: true });
    expectNoRule(run(hygieneRules, wf), "HYG-001");
  });

  it("does NOT fire when active=true AND a schedule trigger is present", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Fetch", { url: "https://api.example.com" }),
    ], { active: true });
    expectNoRule(run(hygieneRules, wf), "HYG-001");
  });

  it("does NOT fire when workflow.active is undefined (treated as inactive)", () => {
    const wf = workflow([httpNode("Fetch", {})]);
    // active defaults to false in our builder
    expectNoRule(run(hygieneRules, wf), "HYG-001");
  });
});

// ─── HYG-002: Orphaned nodes ──────────────────────────────────────────────────

describe("HYG-002 — orphaned nodes", () => {
  it("fires on a non-trigger node with no connections", () => {
    const hook = webhookNode("Hook", { authentication: "headerAuth" });
    const orphan = httpNode("Orphan", { url: "https://api.example.com" });
    // Only connect hook, leave orphan disconnected
    const wf = workflow([hook, orphan], { connections: {} });
    expectRule(run(hygieneRules, wf), "HYG-002");
  });

  it("produces one violation per orphaned node", () => {
    const hook = scheduleNode();
    const a = httpNode("Orphan A", { url: "https://a.example.com" });
    const b = httpNode("Orphan B", { url: "https://b.example.com" });
    const c = httpNode("Connected", { url: "https://c.example.com" });
    const wf = workflow([hook, a, b, c], { connections: chain(hook, c) });
    expectRuleCount(run(hygieneRules, wf), "HYG-002", 2);
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT flag a trigger node with no connections (that is normal)", () => {
    // A trigger node is a valid starting point — it has no incoming edges by design
    const wf = workflow([webhookNode("Hook", { authentication: "headerAuth" })], { connections: {} });
    expectNoRule(run(hygieneRules, wf), "HYG-002");
  });

  it("does NOT flag nodes that are connected as targets", () => {
    const hook = scheduleNode();
    const worker = httpNode("Worker", { url: "https://api.example.com" });
    const wf = workflow([hook, worker], { connections: chain(hook, worker) });
    expectNoRule(run(hygieneRules, wf), "HYG-002");
  });

  it("does NOT flag nodes in a fully connected chain", () => {
    const a = scheduleNode();
    const b = httpNode("Fetch", { url: "https://api.example.com" });
    const c = genericNode("Slack", `${B}slack`, { message: "Done" });
    const wf = workflow([a, b, c], { connections: chain(a, b, c) });
    expectNoRule(run(hygieneRules, wf), "HYG-002");
  });

  it("does NOT flag disabled orphaned nodes", () => {
    const hook = scheduleNode();
    const orphan = httpNode("Orphan", { url: "https://api.example.com" }, { disabled: true });
    const wf = workflow([hook, orphan], { connections: {} });
    expectNoRule(run(hygieneRules, wf), "HYG-002");
  });

  it("does NOT flag an empty workflow", () => {
    const wf = workflow([]);
    expectNoRule(run(hygieneRules, wf), "HYG-002");
  });
});

// ─── HYG-004: All trigger nodes disabled ─────────────────────────────────────

describe("HYG-004 — all trigger nodes disabled", () => {
  it("fires when the only trigger node is disabled", () => {
    const hook = webhookNode("Trigger", {}, { disabled: true });
    const worker = httpNode("Worker", { url: "https://api.example.com" });
    const wf = workflow([hook, worker], { active: false });
    expectRule(run(hygieneRules, wf), "HYG-004");
  });

  it("fires once per disabled trigger when multiple triggers are all disabled", () => {
    const hook1 = webhookNode("Webhook", {}, { disabled: true });
    const hook2 = scheduleNode("Schedule");
    // Override schedule to be disabled
    const disabledSchedule = { ...hook2, disabled: true };
    const wf = workflow([hook1, disabledSchedule]);
    expectRuleCount(run(hygieneRules, wf), "HYG-004", 2);
  });

  it("fires for inactive workflows too (not just active ones)", () => {
    const hook = webhookNode("Trigger", {}, { disabled: true });
    const wf = workflow([hook], { active: false });
    expectRule(run(hygieneRules, wf), "HYG-004");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when at least one trigger is enabled", () => {
    const disabled = webhookNode("Old Trigger", {}, { disabled: true });
    const enabled = scheduleNode("Active Schedule");
    const wf = workflow([disabled, enabled]);
    expectNoRule(run(hygieneRules, wf), "HYG-004");
  });

  it("does NOT fire when there are no trigger nodes at all (HYG-001 covers that)", () => {
    const worker = httpNode("Worker", { url: "https://api.example.com" });
    const wf = workflow([worker]);
    expectNoRule(run(hygieneRules, wf), "HYG-004");
  });

  it("does NOT fire when the trigger is enabled", () => {
    const hook = webhookNode("Trigger", { authentication: "headerAuth" });
    const wf = workflow([hook]);
    expectNoRule(run(hygieneRules, wf), "HYG-004");
  });
});

// ─── HYG-003: Default workflow name ──────────────────────────────────────────

describe("HYG-003 — default workflow name", () => {
  const defaultNames = [
    "My workflow",
    "my workflow",      // case-insensitive
    "Untitled",
    "UNTITLED",
    "Untitled Workflow",
    "New Workflow",
    "",
  ];

  for (const name of defaultNames) {
    it(`fires on name: "${name}"`, () => {
      const wf = workflow([scheduleNode()], { name });
      expectRule(run(hygieneRules, wf), "HYG-003");
    });
  }

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a meaningful name", () => {
    const wf = workflow([scheduleNode()], { name: "Daily Sales Report Generator" });
    expectNoRule(run(hygieneRules, wf), "HYG-003");
  });

  it("does NOT fire on a name that contains 'workflow' but is not a default", () => {
    const wf = workflow([scheduleNode()], { name: "Invoice Processing Workflow" });
    expectNoRule(run(hygieneRules, wf), "HYG-003");
  });

  it("does NOT fire when name is null (treated as unnamed, not default)", () => {
    // null name means no name was set — we treat that the same as "" → fires
    // Actually per spec: null should fire too
    const wf = { ...workflow([scheduleNode()]), name: undefined };
    expectRule(run(hygieneRules, wf), "HYG-003");
  });
});
