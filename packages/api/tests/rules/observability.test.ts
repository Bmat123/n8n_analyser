import { describe, it } from "vitest";
import { observabilityRules } from "../../src/analyzer/rules/observability.js";
import {
  workflow,
  httpNode,
  setNode,
  scheduleNode,
  slackNode,
  ifNode,
  switchNode,
  codeNode,
  respondToWebhookNode,
  errorTriggerNode,
  chain,
  run,
  expectRule,
  expectNoRule,
} from "../helpers.js";

// ─── OP-001 — Execution saving disabled ───────────────────────────────────────

describe("OP-001 — execution saving disabled", () => {
  it("fires when saveDataSuccessExecution=none on large workflow", () => {
    const nodes = [scheduleNode(), ...Array.from({ length: 11 }, (_, i) => httpNode(`Node ${i}`))];
    const wf = { ...workflow(nodes), settings: { saveDataSuccessExecution: "none" } };
    expectRule(run(observabilityRules, wf), "OP-001");
  });

  it("does not fire when fewer than 10 non-trigger nodes", () => {
    const nodes = [scheduleNode(), httpNode("A"), httpNode("B")];
    const wf = { ...workflow(nodes), settings: { saveDataSuccessExecution: "none" } };
    expectNoRule(run(observabilityRules, wf), "OP-001");
  });

  it("does not fire when saving is enabled", () => {
    const nodes = [scheduleNode(), ...Array.from({ length: 11 }, (_, i) => httpNode(`Node ${i}`))];
    const wf = { ...workflow(nodes), settings: { saveDataSuccessExecution: "all" } };
    expectNoRule(run(observabilityRules, wf), "OP-001");
  });
});

// ─── OP-002 — Error workflow has no alerting node ─────────────────────────────

describe("OP-002 — error workflow no alerting node", () => {
  it("fires when error-handler workflow has no alerting nodes", () => {
    const wf = workflow([errorTriggerNode(), setNode("Log Error")], { name: "Error Handler" });
    expectRule(run(observabilityRules, wf), "OP-002");
  });

  it("does not fire when Slack node is present", () => {
    const wf = workflow([errorTriggerNode(), slackNode("Notify Team")], { name: "Error Handler" });
    expectNoRule(run(observabilityRules, wf), "OP-002");
  });

  it("does not fire on workflows that are not error handlers", () => {
    const wf = workflow([scheduleNode(), setNode("Do Work")], { name: "Daily Report" });
    expectNoRule(run(observabilityRules, wf), "OP-002");
  });
});

// ─── OP-005 — Workflow always exits success ───────────────────────────────────

describe("OP-005 — workflow always exits same success", () => {
  it("fires when all terminal nodes are Set nodes and there is branching", () => {
    const trigger = scheduleNode();
    const branch = ifNode("Check Condition");
    const setA = setNode("Result A");
    const setB = setNode("Result B");
    const connections = {
      ...chain(trigger, branch),
      [branch.name]: {
        main: [
          [{ node: setA.name, type: "main", index: 0 }],
          [{ node: setB.name, type: "main", index: 0 }],
        ],
      },
    };
    const wf = workflow([trigger, branch, setA, setB], { connections });
    expectRule(run(observabilityRules, wf), "OP-005");
  });

  it("does not fire without branching", () => {
    const trigger = scheduleNode();
    const set = setNode("Result");
    const wf = workflow([trigger, set], { connections: chain(trigger, set) });
    expectNoRule(run(observabilityRules, wf), "OP-005");
  });
});

// ─── OP-006 — console.log in Code node ───────────────────────────────────────

describe("OP-006 — console.log in Code node", () => {
  it("fires when Code node contains console.log", () => {
    const wf = workflow([codeNode("Debug", "console.log('hello', $json); return $input.all();")]);
    expectRule(run(observabilityRules, wf), "OP-006");
  });

  it("fires on console.error", () => {
    const wf = workflow([codeNode("Log Error", "console.error('something went wrong');")]);
    expectRule(run(observabilityRules, wf), "OP-006");
  });

  it("does not fire when no console statements", () => {
    const wf = workflow([codeNode("Process", "return $input.all().map(i => i.json);")]);
    expectNoRule(run(observabilityRules, wf), "OP-006");
  });

  it("does not fire on disabled nodes", () => {
    const wf = workflow([codeNode("Debug", "console.log('test');", { disabled: true })]);
    expectNoRule(run(observabilityRules, wf), "OP-006");
  });
});
