import { describe, it } from "vitest";
import { loopFlowRules } from "../../src/analyzer/rules/loop-flow.js";
import {
  workflow, scheduleNode, genericNode, executeWorkflowNode,
  run, expectRule, expectNoRule, B,
} from "../helpers.js";

// ─── LF-001: Sub-minute trigger frequency ────────────────────────────────────

describe("LF-001 — trigger fires at sub-minute frequency", () => {
  it("fires when Schedule Trigger uses a seconds-based interval", () => {
    const trigger = scheduleNode("Every 30s");
    // Patch the parameters to use seconds mode
    trigger.parameters = {
      rule: {
        interval: [{ field: "seconds", secondsInterval: 30 }],
      },
    };
    const wf = workflow([trigger]);
    expectRule(run(loopFlowRules, wf), "LF-001");
  });

  it("fires on 6-field cron expression (seconds field present and non-zero)", () => {
    const cron = genericNode("Cron", `${B}cron`, {
      triggerTimes: {
        item: [{ expression: "*/30 * * * * *" }],
      },
    });
    const wf = workflow([cron]);
    expectRule(run(loopFlowRules, wf), "LF-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when Schedule Trigger uses minutes interval", () => {
    const trigger = scheduleNode();
    trigger.parameters = {
      rule: {
        interval: [{ field: "minutes", minutesInterval: 5 }],
      },
    };
    const wf = workflow([trigger]);
    expectNoRule(run(loopFlowRules, wf), "LF-001");
  });

  it("does NOT fire on a 6-field cron that fires exactly once per minute (seconds=0)", () => {
    const cron = genericNode("Cron", `${B}cron`, {
      triggerTimes: {
        item: [{ expression: "0 * * * * *" }],
      },
    });
    const wf = workflow([cron]);
    expectNoRule(run(loopFlowRules, wf), "LF-001");
  });

  it("does NOT fire on standard 5-field cron", () => {
    const cron = genericNode("Cron", `${B}cron`, {
      triggerTimes: {
        item: [{ expression: "*/5 * * * *" }],
      },
    });
    const wf = workflow([cron]);
    expectNoRule(run(loopFlowRules, wf), "LF-001");
  });

  it("does NOT fire on a disabled trigger", () => {
    const trigger = scheduleNode("Every 1s");
    trigger.parameters = {
      rule: { interval: [{ field: "seconds", secondsInterval: 1 }] },
    };
    trigger.disabled = true;
    const wf = workflow([trigger]);
    expectNoRule(run(loopFlowRules, wf), "LF-001");
  });
});

// ─── LF-002: Execute Workflow self-recursion ──────────────────────────────────

describe("LF-002 — Execute Workflow node calls the same workflow", () => {
  it("fires when Execute Workflow targets the current workflow ID (string format)", () => {
    const exec = executeWorkflowNode("Loop Back", "wf-selfref-123");
    const wf = workflow([exec], { id: "wf-selfref-123" });
    expectRule(run(loopFlowRules, wf), "LF-002");
  });

  it("fires when Execute Workflow targets current ID in __rl object format", () => {
    const exec = executeWorkflowNode("Loop Back", {
      __rl: true,
      value: "wf-selfref-456",
      mode: "id",
    });
    const wf = workflow([exec], { id: "wf-selfref-456" });
    expectRule(run(loopFlowRules, wf), "LF-002");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when Execute Workflow targets a different workflow", () => {
    const exec = executeWorkflowNode("Call Other", "wf-other-789");
    const wf = workflow([exec], { id: "wf-current-001" });
    expectNoRule(run(loopFlowRules, wf), "LF-002");
  });

  it("does NOT fire when the workflow has no ID", () => {
    const exec = executeWorkflowNode("Loop", "some-id");
    const wf = { ...workflow([exec]), id: undefined };
    expectNoRule(run(loopFlowRules, wf), "LF-002");
  });

  it("does NOT fire on disabled Execute Workflow nodes", () => {
    const exec = executeWorkflowNode("Loop", "wf-self-999");
    exec.disabled = true;
    const wf = workflow([exec], { id: "wf-self-999" });
    expectNoRule(run(loopFlowRules, wf), "LF-002");
  });
});
