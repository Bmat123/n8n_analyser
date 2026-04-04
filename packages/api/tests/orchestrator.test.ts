import { describe, it, expect } from "vitest";
import { analyzeWorkflow } from "../src/analyzer/index.js";
import {
  workflow, webhookNode, httpNode, scheduleNode, genericNode,
  errorTriggerNode, chain, defaultConfig, B,
} from "./helpers.js";

// ─── Smoke test: clean workflow ───────────────────────────────────────────────

describe("analyzeWorkflow — clean workflow", () => {
  it("returns zero violations on a safe workflow", async () => {
    const sched = scheduleNode();
    const fetch = httpNode("Fetch", { url: "https://api.example.com/data", requestMethod: "GET" });
    const errHandler = errorTriggerNode();
    const wf = workflow(
      [sched, fetch, errHandler],
      { name: "Daily Data Sync", active: true, connections: chain(sched, fetch) }
    );
    const report = await analyzeWorkflow(wf, defaultConfig);
    expect(report.summary.totalViolations).toBe(0);
    expect(report.violations).toHaveLength(0);
  });

  it("populates report metadata correctly", async () => {
    const wf = workflow([scheduleNode(), httpNode("Fetch", { url: "https://api.example.com" })], {
      name: "Test WF",
      id: "wf-123",
    });
    const report = await analyzeWorkflow(wf, defaultConfig);
    expect(report.workflowId).toBe("wf-123");
    expect(report.workflowName).toBe("Test WF");
    expect(report.metadata.analyzerVersion).toBe("1.0.0");
    expect(report.metadata.rulesetVersion).toBe("1.0.0");
    expect(report.metadata.nodeTypesFound).toContain("scheduleTrigger");
    expect(report.metadata.nodeTypesFound).toContain("httpRequest");
  });

  it("sets analyzedAt to a valid ISO8601 timestamp", async () => {
    const wf = workflow([scheduleNode()]);
    const report = await analyzeWorkflow(wf, defaultConfig);
    expect(() => new Date(report.analyzedAt)).not.toThrow();
    expect(new Date(report.analyzedAt).getFullYear()).toBeGreaterThanOrEqual(2024);
  });
});

// ─── Severity threshold filtering ────────────────────────────────────────────

describe("analyzeWorkflow — severity threshold", () => {
  const dangerousWf = workflow([
    genericNode("Cmd", `${B}executeCommand`, { command: "ls" }), // critical
    webhookNode("Hook", { authentication: "none" }),              // high (DP-001)
  ], { name: "Test WF" });

  it("includes all violations when threshold is 'low'", async () => {
    const report = await analyzeWorkflow(dangerousWf, { ...defaultConfig, severityThreshold: "low" });
    expect(report.summary.totalViolations).toBeGreaterThan(0);
  });

  it("excludes low violations when threshold is 'medium'", async () => {
    const wf = workflow([webhookNode("Hook", { authentication: "none" })], { name: "Test" });
    const low = await analyzeWorkflow(wf, { ...defaultConfig, severityThreshold: "low" });
    const medium = await analyzeWorkflow(wf, { ...defaultConfig, severityThreshold: "medium" });
    expect(medium.summary.low).toBe(0);
    expect(medium.summary.totalViolations).toBeLessThanOrEqual(low.summary.totalViolations);
  });

  it("only returns critical violations when threshold is 'critical'", async () => {
    const report = await analyzeWorkflow(dangerousWf, { ...defaultConfig, severityThreshold: "critical" });
    expect(report.summary.high).toBe(0);
    expect(report.summary.medium).toBe(0);
    expect(report.summary.low).toBe(0);
    expect(report.summary.critical).toBeGreaterThan(0);
  });
});

// ─── Disabled rules ───────────────────────────────────────────────────────────

describe("analyzeWorkflow — disabled rules", () => {
  it("skips disabled rules and reports them in skippedRules", async () => {
    const wf = workflow([genericNode("Cmd", `${B}executeCommand`, { command: "ls" })]);
    const report = await analyzeWorkflow(wf, {
      ...defaultConfig,
      disabledRules: new Set(["DN-001"]),
    });
    expect(report.skippedRules).toContain("DN-001");
    expect(report.violations.find((v) => v.ruleId === "DN-001")).toBeUndefined();
  });

  it("still runs non-disabled rules when some are disabled", async () => {
    const wf = workflow([
      genericNode("Cmd", `${B}executeCommand`, { command: "ls" }),
      webhookNode("Hook", { authentication: "none" }),
    ]);
    const report = await analyzeWorkflow(wf, {
      ...defaultConfig,
      disabledRules: new Set(["DN-001"]),
    });
    expect(report.violations.find((v) => v.ruleId === "DP-001")).toBeDefined();
  });
});

// ─── Passed rules ────────────────────────────────────────────────────────────

describe("analyzeWorkflow — passedRules list", () => {
  it("lists rules that produced no violations in passedRules", async () => {
    const wf = workflow([scheduleNode(), errorTriggerNode()], { name: "Minimal Safe WF" });
    const report = await analyzeWorkflow(wf, defaultConfig);
    expect(report.passedRules.length).toBeGreaterThan(0);
    // No DN-001 violation → it should be in passedRules
    expect(report.passedRules).toContain("DN-001");
  });

  it("does NOT include a violated rule in passedRules", async () => {
    const wf = workflow([genericNode("Cmd", `${B}executeCommand`, { command: "ls" })]);
    const report = await analyzeWorkflow(wf, defaultConfig);
    expect(report.passedRules).not.toContain("DN-001");
  });
});

// ─── Evidence redaction ───────────────────────────────────────────────────────

describe("analyzeWorkflow — evidence redaction", () => {
  const secretWf = workflow([
    httpNode("Call", { headers: { Authorization: "Bearer sk-live-ABCDEFGHIJKLMNOPQRSTUVWX123456" } }),
  ]);

  it("redacts evidence by default (REDACT_EVIDENCE=true)", async () => {
    const report = await analyzeWorkflow(secretWf, { ...defaultConfig, redactEvidence: true });
    const sec001 = report.violations.find((v) => v.ruleId === "SEC-001");
    expect(sec001).toBeDefined();
    expect(sec001!.evidence).toContain("REDACTED");
    expect(sec001!.evidence).not.toContain("sk-live-ABCDEFGHIJ");
  });

  it("does NOT redact when REDACT_EVIDENCE=false", async () => {
    const report = await analyzeWorkflow(secretWf, { ...defaultConfig, redactEvidence: false });
    const sec001 = report.violations.find((v) => v.ruleId === "SEC-001");
    expect(sec001).toBeDefined();
    expect(sec001!.evidence).not.toContain("REDACTED");
  });
});

// ─── Summary counts ───────────────────────────────────────────────────────────

describe("analyzeWorkflow — summary counts", () => {
  it("totalNodes matches the number of nodes in the workflow", async () => {
    const nodes = [scheduleNode(), httpNode("A", {}), httpNode("B", {})];
    const wf = workflow(nodes, { name: "Count Test" });
    const report = await analyzeWorkflow(wf, defaultConfig);
    expect(report.summary.totalNodes).toBe(3);
  });

  it("severity counts sum to totalViolations", async () => {
    const wf = workflow([
      genericNode("Cmd", `${B}executeCommand`, { command: "ls" }),
      webhookNode("Hook", { authentication: "none" }),
    ]);
    const report = await analyzeWorkflow(wf, { ...defaultConfig, severityThreshold: "low" });
    const summed =
      report.summary.critical +
      report.summary.high +
      report.summary.medium +
      report.summary.low;
    expect(summed).toBe(report.summary.totalViolations);
  });
});

// ─── End-to-end: known bad fixtures ──────────────────────────────────────────

describe("analyzeWorkflow — fixture files", () => {
  it("reports 0 violations on the clean-workflow fixture", async () => {
    const fixture = await import("./fixtures/clean-workflow.json", { assert: { type: "json" } });
    const report = await analyzeWorkflow(fixture.default as never, defaultConfig);
    expect(report.summary.totalViolations).toBe(0);
  });

  it("reports critical violations on the hardcoded-credentials fixture", async () => {
    const fixture = await import("./fixtures/hardcoded-credentials.json", { assert: { type: "json" } });
    const report = await analyzeWorkflow(fixture.default as never, defaultConfig);
    expect(report.summary.critical).toBeGreaterThan(0);
    expect(report.violations.map((v) => v.ruleId)).toContain("SEC-001");
  });

  it("reports critical violations on the dangerous-nodes fixture", async () => {
    const fixture = await import("./fixtures/dangerous-nodes.json", { assert: { type: "json" } });
    const report = await analyzeWorkflow(fixture.default as never, defaultConfig);
    expect(report.summary.critical).toBeGreaterThan(0);
    expect(report.violations.map((v) => v.ruleId)).toContain("DN-001");
    expect(report.violations.map((v) => v.ruleId)).toContain("DN-002");
  });

  it("reports injection violations on the expression-injection fixture", async () => {
    const fixture = await import("./fixtures/expression-injection.json", { assert: { type: "json" } });
    const report = await analyzeWorkflow(fixture.default as never, defaultConfig);
    expect(report.violations.map((v) => v.ruleId)).toContain("EXP-001");
    expect(report.violations.map((v) => v.ruleId)).toContain("EXP-002");
  });
});
