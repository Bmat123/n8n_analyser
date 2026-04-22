import { describe, it } from "vitest";
import { dataFlowRules } from "../../src/analyzer/rules/data-flow.js";
import {
  workflow, webhookNode, postgresNode, setNode, genericNode,
  respondToWebhookNode, slackNode, googleSheetsNode, chain,
  run, expectRule, expectNoRule, B,
} from "../helpers.js";

// ─── DF-001: Webhook response echoes full $json ───────────────────────────────

describe("DF-001 — webhook response echoes full payload", () => {
  it("fires when responseBody is ={{ $json }}", () => {
    const wf = workflow([
      respondToWebhookNode("Respond", { responseBody: "={{ $json }}" }),
    ]);
    expectRule(run(dataFlowRules, wf), "DF-001");
  });

  it("fires when responseBody uses JSON.stringify($json)", () => {
    const wf = workflow([
      respondToWebhookNode("Respond", {
        responseBody: "={{ JSON.stringify($json) }}",
      }),
    ]);
    expectRule(run(dataFlowRules, wf), "DF-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when responseBody selects a specific field", () => {
    const wf = workflow([
      respondToWebhookNode("Respond", {
        responseBody: '={{ JSON.stringify({ status: "ok", id: $json.id }) }}',
      }),
    ]);
    expectNoRule(run(dataFlowRules, wf), "DF-001");
  });

  it("does NOT fire on a static JSON response", () => {
    const wf = workflow([
      respondToWebhookNode("Respond", { responseBody: '{"status":"ok"}' }),
    ]);
    expectNoRule(run(dataFlowRules, wf), "DF-001");
  });

  it("does NOT fire on disabled nodes", () => {
    const wf = workflow([
      respondToWebhookNode("Off", { responseBody: "={{ $json }}" }, { disabled: true }),
    ]);
    expectNoRule(run(dataFlowRules, wf), "DF-001");
  });

  it("does NOT fire on non-respondToWebhook nodes", () => {
    const wf = workflow([
      genericNode("HTTP Out", `${B}httpRequest`, { body: "={{ $json }}" }),
    ]);
    expectNoRule(run(dataFlowRules, wf), "DF-001");
  });
});

// ─── DF-002: DB → cloud write without field filter ───────────────────────────

describe("DF-002 — unfiltered database data flows to cloud write destination", () => {
  it("fires when Postgres is connected directly to Google Sheets", () => {
    const db = postgresNode("DB Read", { operation: "select" });
    const sheets = googleSheetsNode("Export", { operation: "appendOrUpdate" });
    const wf = workflow([db, sheets], { connections: chain(db, sheets) });
    expectRule(run(dataFlowRules, wf), "DF-002");
  });

  it("fires when Postgres is connected directly to an email node", () => {
    const db = postgresNode("DB Read", {});
    const email = genericNode("Send Email", `${B}emailSend`, {});
    const wf = workflow([db, email], { connections: chain(db, email) });
    expectRule(run(dataFlowRules, wf), "DF-002");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when a Set node filters between DB and Sheets", () => {
    const db = postgresNode("DB", {});
    const filter = setNode("Filter Fields", {
      values: { string: [{ name: "name", value: "={{ $json.name }}" }] },
    });
    const sheets = googleSheetsNode("Sheets", {});
    const wf = workflow([db, filter, sheets], {
      connections: chain(db, filter, sheets),
    });
    expectNoRule(run(dataFlowRules, wf), "DF-002");
  });

  it("does NOT fire when there is no path from DB to cloud write", () => {
    const db = postgresNode("DB", {});
    const sheets = googleSheetsNode("Sheets", {}); // disconnected
    const wf = workflow([db, sheets], { connections: {} });
    expectNoRule(run(dataFlowRules, wf), "DF-002");
  });

  it("does NOT fire when there are no cloud write nodes", () => {
    const db = postgresNode("DB", {});
    const slack = slackNode("Notify", {});
    const wf = workflow([db, slack], { connections: chain(db, slack) });
    // Slack is not a cloud *write* node (DF-003 covers that)
    expectNoRule(run(dataFlowRules, wf), "DF-002");
  });
});

// ─── DF-003: Chat node receives DB/webhook data ───────────────────────────────

describe("DF-003 — database or webhook data flows into chat node", () => {
  it("fires when Postgres is connected to Slack", () => {
    const db = postgresNode("DB", {});
    const slack = slackNode("Notify", {});
    const wf = workflow([db, slack], { connections: chain(db, slack) });
    expectRule(run(dataFlowRules, wf), "DF-003");
  });

  it("fires when a webhook is connected to a Telegram node", () => {
    const hook = webhookNode("Trigger", { authentication: "headerAuth" });
    const tg = genericNode("Send TG", `${B}telegram`, {});
    const wf = workflow([hook, tg], { connections: chain(hook, tg) });
    expectRule(run(dataFlowRules, wf), "DF-003");
  });

  it("fires when DB data reaches Slack via an intermediate node", () => {
    const db = postgresNode("DB", {});
    const transform = genericNode("Transform", `${B}set`, {});
    const slack = slackNode("Notify", {});
    const wf = workflow([db, transform, slack], {
      connections: chain(db, transform, slack),
    });
    expectRule(run(dataFlowRules, wf), "DF-003");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when Slack has no DB/webhook upstream", () => {
    const slack = slackNode("Notify", { message: "Deployment complete" });
    const wf = workflow([slack], { connections: {} });
    expectNoRule(run(dataFlowRules, wf), "DF-003");
  });

  it("does NOT fire when there are no chat nodes", () => {
    const db = postgresNode("DB", {});
    const sheets = googleSheetsNode("Export", {});
    const wf = workflow([db, sheets], { connections: chain(db, sheets) });
    expectNoRule(run(dataFlowRules, wf), "DF-003");
  });

  it("does NOT fire on disconnected source and chat nodes", () => {
    const db = postgresNode("DB", {});
    const slack = slackNode("Notify", {}); // not connected
    const wf = workflow([db, slack], { connections: {} });
    expectNoRule(run(dataFlowRules, wf), "DF-003");
  });
});
