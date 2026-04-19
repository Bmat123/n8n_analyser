import { describe, it } from "vitest";
import { dataQualityRules } from "../../src/analyzer/rules/data-quality.js";
import {
  workflow,
  httpNode,
  setNode,
  scheduleNode,
  webhookNode,
  ifNode,
  codeNode,
  chain,
  run,
  expectRule,
  expectNoRule,
  defaultConfig,
} from "../helpers.js";

// ─── DQ-009 — No input validation on webhook ──────────────────────────────────

describe("DQ-009 — webhook no input validation", () => {
  it("fires when webhook has no IF or validation Code downstream", () => {
    const webhook = webhookNode("Receive Order");
    const set = setNode("Store");
    const wf = workflow([webhook, set], { connections: chain(webhook, set) });
    expectRule(run(dataQualityRules, wf), "DQ-009");
  });

  it("does not fire when IF is immediately downstream", () => {
    const webhook = webhookNode("Receive Order");
    const check = ifNode("Validate Fields");
    const wf = workflow([webhook, check], { connections: chain(webhook, check) });
    expectNoRule(run(dataQualityRules, wf), "DQ-009");
  });

  it("does not fire when Code node with throw is downstream", () => {
    const webhook = webhookNode("Receive Order");
    const validate = codeNode("Validate", "if (!$json.orderId) throw new Error('Missing orderId');");
    const wf = workflow([webhook, validate], { connections: chain(webhook, validate) });
    expectNoRule(run(dataQualityRules, wf), "DQ-009");
  });

  it("does not fire on disabled webhook", () => {
    const webhook = webhookNode("Receive Order", {}, { disabled: true });
    const wf = workflow([webhook]);
    expectNoRule(run(dataQualityRules, wf), "DQ-009");
  });
});

// ─── DQ-010 — Date/time expression without timezone ───────────────────────────

describe("DQ-010 — date expression without timezone", () => {
  it("fires on new Date() without timezone hint", () => {
    const wf = workflow([
      setNode("Set Date", {
        values: { string: [{ name: "now", value: "{{ new Date().toISOString() }}" }] },
      }),
    ]);
    expectRule(run(dataQualityRules, wf), "DQ-010");
  });

  it("fires on Date.now() without timezone", () => {
    const wf = workflow([
      setNode("Set Timestamp", {
        values: { string: [{ name: "ts", value: "{{ Date.now() }}" }] },
      }),
    ]);
    expectRule(run(dataQualityRules, wf), "DQ-010");
  });

  it("does not fire when UTC is specified", () => {
    const wf = workflow([
      setNode("Set Date", {
        values: { string: [{ name: "now", value: "{{ DateTime.now().toUTC().toISO() }}" }] },
      }),
    ]);
    expectNoRule(run(dataQualityRules, wf), "DQ-010");
  });

  it("does not fire when timezone is explicitly set", () => {
    const wf = workflow([
      setNode("Set Date", {
        values: { string: [{ name: "now", value: "{{ DateTime.now().setZone('Europe/Berlin').toISO() }}" }] },
      }),
    ]);
    expectNoRule(run(dataQualityRules, wf), "DQ-010");
  });

  it("does not fire on disabled nodes", () => {
    const wf = workflow([
      setNode("Set Date", {
        values: { string: [{ name: "now", value: "{{ new Date().toISOString() }}" }] },
      }, { disabled: true }),
    ]);
    expectNoRule(run(dataQualityRules, wf), "DQ-010");
  });
});

// ─── DQ-012 — Currency arithmetic without rounding ───────────────────────────

describe("DQ-012 — currency arithmetic without rounding", () => {
  it("fires on price * quantity without Math.round", () => {
    const wf = workflow([
      setNode("Calculate", {
        values: { string: [{ name: "total", value: "{{ $json.price * $json.quantity }}" }] },
      }),
    ]);
    expectRule(run(dataQualityRules, wf), "DQ-012");
  });

  it("does not fire when Math.round is used", () => {
    const wf = workflow([
      setNode("Calculate", {
        values: { string: [{ name: "total", value: "{{ Math.round($json.price * $json.quantity * 100) / 100 }}" }] },
      }),
    ]);
    expectNoRule(run(dataQualityRules, wf), "DQ-012");
  });

  it("does not fire when .toFixed is used", () => {
    const wf = workflow([
      setNode("Calculate", {
        values: { string: [{ name: "total", value: "{{ ($json.price * $json.quantity).toFixed(2) }}" }] },
      }),
    ]);
    expectNoRule(run(dataQualityRules, wf), "DQ-012");
  });

  it("does not fire when currencyFieldNames is empty", () => {
    const wf = workflow([
      setNode("Calculate", {
        values: { string: [{ name: "total", value: "{{ $json.price * 1.1 }}" }] },
      }),
    ]);
    const cfg = { ...defaultConfig, currencyFieldNames: new Set<string>() };
    expectNoRule(run(dataQualityRules, wf, cfg), "DQ-012");
  });
});

// ─── DQ-013 — Hardcoded business logic values (advisory) ─────────────────────

describe("DQ-013 — hardcoded business logic values", () => {
  it("fires when IF node compares discount against hardcoded number", () => {
    const wf = workflow([
      ifNode("Check Discount", {
        conditions: { string: [{ value1: "{{ $json.discount }}", operation: "larger", value2: "10" }] },
      }),
    ]);
    expectRule(run(dataQualityRules, wf), "DQ-013");
  });

  it("does not fire when includeAdvisory is false", () => {
    const wf = workflow([
      ifNode("Check Discount", {
        conditions: { string: [{ value1: "{{ $json.discount }}", operation: "larger", value2: "10" }] },
      }),
    ]);
    const cfg = { ...defaultConfig, includeAdvisory: false };
    expectNoRule(run(dataQualityRules, wf, cfg), "DQ-013");
  });
});
