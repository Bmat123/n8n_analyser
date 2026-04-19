import { describe, it } from "vitest";
import { dataPolicyRules } from "../../src/analyzer/rules/data-policy.js";
import {
  workflow,
  httpNode,
  webhookNode,
  defaultConfig,
  run,
  expectRule,
  expectNoRule,
  expectRuleCount,
} from "../helpers.js";
import type { Config } from "../../src/config.js";

// Config with an allowlist configured
function cfg(hosts: string[]): Config {
  return { ...defaultConfig, approvedEgressHosts: new Set(hosts) };
}

describe("DP-006 — HTTP egress to unapproved host", () => {
  // ── Rule disabled when no allowlist ─────────────────────────────────────────

  it("does not fire when APPROVED_EGRESS_HOSTS is empty (opt-in rule)", () => {
    const wf = workflow([
      httpNode("Call Stripe", { url: "https://api.stripe.com/v1/charges" }),
    ]);
    const v = run(dataPolicyRules, wf, defaultConfig);
    expectNoRule(v, "DP-006");
  });

  // ── True positives ──────────────────────────────────────────────────────────

  it("fires when HTTP node calls a host not in the allowlist", () => {
    const wf = workflow([
      httpNode("Send Data", { url: "https://api.evil.com/collect" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["api.stripe.com"]));
    expectRule(v, "DP-006");
  });

  it("includes the offending hostname in the evidence field", () => {
    const wf = workflow([
      httpNode("Send Data", { url: "https://exfil.example.com/upload" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["api.approved.com"]));
    const violation = expectRule(v, "DP-006");
    if (!violation.evidence?.includes("exfil.example.com")) {
      throw new Error(`Expected evidence to contain hostname, got: ${violation.evidence}`);
    }
  });

  it("fires for each distinct unapproved host in the same workflow", () => {
    const wf = workflow([
      httpNode("Call A", { url: "https://third-party-a.com/api" }),
      httpNode("Call B", { url: "https://third-party-b.com/api" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectRuleCount(v, "DP-006", 2);
  });

  it("fires only once per node even when multiple params contain the same host", () => {
    const wf = workflow([
      httpNode("Multi-param", {
        url: "https://leaky.com/send",
        // Another param on the same node referencing the same host
        options: { redirect: { url: "https://leaky.com/redirect" } },
      }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectRuleCount(v, "DP-006", 1);
  });

  it("fires for http:// URLs (unapproved even if also caught by NET-001)", () => {
    const wf = workflow([
      httpNode("Plain HTTP", { url: "http://unapproved.example.com/data" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectRule(v, "DP-006");
  });

  // ── True negatives ──────────────────────────────────────────────────────────

  it("does not fire when the host is in the allowlist", () => {
    const wf = workflow([
      httpNode("Call Stripe", { url: "https://api.stripe.com/v1/charges" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["api.stripe.com"]));
    expectNoRule(v, "DP-006");
  });

  it("is case-insensitive — allowlist entry matches mixed-case host", () => {
    const wf = workflow([
      httpNode("Call API", { url: "https://API.Stripe.COM/v1/charges" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["api.stripe.com"]));
    expectNoRule(v, "DP-006");
  });

  it("does not fire for disabled HTTP Request nodes", () => {
    const wf = workflow([
      httpNode("Disabled", { url: "https://unapproved.com/data" }, { disabled: true }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectNoRule(v, "DP-006");
  });

  it("does not fire for non-HTTP nodes (e.g. Webhook)", () => {
    const wf = workflow([
      webhookNode("Entry", { path: "my-hook", authentication: "headerAuth" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectNoRule(v, "DP-006");
  });

  it("does not fire for internal/private hosts (those belong to NET-003)", () => {
    const wf = workflow([
      httpNode("Internal Call", { url: "http://192.168.1.50/api" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectNoRule(v, "DP-006");
  });

  it("does not fire for localhost (private host)", () => {
    const wf = workflow([
      httpNode("Localhost", { url: "http://localhost:3000/health" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectNoRule(v, "DP-006");
  });

  it("does not fire for fully dynamic URLs (those belong to NET-004)", () => {
    const wf = workflow([
      httpNode("Dynamic URL", { url: "={{ $json.targetUrl }}" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["approved.com"]));
    expectNoRule(v, "DP-006");
  });

  it("multiple approved hosts — only the unapproved one fires", () => {
    const wf = workflow([
      httpNode("OK Call", { url: "https://api.stripe.com/v1/charges" }),
      httpNode("Bad Call", { url: "https://random-tracker.io/pixel" }),
    ]);
    const v = run(dataPolicyRules, wf, cfg(["api.stripe.com", "api.sendgrid.com"]));
    expectRuleCount(v, "DP-006", 1);
    const viol = expectRule(v, "DP-006");
    if (!viol.evidence?.includes("random-tracker.io")) {
      throw new Error(`Expected evidence to name random-tracker.io, got: ${viol.evidence}`);
    }
  });
});
