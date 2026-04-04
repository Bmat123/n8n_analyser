import { describe, it } from "vitest";
import { networkRules } from "../../src/analyzer/rules/network.js";
import {
  workflow, httpNode, scheduleNode,
  run, expectRule, expectNoRule,
} from "../helpers.js";

// ─── NET-001: HTTP (unencrypted) ──────────────────────────────────────────────

describe("NET-001 — unencrypted HTTP", () => {
  it("fires on http:// URL to an external host", () => {
    const wf = workflow([httpNode("Call", { url: "http://api.example.com/data" })]);
    expectRule(run(networkRules, wf), "NET-001");
  });

  it("fires on mixed-case http://", () => {
    const wf = workflow([httpNode("Call", { url: "HTTP://API.EXAMPLE.COM/data" })]);
    expectRule(run(networkRules, wf), "NET-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on https://", () => {
    const wf = workflow([httpNode("Safe", { url: "https://api.example.com/data" })]);
    expectNoRule(run(networkRules, wf), "NET-001");
  });

  it("does NOT fire on http://localhost (covered by NET-003 instead)", () => {
    const wf = workflow([httpNode("Local", { url: "http://localhost:3000/health" })]);
    expectNoRule(run(networkRules, wf), "NET-001");
  });

  it("does NOT fire on http://127.0.0.1 (covered by NET-003)", () => {
    const wf = workflow([httpNode("Loop", { url: "http://127.0.0.1/api" })]);
    expectNoRule(run(networkRules, wf), "NET-001");
  });

  it("does NOT fire on a non-HTTP-request node type", () => {
    const wf = workflow([scheduleNode()]);
    expectNoRule(run(networkRules, wf), "NET-001");
  });

  it("does NOT fire on a fully dynamic URL expression", () => {
    const wf = workflow([httpNode("Dynamic", { url: "={{ $json.url }}" })]);
    expectNoRule(run(networkRules, wf), "NET-001");
  });
});

// ─── NET-002: SSL verification disabled ──────────────────────────────────────

describe("NET-002 — SSL verification disabled", () => {
  it("fires on allowUnauthorizedCerts: true at top level", () => {
    const wf = workflow([httpNode("Call", { url: "https://api.example.com", allowUnauthorizedCerts: true })]);
    expectRule(run(networkRules, wf), "NET-002");
  });

  it("fires on allowUnauthorizedCerts: true inside options object", () => {
    const wf = workflow([httpNode("Call", { url: "https://api.example.com", options: { allowUnauthorizedCerts: true } })]);
    expectRule(run(networkRules, wf), "NET-002");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when allowUnauthorizedCerts is false", () => {
    const wf = workflow([httpNode("Safe", { url: "https://api.example.com", allowUnauthorizedCerts: false })]);
    expectNoRule(run(networkRules, wf), "NET-002");
  });

  it("does NOT fire when allowUnauthorizedCerts is absent", () => {
    const wf = workflow([httpNode("Safe", { url: "https://api.example.com" })]);
    expectNoRule(run(networkRules, wf), "NET-002");
  });

  it("does NOT fire on a disabled node", () => {
    const wf = workflow([httpNode("Disabled", { allowUnauthorizedCerts: true }, { disabled: true })]);
    expectNoRule(run(networkRules, wf), "NET-002");
  });
});

// ─── NET-003: Private / internal IP ──────────────────────────────────────────

describe("NET-003 — private/internal host (SSRF risk)", () => {
  const privateHosts = [
    ["10.x.x.x", "http://10.0.0.1/api"],
    ["192.168.x.x", "http://192.168.1.100/api"],
    ["172.16-31 range", "http://172.20.0.5/api"],
    ["localhost", "http://localhost:8080/internal"],
    ["127.0.0.1", "http://127.0.0.1/health"],
    ["169.254 link-local", "http://169.254.169.254/latest/meta-data"],
    [".internal suffix", "http://db.prod.internal/api"],
    [".local suffix", "http://service.local/api"],
  ];

  for (const [label, url] of privateHosts) {
    it(`fires on ${label}: ${url}`, () => {
      const wf = workflow([httpNode("Call", { url })]);
      expectRule(run(networkRules, wf), "NET-003");
    });
  }

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a public HTTPS URL", () => {
    const wf = workflow([httpNode("Public", { url: "https://api.example.com/data" })]);
    expectNoRule(run(networkRules, wf), "NET-003");
  });

  it("does NOT fire on 10.x.x.x-like string that is not a URL", () => {
    // This is a description field, not a URL
    const wf = workflow([httpNode("Safe", { description: "Server is at 10.0.0.1" })]);
    expectNoRule(run(networkRules, wf), "NET-003");
  });
});

// ─── NET-004: Fully dynamic URL ───────────────────────────────────────────────

describe("NET-004 — fully dynamic URL", () => {
  it("fires on a URL that is entirely an expression", () => {
    const wf = workflow([httpNode("Dynamic", { url: "={{ $json.targetUrl }}" })]);
    expectRule(run(networkRules, wf), "NET-004");
  });

  it("fires on a URL expression without leading =", () => {
    const wf = workflow([httpNode("Dynamic", { url: "{{ $json.targetUrl }}" })]);
    expectRule(run(networkRules, wf), "NET-004");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a static URL", () => {
    const wf = workflow([httpNode("Static", { url: "https://api.example.com/endpoint" })]);
    expectNoRule(run(networkRules, wf), "NET-004");
  });

  it("does NOT fire on a URL with a static host and dynamic path", () => {
    // Only the path is dynamic — the host is known
    const wf = workflow([httpNode("Mixed", { url: "https://api.example.com/users/{{ $json.userId }}" })]);
    expectNoRule(run(networkRules, wf), "NET-004");
  });
});
