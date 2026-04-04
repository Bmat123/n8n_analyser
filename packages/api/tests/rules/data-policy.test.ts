import { describe, it } from "vitest";
import { dataPolicyRules } from "../../src/analyzer/rules/data-policy.js";
import {
  workflow, httpNode, webhookNode, codeNode, postgresNode,
  genericNode, scheduleNode, errorTriggerNode,
  run, expectRule, expectNoRule, defaultConfig, B,
} from "../helpers.js";

// ─── DP-001: Unauthenticated webhook ─────────────────────────────────────────

describe("DP-001 — unauthenticated webhook", () => {
  it("fires when authentication is 'none'", () => {
    const wf = workflow([webhookNode("Hook", { authentication: "none" })]);
    expectRule(run(dataPolicyRules, wf), "DP-001");
  });

  it("fires when authentication field is absent", () => {
    const wf = workflow([webhookNode("Hook", { path: "trigger" })]);
    expectRule(run(dataPolicyRules, wf), "DP-001");
  });

  it("fires when authentication is an empty string", () => {
    const wf = workflow([webhookNode("Hook", { authentication: "" })]);
    expectRule(run(dataPolicyRules, wf), "DP-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when authentication is 'headerAuth'", () => {
    const wf = workflow([webhookNode("Secure Hook", { authentication: "headerAuth" })]);
    expectNoRule(run(dataPolicyRules, wf), "DP-001");
  });

  it("does NOT fire when authentication is 'basicAuth'", () => {
    const wf = workflow([webhookNode("Secure Hook", { authentication: "basicAuth" })]);
    expectNoRule(run(dataPolicyRules, wf), "DP-001");
  });

  it("does NOT fire on a non-webhook node", () => {
    const wf = workflow([scheduleNode()]);
    expectNoRule(run(dataPolicyRules, wf), "DP-001");
  });

  it("does NOT fire on a disabled unauthenticated webhook", () => {
    const wf = workflow([webhookNode("Disabled", { authentication: "none" }, { disabled: true })]);
    expectNoRule(run(dataPolicyRules, wf), "DP-001");
  });
});

// ─── DP-002: PII in outbound HTTP request ─────────────────────────────────────

describe("DP-002 — PII field in outbound HTTP request", () => {
  const piiFields = ["email", "firstName", "lastName", "phone", "ssn",
                     "nationalId", "dateOfBirth", "iban", "creditCard", "passport"];

  for (const field of piiFields) {
    it(`fires on $json.${field} in a POST body`, () => {
      const wf = workflow([
        httpNode("Send PII", {
          requestMethod: "POST",
          body: { value: `{{ $json.${field} }}` },
        }),
      ]);
      expectRule(run(dataPolicyRules, wf), "DP-002");
    });
  }

  it("fires on PII in a PUT request", () => {
    const wf = workflow([
      httpNode("Update User", {
        requestMethod: "PUT",
        body: { email: "{{ $json.email }}", phone: "{{ $json.phone }}" },
      }),
    ]);
    expectRule(run(dataPolicyRules, wf), "DP-002");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a GET request that references PII", () => {
    // GET requests don't normally send a body with PII
    const wf = workflow([
      httpNode("Fetch User", {
        requestMethod: "GET",
        url: "https://api.example.com/users/{{ $json.email }}",
      }),
    ]);
    expectNoRule(run(dataPolicyRules, wf), "DP-002");
  });

  it("does NOT fire when the POST body has no PII fields", () => {
    const wf = workflow([
      httpNode("Post Data", {
        requestMethod: "POST",
        body: { orderId: "{{ $json.orderId }}", amount: "{{ $json.amount }}" },
      }),
    ]);
    expectNoRule(run(dataPolicyRules, wf), "DP-002");
  });

  it("does NOT fire when field name contains 'email' as a substring of a non-PII field", () => {
    // emailTemplateId is NOT a PII field — the rule uses word-boundary matching
    const wf = workflow([
      httpNode("Send", {
        requestMethod: "POST",
        body: { value: "{{ $json.emailTemplateId }}" },
      }),
    ]);
    expectNoRule(run(dataPolicyRules, wf), "DP-002");
  });
});

// ─── DP-003: Unapproved database host ────────────────────────────────────────

describe("DP-003 — unapproved database host", () => {
  it("fires on a postgres node with an unapproved host", () => {
    const wf = workflow([postgresNode("DB", { host: "db.external.com" })]);
    expectRule(run(dataPolicyRules, wf), "DP-003");
  });

  it("fires on any DB node when approved list is empty", () => {
    const wf = workflow([postgresNode("DB", { host: "db.internal" })]);
    expectRule(run(dataPolicyRules, wf), "DP-003");
  });

  it("does NOT fire when the host is in the approved list", () => {
    const cfg = { ...defaultConfig, approvedDbHosts: new Set(["db.internal", "postgres.prod"]) };
    const wf = workflow([postgresNode("DB", { host: "db.internal" })]);
    expectNoRule(run(dataPolicyRules, wf, cfg), "DP-003");
  });

  it("does NOT fire when no static host is present (credential-referenced)", () => {
    const wf = workflow([postgresNode("DB", { operation: "executeQuery" })]);
    expectNoRule(run(dataPolicyRules, wf), "DP-003");
  });

  it("does NOT fire on non-DB nodes", () => {
    const wf = workflow([scheduleNode()]);
    expectNoRule(run(dataPolicyRules, wf), "DP-003");
  });

  it("is case-insensitive for approved host matching", () => {
    const cfg = { ...defaultConfig, approvedDbHosts: new Set(["DB.INTERNAL"]) };
    const wf = workflow([postgresNode("DB", { host: "db.internal" })]);
    expectNoRule(run(dataPolicyRules, wf, cfg), "DP-003");
  });
});

// ─── DP-004: console.log in code node ────────────────────────────────────────

describe("DP-004 — console.log in code node", () => {
  it("fires on console.log", () => {
    const wf = workflow([codeNode("Transform", `const x = items[0].json;\nconsole.log(x);\nreturn items;`)]);
    expectRule(run(dataPolicyRules, wf), "DP-004");
  });

  it("fires on console.error", () => {
    const wf = workflow([codeNode("Transform", `console.error('failed', $json);`)]);
    expectRule(run(dataPolicyRules, wf), "DP-004");
  });

  it("fires on console.warn", () => {
    const wf = workflow([codeNode("Transform", `console.warn('warning', items);`)]);
    expectRule(run(dataPolicyRules, wf), "DP-004");
  });

  it("fires on Function node type as well", () => {
    const wf = workflow([genericNode("Fn", `${B}function`, { functionCode: `console.log(items);` })]);
    expectRule(run(dataPolicyRules, wf), "DP-004");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a code node with no console calls", () => {
    const wf = workflow([codeNode("Clean", `return items.map(i => ({ json: { ...i.json, done: true } }));`)]);
    expectNoRule(run(dataPolicyRules, wf), "DP-004");
  });

  it("does NOT fire on a string containing 'console.log' in a non-code node", () => {
    const wf = workflow([
      webhookNode("Docs", { description: "Use console.log for debugging" }),
    ]);
    expectNoRule(run(dataPolicyRules, wf), "DP-004");
  });

  it("does NOT fire on a disabled code node", () => {
    const wf = workflow([codeNode("Disabled", `console.log('data');`, { disabled: true })]);
    expectNoRule(run(dataPolicyRules, wf), "DP-004");
  });
});

// ─── DP-005: No error handler ─────────────────────────────────────────────────

describe("DP-005 — no error handler with external data", () => {
  it("fires when workflow has an HTTP node but no error trigger", () => {
    const wf = workflow([scheduleNode(), httpNode("Fetch", { url: "https://api.example.com" })]);
    expectRule(run(dataPolicyRules, wf), "DP-005");
  });

  it("fires when workflow has a webhook but no error trigger", () => {
    const wf = workflow([webhookNode("Hook", { authentication: "headerAuth" })]);
    expectRule(run(dataPolicyRules, wf), "DP-005");
  });

  it("fires when workflow has a postgres node but no error trigger", () => {
    const wf = workflow([scheduleNode(), postgresNode("DB", { host: "db.example.com" })]);
    expectRule(run(dataPolicyRules, wf), "DP-005");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when an error trigger is present", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Fetch", { url: "https://api.example.com" }),
      errorTriggerNode(),
    ]);
    expectNoRule(run(dataPolicyRules, wf), "DP-005");
  });

  it("does NOT fire on a workflow with no external data nodes", () => {
    const wf = workflow([scheduleNode(), codeNode("Transform", "return items;")]);
    expectNoRule(run(dataPolicyRules, wf), "DP-005");
  });

  it("does NOT fire on an empty workflow", () => {
    const wf = workflow([]);
    expectNoRule(run(dataPolicyRules, wf), "DP-005");
  });
});
