import { describe, it } from "vitest";
import { credentialsRules } from "../../src/analyzer/rules/credentials.js";
import {
  workflow, httpNode, setNode, scheduleNode,
  run, expectRule, expectNoRule,
} from "../helpers.js";

// ─── SEC-001: Hardcoded secret ────────────────────────────────────────────────

describe("SEC-001 — hardcoded secret", () => {
  it("fires on a Bearer token in an Authorization header value", () => {
    const wf = workflow([
      httpNode("Call API", {
        headerParameters: { values: [{ name: "Authorization", value: "Bearer sk-abcdef1234567890abcdef1234567890abc" }] },
      }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on an OpenAI key pattern (sk-...)", () => {
    const wf = workflow([
      httpNode("GPT Call", { url: "https://api.openai.com", bodyParameters: { values: [{ name: "key", value: "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" }] } }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on an Anthropic key pattern (sk-ant-...)", () => {
    const wf = workflow([
      httpNode("Claude Call", { bodyParameters: { values: [{ name: "key", value: "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXX" }] } }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on a GitHub PAT (ghp_...)", () => {
    const wf = workflow([
      // token must be exactly ghp_ + 36 alphanumeric chars
      httpNode("GitHub", { headers: { Authorization: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234" } }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on a Slack token (xoxb-...)", () => {
    const wf = workflow([
      httpNode("Slack", { token: "xoxb-123456789012-123456789012-ABCDEFGHIJKLMNOPQRSTUVWX" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on an AWS access key (AKIA...)", () => {
    const wf = workflow([
      httpNode("S3", { accessKey: "AKIAIOSFODNN7EXAMPLE" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on a Stripe live key (sk_live_...)", () => {
    const wf = workflow([
      httpNode("Stripe", { url: "https://api.stripe.com", body: { key: "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX" } }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on a high-entropy value in a field named 'password'", () => {
    const wf = workflow([
      httpNode("Login", { password: "xK9#mP2$vL7nQ4wR8sT1uY6bC3dF5gH0" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  it("fires on a high-entropy value in a field named 'apiKey'", () => {
    const wf = workflow([
      httpNode("Auth", { apiKey: "aB3cD9eF2gH7iJ4kL1mN6oP8qR5sT0uV" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a plain URL with no secrets", () => {
    const wf = workflow([
      httpNode("Safe Call", { url: "https://api.example.com/data" }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-001");
  });

  it("does NOT fire on a short low-entropy string in an apiKey field", () => {
    const wf = workflow([
      httpNode("Safe", { apiKey: "demo" }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-001");
  });

  it("does NOT fire on a node with no parameters", () => {
    const wf = workflow([scheduleNode()]);
    expectNoRule(run(credentialsRules, wf), "SEC-001");
  });

  it("does NOT fire on a disabled node with hardcoded key", () => {
    const wf = workflow([
      httpNode("Disabled", { token: "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX" }, { disabled: true }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-001");
  });
});

// ─── SEC-002: Token in URL query string ───────────────────────────────────────

describe("SEC-002 — credential in URL query string", () => {
  it("fires on ?api_key= in URL", () => {
    const wf = workflow([
      httpNode("API", { url: "https://api.example.com/data?api_key=supersecret123" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-002");
  });

  it("fires on ?token= in URL", () => {
    const wf = workflow([
      httpNode("API", { url: "https://api.example.com/resource?token=abc123def456" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-002");
  });

  it("fires on ?secret= in URL", () => {
    const wf = workflow([
      httpNode("API", { url: "https://api.example.com/resource?secret=mysecretvalue" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-002");
  });

  it("fires on ?password= in URL", () => {
    const wf = workflow([
      httpNode("API", { url: "https://api.example.com/login?password=hunter2" }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-002");
  });

  it("fires on ?access_token= in URL", () => {
    const wf = workflow([
      httpNode("OAuth", { url: "https://graph.facebook.com/me?access_token=EAABsbCS..." }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-002");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a URL with only safe query params", () => {
    const wf = workflow([
      httpNode("Safe", { url: "https://api.example.com/users?page=1&limit=20&sort=asc" }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-002");
  });

  it("does NOT fire on an HTTPS URL with no query string", () => {
    const wf = workflow([
      httpNode("Safe", { url: "https://api.example.com/data" }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-002");
  });

  it("does NOT fire on a plain string that is not a URL", () => {
    const wf = workflow([
      httpNode("Safe", { description: "Use token= parameter in headers" }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-002");
  });

  it("does NOT fire on a fully dynamic URL expression", () => {
    const wf = workflow([
      httpNode("Dynamic", { url: "{{ $json.apiUrl }}" }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-002");
  });
});

// ─── SEC-003: Credential in Set node ─────────────────────────────────────────

describe("SEC-003 — credential value in Set node", () => {
  it("fires on a Set node with a field named 'apiKey'", () => {
    const wf = workflow([
      setNode("Prepare Auth", {
        values: { string: [{ name: "apiKey", value: "some-value-here" }] },
      }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-003");
  });

  it("fires on a Set node with a field named 'password'", () => {
    const wf = workflow([
      setNode("Set Creds", {
        values: { string: [{ name: "password", value: "hunter2" }] },
      }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-003");
  });

  it("fires on a Set node whose value contains a secret pattern", () => {
    const wf = workflow([
      setNode("Set Header", {
        values: { string: [{ name: "authHeader", value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234" }] },
      }),
    ]);
    expectRule(run(credentialsRules, wf), "SEC-003");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a Set node with innocent fields", () => {
    const wf = workflow([
      setNode("Set User", {
        values: { string: [{ name: "username", value: "john.doe" }, { name: "region", value: "eu-west-1" }] },
      }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-003");
  });

  it("does NOT fire on an HTTP node (only checks Set nodes)", () => {
    const wf = workflow([
      httpNode("Call API", { apiKey: "demo" }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-003");
  });

  it("does NOT fire on a disabled Set node", () => {
    const wf = workflow([
      setNode("Disabled", { values: { string: [{ name: "apiKey", value: "secret" }] } }, { disabled: true }),
    ]);
    expectNoRule(run(credentialsRules, wf), "SEC-003");
  });
});
