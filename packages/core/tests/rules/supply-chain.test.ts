import { describe, it } from "vitest";
import { supplyChainRules } from "../../src/analyzer/rules/supply-chain.js";
import {
  workflow, httpNode, codeNode, genericNode, communityNode, scheduleNode,
  run, expectRule, expectNoRule, B,
} from "../helpers.js";

// ─── SC-001: n8n self-API call ────────────────────────────────────────────────

describe("SC-001 — HTTP Request targeting n8n local API", () => {
  it("fires on localhost:5678 URL", () => {
    const wf = workflow([
      httpNode("Self Call", { url: "http://localhost:5678/api/v1/workflows" }),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-001");
  });

  it("fires on 127.0.0.1:5678", () => {
    const wf = workflow([
      httpNode("Self Call", { url: "http://127.0.0.1:5678/api/v1/credentials" }),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-001");
  });

  it("fires when /api/v1/ path is on localhost without explicit port", () => {
    const wf = workflow([
      httpNode("Self Call", { url: "http://localhost/api/v1/executions" }),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on external HTTPS URLs", () => {
    const wf = workflow([
      httpNode("External", { url: "https://api.example.com/v1/data" }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-001");
  });

  it("does NOT fire on localhost URLs that are not the n8n API", () => {
    const wf = workflow([
      httpNode("Local Service", { url: "http://localhost:8080/health" }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-001");
  });

  it("does NOT fire on disabled nodes", () => {
    const wf = workflow([
      httpNode("Disabled", { url: "http://localhost:5678/api/v1/workflows" }, { disabled: true }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-001");
  });
});

// ─── SC-002: Community node detection ────────────────────────────────────────

describe("SC-002 — community (third-party) node detected", () => {
  it("fires on a non-official node namespace", () => {
    const wf = workflow([
      communityNode("Custom Tool", "n8n-nodes-custom-crm.crmAction"),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-002");
  });

  it("fires once per unique community node type even with multiple instances", () => {
    const wf = workflow([
      communityNode("CRM 1", "n8n-nodes-vendor.action"),
      communityNode("CRM 2", "n8n-nodes-vendor.action"),
    ]);
    // Should fire exactly once (deduplicated by type)
    const violations = run(supplyChainRules, wf).filter((v) => v.ruleId === "SC-002");
    if (violations.length !== 1) {
      throw new Error(`Expected 1 SC-002 violation but got ${violations.length}`);
    }
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on n8n-nodes-base.* nodes", () => {
    const wf = workflow([
      httpNode("HTTP", { url: "https://api.example.com" }),
      scheduleNode(),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-002");
  });

  it("does NOT fire on @n8n/n8n-nodes-langchain.* nodes", () => {
    const wf = workflow([
      genericNode("AI Agent", "@n8n/n8n-nodes-langchain.agent", {}),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-002");
  });

  it("does NOT fire on disabled community nodes", () => {
    const wf = workflow([
      communityNode("Off", "n8n-nodes-vendor.action", {}, { disabled: true }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-002");
  });
});

// ─── SC-003: Dangerous Code node patterns ────────────────────────────────────

describe("SC-003 — dangerous runtime patterns in Code node", () => {
  it("fires on require() in a code node", () => {
    const wf = workflow([
      codeNode("Exec", `const fs = require('fs');\nreturn items;`),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-003");
  });

  it("fires on process.env access in a code node", () => {
    const wf = workflow([
      codeNode("Leak", `const key = process.env.API_KEY;\nreturn items;`),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-003");
  });

  it("fires on child_process reference", () => {
    const wf = workflow([
      codeNode("Shell", `const { exec } = require('child_process');\nexec('ls');`),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-003");
  });

  it("fires on eval() call", () => {
    const wf = workflow([
      codeNode("Eval", `eval($json.body.code);`),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-003");
  });

  it("fires on new Function() constructor", () => {
    const wf = workflow([
      codeNode("FnCtor", `const fn = new Function('return process')();\nreturn items;`),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-003");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on safe code with no dangerous patterns", () => {
    const wf = workflow([
      codeNode("Safe", `return items.map(i => ({ json: { ...i.json, processed: true } }));`),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-003");
  });

  it("does NOT fire on disabled code nodes", () => {
    const wf = workflow([
      codeNode("Off", `const x = require('fs');`, { disabled: true }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-003");
  });

  it("does NOT fire on non-code node types", () => {
    const wf = workflow([
      httpNode("HTTP", { url: "https://api.example.com", body: "require('fs')" }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-003");
  });
});

// ─── SC-004: HTTP Request to raw content hosts ───────────────────────────────

describe("SC-004 — HTTP Request fetches from raw-content hosting site", () => {
  it("fires on raw.githubusercontent.com", () => {
    const wf = workflow([
      httpNode("Fetch Script", { url: "https://raw.githubusercontent.com/user/repo/main/script.js" }),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-004");
  });

  it("fires on pastebin.com", () => {
    const wf = workflow([
      httpNode("Fetch Config", { url: "https://pastebin.com/raw/abc123" }),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-004");
  });

  it("fires on hastebin.com", () => {
    const wf = workflow([
      httpNode("Fetch", { url: "https://hastebin.com/someid.js" }),
    ]);
    expectRule(run(supplyChainRules, wf), "SC-004");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on github.com (not raw content)", () => {
    const wf = workflow([
      httpNode("GitHub API", { url: "https://api.github.com/repos/user/repo" }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-004");
  });

  it("does NOT fire on regular external APIs", () => {
    const wf = workflow([
      httpNode("API", { url: "https://api.stripe.com/v1/charges" }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-004");
  });

  it("does NOT fire on disabled nodes", () => {
    const wf = workflow([
      httpNode("Off", { url: "https://raw.githubusercontent.com/user/repo/main/x.js" }, { disabled: true }),
    ]);
    expectNoRule(run(supplyChainRules, wf), "SC-004");
  });
});
