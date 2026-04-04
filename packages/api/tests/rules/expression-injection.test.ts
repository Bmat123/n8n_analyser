import { describe, it } from "vitest";
import { expressionInjectionRules } from "../../src/analyzer/rules/expression-injection.js";
import {
  workflow, webhookNode, codeNode, postgresNode, genericNode,
  run, expectRule, expectNoRule, chain, B,
} from "../helpers.js";

// ─── EXP-001: Unsanitised webhook → code/command ──────────────────────────────

describe("EXP-001 — unsanitised webhook input to code/command node", () => {
  it("fires when webhook feeds directly into a code node with $json.body reference", () => {
    const hook = webhookNode("Inbound", { authentication: "headerAuth" });
    const code = codeNode("Run Script", `const input = $json.body.cmd;\neval(input);`);
    const wf = workflow([hook, code], { connections: chain(hook, code) });
    expectRule(run(expressionInjectionRules, wf), "EXP-001");
  });

  it("fires when webhook feeds into an executeCommand node with $json.body reference", () => {
    const hook = webhookNode("Inbound", { authentication: "headerAuth" });
    const cmd = genericNode("Exec", `${B}executeCommand`, { command: "echo {{ $json.body.input }}" });
    const wf = workflow([hook, cmd], { connections: chain(hook, cmd) });
    expectRule(run(expressionInjectionRules, wf), "EXP-001");
  });

  it("fires when webhook references $json.query in code node", () => {
    const hook = webhookNode("Hook", { authentication: "headerAuth" });
    const code = codeNode("Code", `const q = $json.query.search; return items;`);
    const wf = workflow([hook, code], { connections: chain(hook, code) });
    expectRule(run(expressionInjectionRules, wf), "EXP-001");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire when a Set node sanitises between webhook and code", () => {
    const hook = webhookNode("Hook", { authentication: "headerAuth" });
    const sanitise = genericNode("Sanitise", `${B}set`, {
      values: { string: [{ name: "safeInput", value: "{{ $json.body.name.substring(0, 50) }}" }] },
    });
    const code = codeNode("Code", `const safe = $json.body.safeInput;\nreturn items;`);
    const wf = workflow([hook, sanitise, code], {
      connections: chain(hook, sanitise, code),
    });
    expectNoRule(run(expressionInjectionRules, wf), "EXP-001");
  });

  it("does NOT fire when an IF node sanitises between webhook and code", () => {
    const hook = webhookNode("Hook", { authentication: "headerAuth" });
    const guard = genericNode("Validate", `${B}if`, { conditions: {} });
    const code = codeNode("Code", `const d = $json.body.data;\nreturn items;`);
    const wf = workflow([hook, guard, code], {
      connections: chain(hook, guard, code),
    });
    expectNoRule(run(expressionInjectionRules, wf), "EXP-001");
  });

  it("does NOT fire when the code node does NOT reference $json.body", () => {
    const hook = webhookNode("Hook", { authentication: "headerAuth" });
    const code = codeNode("Code", `return items.map(i => ({ json: { processed: true } }));`);
    const wf = workflow([hook, code], { connections: chain(hook, code) });
    expectNoRule(run(expressionInjectionRules, wf), "EXP-001");
  });

  it("does NOT fire when there is no webhook node in the workflow", () => {
    const code = codeNode("Code", `const x = $json.body.input;\nreturn items;`);
    const wf = workflow([code]);
    expectNoRule(run(expressionInjectionRules, wf), "EXP-001");
  });

  it("does NOT fire when the code node is not reachable from the webhook", () => {
    const hook = webhookNode("Hook", { authentication: "headerAuth" });
    // Code node is in the workflow but not connected to the webhook
    const code = codeNode("Orphan", `const x = $json.body.input;\nreturn items;`);
    const wf = workflow([hook, code], { connections: {} });
    // No path exists from hook to code so EXP-001 should not fire
    expectNoRule(run(expressionInjectionRules, wf), "EXP-001");
  });
});

// ─── EXP-002: Expression interpolated into SQL ───────────────────────────────

describe("EXP-002 — expression interpolated into SQL query", () => {
  it("fires on a postgres node with $json.* directly in a SELECT query", () => {
    const wf = workflow([
      postgresNode("DB", {
        operation: "executeQuery",
        query: "SELECT * FROM users WHERE email = '{{ $json.email }}'",
      }),
    ]);
    expectRule(run(expressionInjectionRules, wf), "EXP-002");
  });

  it("fires on a mysql node with $json.* in a WHERE clause", () => {
    const wf = workflow([
      genericNode("MySQL", `${B}mysql`, {
        operation: "executeQuery",
        query: "SELECT id FROM accounts WHERE username = '{{ $json.username }}'",
      }),
    ]);
    expectRule(run(expressionInjectionRules, wf), "EXP-002");
  });

  it("fires on an INSERT with expression interpolation", () => {
    const wf = workflow([
      postgresNode("DB", {
        query: "INSERT INTO logs (msg) VALUES ('{{ $json.body.message }}')",
      }),
    ]);
    expectRule(run(expressionInjectionRules, wf), "EXP-002");
  });

  it("fires on a code node that builds a SQL string with $json.*", () => {
    const wf = workflow([
      codeNode("Build Query", `const q = \`SELECT * FROM t WHERE id = \${$json.id}\`;\nreturn items;`),
    ]);
    expectRule(run(expressionInjectionRules, wf), "EXP-002");
  });

  // ── False positives ──────────────────────────────────────────────────────

  it("does NOT fire on a parameterised query with no direct interpolation", () => {
    const wf = workflow([
      postgresNode("DB", {
        operation: "executeQuery",
        query: "SELECT * FROM users WHERE email = $1",
        additionalFields: { queryParams: "={{ [$json.email] }}" },
      }),
    ]);
    expectNoRule(run(expressionInjectionRules, wf), "EXP-002");
  });

  it("does NOT fire on a query string with no SQL keywords", () => {
    const wf = workflow([
      postgresNode("DB", {
        query: "{{ $json.customQuery }}",
      }),
    ]);
    // No SQL keyword + expression combo — the expression IS the full query,
    // but the SQL keyword regex won't match a bare expression
    expectNoRule(run(expressionInjectionRules, wf), "EXP-002");
  });

  it("does NOT fire on a non-DB node with SQL-like text", () => {
    const wf = workflow([
      genericNode("Slack", `${B}slack`, { message: "Run SELECT * FROM orders WHERE id = $json.orderId" }),
    ]);
    expectNoRule(run(expressionInjectionRules, wf), "EXP-002");
  });
});
