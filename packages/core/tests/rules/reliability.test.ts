import { describe, it } from "vitest";
import { reliabilityRules } from "../../src/analyzer/rules/reliability.js";
import {
  workflow,
  httpNode,
  setNode,
  scheduleNode,
  postgresNode,
  mysqlNode,
  ifNode,
  codeNode,
  chain,
  run,
  expectRule,
  expectNoRule,
  expectRuleCount,
} from "../helpers.js";

// ─── REL-001 — No timeout on HTTP Request ─────────────────────────────────────

describe("REL-001 — HTTP Request no timeout", () => {
  it("fires when timeout is not set", () => {
    const wf = workflow([httpNode("Call API", { url: "https://example.com" })]);
    expectRule(run(reliabilityRules, wf), "REL-001");
  });

  it("fires when timeout is 0", () => {
    const wf = workflow([httpNode("Call API", { url: "https://example.com", timeout: 0 })]);
    expectRule(run(reliabilityRules, wf), "REL-001");
  });

  it("does not fire when timeout is set", () => {
    const wf = workflow([httpNode("Call API", { url: "https://example.com", timeout: 10000 })]);
    expectNoRule(run(reliabilityRules, wf), "REL-001");
  });

  it("does not fire on disabled nodes", () => {
    const wf = workflow([httpNode("Call API", { url: "https://example.com" }, { disabled: true })]);
    expectNoRule(run(reliabilityRules, wf), "REL-001");
  });
});

// ─── REL-002 — Retry with no backoff ──────────────────────────────────────────

describe("REL-002 — Retry with no backoff", () => {
  it("fires when retryOnFail=true and waitBetweenTries not set", () => {
    const wf = workflow([httpNode("Call API", { retryOnFail: true })]);
    expectRule(run(reliabilityRules, wf), "REL-002");
  });

  it("fires when retryOnFail=true and waitBetweenTries=0", () => {
    const wf = workflow([httpNode("Call API", { retryOnFail: true, waitBetweenTries: 0 })]);
    expectRule(run(reliabilityRules, wf), "REL-002");
  });

  it("does not fire when waitBetweenTries is set", () => {
    const wf = workflow([httpNode("Call API", { retryOnFail: true, waitBetweenTries: 1000 })]);
    expectNoRule(run(reliabilityRules, wf), "REL-002");
  });

  it("does not fire when retryOnFail is false", () => {
    const wf = workflow([httpNode("Call API", { retryOnFail: false })]);
    expectNoRule(run(reliabilityRules, wf), "REL-002");
  });
});

// ─── DQ-008 — Retry on non-idempotent method without idempotency key ─────────

describe("DQ-008 — Retry on non-idempotent without idempotency key", () => {
  it("fires on POST with retryOnFail and no idempotency key", () => {
    const wf = workflow([httpNode("Create Record", { method: "POST", retryOnFail: true })]);
    expectRule(run(reliabilityRules, wf), "DQ-008");
  });

  it("fires on DELETE with retryOnFail", () => {
    const wf = workflow([httpNode("Delete Record", { requestMethod: "DELETE", retryOnFail: true })]);
    expectRule(run(reliabilityRules, wf), "DQ-008");
  });

  it("does not fire when idempotency key header is present", () => {
    const wf = workflow([httpNode("Create Record", {
      method: "POST",
      retryOnFail: true,
      headerParameters: { parameters: [{ name: "Idempotency-Key", value: "{{ $json.id }}" }] },
    })]);
    expectNoRule(run(reliabilityRules, wf), "DQ-008");
  });

  it("does not fire on GET", () => {
    const wf = workflow([httpNode("Fetch Data", { method: "GET", retryOnFail: true })]);
    expectNoRule(run(reliabilityRules, wf), "DQ-008");
  });
});

// ─── DQ-001 — continueOnFail overuse ─────────────────────────────────────────

describe("DQ-001 — continueOnFail overuse", () => {
  it("fires when >30% of nodes have continueOnFail", () => {
    const nodes = [
      scheduleNode(),
      httpNode("A", {}, { parameters: { continueOnFail: true } as Record<string, unknown> }),
      httpNode("B", {}, { parameters: { continueOnFail: true } as Record<string, unknown> }),
      setNode("C"),
    ];
    // Manually set continueOnFail as top-level property
    nodes[1].parameters.continueOnFail = true;
    nodes[2].parameters.continueOnFail = true;
    const wf = workflow(nodes);
    expectRule(run(reliabilityRules, wf), "DQ-001");
  });

  it("fires when a critical DB node has continueOnFail", () => {
    const dbNode = postgresNode("Write DB", { operation: "insert" });
    (dbNode as Record<string, unknown>).continueOnFail = true;
    dbNode.parameters.continueOnFail = true;
    const wf = workflow([scheduleNode(), dbNode]);
    expectRule(run(reliabilityRules, wf), "DQ-001");
  });
});

// ─── DQ-002 — HTTP Request with no downstream status check ───────────────────

describe("DQ-002 — HTTP Request no downstream status check", () => {
  it("fires when HTTP Request has no IF downstream", () => {
    const http = httpNode("Call API");
    const set = setNode("Store Result");
    const wf = workflow([scheduleNode(), http, set], { connections: chain(http, set) });
    expectRule(run(reliabilityRules, wf), "DQ-002");
  });

  it("does not fire when IF is immediately downstream", () => {
    const http = httpNode("Call API");
    const check = ifNode("Check Response", { conditions: { boolean: [{ value1: "{{ $json.ok }}", value2: true }] } });
    const wf = workflow([scheduleNode(), http, check], { connections: chain(http, check) });
    expectNoRule(run(reliabilityRules, wf), "DQ-002");
  });

  it("does not fire when Code node checks statusCode", () => {
    const http = httpNode("Call API");
    const code = codeNode("Validate", "if ($json.statusCode !== 200) throw new Error('fail');");
    const wf = workflow([scheduleNode(), http, code], { connections: chain(http, code) });
    expectNoRule(run(reliabilityRules, wf), "DQ-002");
  });
});

// ─── REL-004 — DB insert with no upstream dedup ───────────────────────────────

describe("REL-004 — DB insert no upstream dedup", () => {
  it("fires when INSERT has no upstream IF or SELECT", () => {
    const trigger = scheduleNode();
    const insert = postgresNode("Insert Record", { operation: "insert" });
    const wf = workflow([trigger, insert], { connections: chain(trigger, insert) });
    expectRule(run(reliabilityRules, wf), "REL-004");
  });

  it("does not fire when IF is upstream of INSERT", () => {
    const trigger = scheduleNode();
    const check = ifNode("Check Exists");
    const insert = postgresNode("Insert Record", { operation: "insert" });
    const wf = workflow([trigger, check, insert], {
      connections: {
        ...chain(trigger, check),
        [check.name]: { main: [[{ node: insert.name, type: "main", index: 0 }]] },
      },
    });
    expectNoRule(run(reliabilityRules, wf), "REL-004");
  });

  it("does not fire on UPDATE operations", () => {
    const trigger = scheduleNode();
    const update = postgresNode("Update Record", { operation: "update" });
    const wf = workflow([trigger, update], { connections: chain(trigger, update) });
    expectNoRule(run(reliabilityRules, wf), "REL-004");
  });
});

// ─── OP-003 — DB write with no error workflow ─────────────────────────────────

describe("OP-003 — DB write no error workflow", () => {
  it("fires when DB write exists and no errorWorkflow in settings", () => {
    const wf = workflow([scheduleNode(), postgresNode("Write DB", { operation: "insert" })]);
    expectRule(run(reliabilityRules, wf), "OP-003");
  });

  it("does not fire when errorWorkflow is set", () => {
    const wf = {
      ...workflow([scheduleNode(), postgresNode("Write DB", { operation: "insert" })]),
      settings: { errorWorkflow: "wf-error-handler" },
    };
    expectNoRule(run(reliabilityRules, wf), "OP-003");
  });

  it("does not fire when no DB write nodes are present", () => {
    const wf = workflow([scheduleNode(), httpNode("Call API")]);
    expectNoRule(run(reliabilityRules, wf), "OP-003");
  });
});
