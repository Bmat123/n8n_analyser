import { describe, it } from "vitest";
import { performanceRules } from "../../src/analyzer/rules/performance.js";
import {
  workflow,
  httpNode,
  setNode,
  scheduleNode,
  postgresNode,
  ifNode,
  waitNode,
  splitInBatchesNode,
  genericNode,
  chain,
  run,
  expectRule,
  expectNoRule,
  defaultConfig,
  B,
} from "../helpers.js";

// ─── DQ-003 — Unthrottled loop with HTTP Request ──────────────────────────────

describe("DQ-003 — unthrottled loop with HTTP Request", () => {
  it("fires when loop body has HTTP Request but no Wait node", () => {
    const loop = splitInBatchesNode("Loop Items");
    const http = httpNode("Call API per Item");
    const connections = {
      [loop.name]: {
        main: [[{ node: http.name, type: "main", index: 0 }]],
      },
      // loopback from http → loop (port 0 = body, loop continues)
      [http.name]: {
        main: [[{ node: loop.name, type: "main", index: 0 }]],
      },
    };
    const wf = workflow([scheduleNode(), loop, http], { connections });
    expectRule(run(performanceRules, wf), "DQ-003");
  });

  it("does not fire when Wait node is in the loop body", () => {
    const loop = splitInBatchesNode("Loop Items");
    const http = httpNode("Call API per Item");
    const wait = waitNode("Throttle", { resume: "timeInterval", value: 100, unit: "milliseconds" });
    const connections = {
      [loop.name]: {
        main: [[{ node: http.name, type: "main", index: 0 }]],
      },
      [http.name]: {
        main: [[{ node: wait.name, type: "main", index: 0 }]],
      },
      [wait.name]: {
        main: [[{ node: loop.name, type: "main", index: 0 }]],
      },
    };
    const wf = workflow([scheduleNode(), loop, http, wait], { connections });
    expectNoRule(run(performanceRules, wf), "DQ-003");
  });

  it("respects loopRateLimitExemptions", () => {
    const loop = splitInBatchesNode("Loop Items");
    const http = httpNode("Call API per Item");
    const connections = {
      [loop.name]: { main: [[{ node: http.name, type: "main", index: 0 }]] },
      [http.name]: { main: [[{ node: loop.name, type: "main", index: 0 }]] },
    };
    const wf = workflow([scheduleNode(), loop, http], { connections });
    const cfg = { ...defaultConfig, loopRateLimitExemptions: new Set(["Loop Items"]) };
    expectNoRule(run(performanceRules, wf, cfg), "DQ-003");
  });
});

// ─── DQ-004 — Full table scan ────────────────────────────────────────────────

describe("DQ-004 — full table scan", () => {
  it("fires on SELECT * query with no WHERE clause", () => {
    const wf = workflow([
      scheduleNode(),
      postgresNode("Get All Users", { query: "SELECT * FROM users" }),
    ]);
    expectRule(run(performanceRules, wf), "DQ-004");
  });

  it("fires on SELECT * with no LIMIT clause", () => {
    const wf = workflow([
      scheduleNode(),
      postgresNode("Get Users", { query: "SELECT * FROM users WHERE active = true" }),
    ]);
    expectRule(run(performanceRules, wf), "DQ-004");
  });

  it("does not fire when WHERE and LIMIT are both present", () => {
    const wf = workflow([
      scheduleNode(),
      postgresNode("Get Recent Users", {
        query: "SELECT * FROM users WHERE created_at > NOW() - INTERVAL '1 hour' LIMIT 100",
      }),
    ]);
    expectNoRule(run(performanceRules, wf), "DQ-004");
  });

  it("does not fire on INSERT operations", () => {
    const wf = workflow([
      scheduleNode(),
      postgresNode("Insert User", { operation: "insert" }),
    ]);
    expectNoRule(run(performanceRules, wf), "DQ-004");
  });
});

// ─── PERF-001 — N+1 query pattern ────────────────────────────────────────────

describe("PERF-001 — N+1 database query in loop", () => {
  it("fires when DB node is inside a loop body", () => {
    const loop = splitInBatchesNode("Loop Orders");
    const db = postgresNode("Fetch Order Details", { operation: "select" });
    const connections = {
      [loop.name]: { main: [[{ node: db.name, type: "main", index: 0 }]] },
      [db.name]: { main: [[{ node: loop.name, type: "main", index: 0 }]] },
    };
    const wf = workflow([scheduleNode(), loop, db], { connections });
    expectRule(run(performanceRules, wf), "PERF-001");
  });

  it("does not fire when DB node is outside the loop", () => {
    const loop = splitInBatchesNode("Loop Orders");
    const db = postgresNode("Fetch All Orders", { operation: "select" });
    const http = httpNode("Process Item");
    const connections = {
      ...chain(db, loop),
      [loop.name]: { main: [[{ node: http.name, type: "main", index: 0 }]] },
      [http.name]: { main: [[{ node: loop.name, type: "main", index: 0 }]] },
    };
    const wf = workflow([scheduleNode(), db, loop, http], { connections });
    expectNoRule(run(performanceRules, wf), "PERF-001");
  });
});

// ─── PERF-004 — Duplicate API calls to same endpoint ─────────────────────────

describe("PERF-004 — duplicate API calls to same endpoint", () => {
  it("fires when same host+path is called by multiple HTTP Request nodes", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Fetch Users A", { url: "https://api.example.com/users" }),
      httpNode("Fetch Users B", { url: "https://api.example.com/users" }),
    ]);
    expectRule(run(performanceRules, wf), "PERF-004");
  });

  it("does not fire when endpoints differ by path", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Fetch Users", { url: "https://api.example.com/users" }),
      httpNode("Fetch Orders", { url: "https://api.example.com/orders" }),
    ]);
    expectNoRule(run(performanceRules, wf), "PERF-004");
  });

  it("does not fire for dynamic URLs without a parseable host", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Call A", { url: "{{ $json.apiUrl }}/users" }),
      httpNode("Call B", { url: "{{ $json.apiUrl }}/users" }),
    ]);
    expectNoRule(run(performanceRules, wf), "PERF-004");
  });
});

// ─── PERF-003 — Unbounded result set (advisory) ───────────────────────────────

describe("PERF-003 — unbounded API result (advisory)", () => {
  it("fires on HTTP Request outside loop with no pagination params", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Fetch All Records", { url: "https://api.example.com/records" }),
    ]);
    expectRule(run(performanceRules, wf), "PERF-003");
  });

  it("does not fire when URL contains pagination param", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Fetch Page 1", { url: "https://api.example.com/records?page=1&limit=100" }),
    ]);
    expectNoRule(run(performanceRules, wf), "PERF-003");
  });

  it("does not fire when includeAdvisory is false", () => {
    const wf = workflow([
      scheduleNode(),
      httpNode("Fetch Records", { url: "https://api.example.com/records" }),
    ]);
    const cfg = { ...defaultConfig, includeAdvisory: false };
    expectNoRule(run(performanceRules, wf, cfg), "PERF-003");
  });
});
