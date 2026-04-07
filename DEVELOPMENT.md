# Development Guide

How the analyzer engine works, how the AI layer is built, how the GitHub integration works, and how to run and extend the test suite.

---

## How the engine works

The analyzer is a **static inspection engine** — it reads the workflow JSON structure without executing code, making network calls, or modifying anything.

```
Workflow JSON  ──or──  n8n REST API (Mode B)
        │
        ▼
┌─────────────────────────────────────────┐
│             Orchestrator                │
│  1. Load ALL_RULES (33 rules)           │
│  2. Remove DISABLED_RULES               │
│  3. Run each rule → collect Violations  │
│  4. Filter by SEVERITY_THRESHOLD        │
│  5. Build AnalysisReport                │
└─────────────────────────────────────────┘
        │
        │  (optional — only if GEMINI_API_KEY set and ai: true)
        ▼
┌─────────────────────────────────────────┐
│          AI Enhancement Layer           │
│  gemini-2.5-flash with compact prompt   │
│  → dataFlowRisks                        │
│  → falsePositiveNotes                   │
│  → remediationPriority                  │
│  → suggestedRedesigns                   │
│  → summary + confidence                 │
└─────────────────────────────────────────┘
        │
        ▼
AnalysisReport + aiAnalysis (additive)
```

### The rule interface

Every rule is a self-contained object:

```typescript
interface RuleRunner {
  definition: RuleDefinition;          // id, severity, category, title, description, remediation
  run(ctx: RuleContext): Violation[];  // pure function — no side effects
}
```

Rules are **pure functions**. Same workflow + config always produces the same violations. They cannot read files, make network calls, or share state. This makes them safe to run in any order and trivial to test in isolation.

Rules are grouped and registered in `src/analyzer/rules/index.ts`:

```
ALL_RULES
  ├── credentialsRules    → SEC-001, SEC-002, SEC-003
  ├── networkRules        → NET-001, NET-002, NET-003, NET-004
  ├── dataPolicyRules     → DP-001, DP-002, DP-003, DP-004, DP-005, DP-006
  ├── dangerousNodesRules → DN-001, DN-002, DN-003, DN-004
  ├── expressionInjRules  → EXP-001, EXP-002, EXP-003, EXP-004
  ├── hygieneRules        → HYG-001, HYG-002, HYG-003, HYG-004
  ├── supplyChainRules    → SC-001, SC-002, SC-003, SC-004
  ├── dataFlowRules       → DF-001, DF-002, DF-003
  └── loopFlowRules       → LF-001, LF-002
```

---

## Detection techniques

### 1. Parameter walking

n8n node parameters are arbitrary nested objects. The walker in `src/analyzer/utils.ts → walkStringParams` recurses through the entire parameter tree and yields every string leaf with its dot-notation path:

```
Input: node.parameters = {
  url: "https://api.example.com",
  headerParameters: {
    values: [{ name: "Authorization", value: "Bearer sk-abc123..." }]
  }
}

Output:
  { path: "parameters.url",                               value: "https://api.example.com" }
  { path: "parameters.headerParameters.values[0].name",   value: "Authorization" }
  { path: "parameters.headerParameters.values[0].value",  value: "Bearer sk-abc123..." }
```

The path is reported in the violation's `field` property so you can find the exact location in the n8n editor.

Used by: SEC-001, SEC-002, NET-001–004, DP-002, DP-004, DP-006, EXP-002, EXP-003, EXP-004, SC-003, SC-004.

### 2. Secret pattern matching (SEC-001)

14 regex patterns targeting specific credential formats, plus a high-entropy heuristic for fields named `password`, `secret`, `token`, `apiKey`, etc. (≥20 chars, >10 unique chars).

False-positive guards: skips disabled nodes and `$credentials.` references.

### 3. URL parsing (SEC-002, NET-001–004, DP-006, SC-001, SC-004)

Uses the built-in `URL` class — not regex — to parse URLs. Values containing `{{...}}` expressions are skipped. For NET-003, the hostname is checked against all RFC 1918 ranges, loopback, link-local (169.254.x — AWS metadata), and internal DNS suffixes.

DP-006 reuses the same hostname extraction to compare against the `APPROVED_EGRESS_HOSTS` set. Private hosts are excluded (they belong to NET-003) and fully dynamic URLs are excluded (they belong to NET-004), so the three rules do not overlap.

### 4. Set node structure inspection (SEC-003)

n8n's Set node stores field names inside `{ name, value }` objects — not as JSON keys — so the parameter walker alone can't identify them. SEC-003 reads the Set node shape directly:

```
v1: parameters.values.string[0]            = { name: "apiKey", value: "..." }
v2: parameters.assignments.assignments[0]  = { name: "apiKey", value: "..." }
```

### 5. Connection graph traversal (EXP-001, HYG-002, DF-002, DF-003)

`buildAdjacencyList` converts n8n's `connections` object into a `Map<string, Set<string>>`. Three higher-level utilities are built on top:

**`bfsFrom(graph, startNode, visitor)`** — breadth-first traversal from a starting node. Used by DF-003 to check whether a chat node is reachable downstream from a database or webhook source.

**`hasSanitizationBetween(graph, start, target, sanitizationSet)`** — depth-first search that returns `true` only if every path from `start` to `target` passes through at least one node in `sanitizationSet`. Used by EXP-001 (sanitisation nodes: IF, Switch, Set, Filter) and DF-002 (sanitisation node: Set).

```
Example — EXP-001 FIRES (direct bypass exists):
  Webhook → Validate Input (IF) → Run Script
          ↘ ──────────────────── → Run Script
  Path 1: sanitised ✓
  Path 2: NOT sanitised ✗  →  violation
```

HYG-002 uses the adjacency list directly to find nodes with no edges in either direction (orphaned nodes).

### 6. PII expression matching (DP-002)

Matches n8n expressions referencing PII fields (`email`, `firstName`, `ssn`, etc.) in POST/PUT/PATCH request bodies. Uses `\b` word boundaries to prevent `emailTemplateId` false positives.

### 7. Environment variable reference detection (EXP-003)

Scans all node parameters for `$env.<VARIABLE_NAME>` using a global regex. The regex `lastIndex` is manually reset before each call to prevent stateful bugs when the same regex object is reused across multiple parameters.

### 8. Egress allowlist enforcement (DP-006)

When `APPROVED_EGRESS_HOSTS` is non-empty, every HTTP Request node is inspected. For each parameter value, the hostname is extracted using the same `URL` parser used by the network rules. The hostname is compared case-insensitively against the approved set. Private hosts and fully dynamic expressions are excluded. A `reportedHosts` Set per node prevents duplicate violations when the same hostname appears in multiple parameters (e.g. a URL and a redirect option).

### 9. Supply chain detection (SC-001–SC-004)

- **SC-001** matches HTTP Request URLs against local n8n API patterns (`:5678`, `/api/v1/` on local addresses) using regex, not URL parsing, because these patterns may appear in partial URL strings inside expressions.
- **SC-002** checks `node.type` against `OFFICIAL_NODE_PREFIXES`. Results are deduplicated by type — one violation per community node type, not per node instance.
- **SC-003** applies 6 dangerous-code regexes to code node parameters (`jsCode`, `functionCode`, `code`).
- **SC-004** extracts the hostname from HTTP Request URLs and checks it against a fixed set of known raw-content/paste hosts.

### 10. Data flow tracking (DF-001–DF-003)

- **DF-001** uses the parameter walker to find `={{ $json }}` or `JSON.stringify($json)` in RespondToWebhook node parameters.
- **DF-002** uses `hasSanitizationBetween` with Set nodes as the sanitisation barrier. Fires for each (DB source node → cloud write destination) pair where at least one unsanitised path exists.
- **DF-003** uses `bfsFrom` to traverse the graph from each DB/webhook source node and fires if any chat node (Slack, Telegram, Discord, Teams) is reachable.

### 11. Loop and cron detection (LF-001–LF-002)

- **LF-001** inspects Schedule Trigger parameters for seconds-based intervals, and Cron node expressions for 6-field cron syntax where the seconds field is not `0`.
- **LF-002** extracts the target workflow ID from Execute Workflow node parameters. Supports both the v1 string format (`parameters.workflowId: "abc"`) and the v2 resource-locator format (`parameters.workflowId: { __rl: true, value: "abc" }`), then compares against `workflow.id`.

---

## Configuration

All configuration is loaded from environment variables in `src/config.ts` and injected into every rule via the `RuleContext`. Rules never read `process.env` directly.

| Variable | Type | Used by |
|---|---|---|
| `APPROVED_DB_HOSTS` | `Set<string>` | DP-003 |
| `APPROVED_EGRESS_HOSTS` | `Set<string>` | DP-006 |
| `DISABLED_RULES` | `Set<string>` | Orchestrator |
| `SEVERITY_THRESHOLD` | `Severity` | Orchestrator |
| `REDACT_EVIDENCE` | `boolean` | Orchestrator |
| `GEMINI_API_KEY` | `string \| null` | AI layer |

Adding a new config-driven rule:

1. Add the field to the `Config` interface in `src/config.ts`
2. Parse it from `process.env` in `buildConfig()`
3. Access it via `ctx.config.yourField` inside the rule's `run()` function
4. Add the field to `defaultConfig` in `tests/helpers.ts`

---

## AI layer

### Workflow analysis (`ai: true`)

When `GEMINI_API_KEY` is set and `"ai": true` is passed, the orchestrator calls `enhanceWithAI` after the static pass:

- **Always additive** — failure returns the static report unchanged with a warning
- **Compact prompt** — max 80 nodes, code truncated at 300 chars, URLs at 120 chars
- **30-second timeout** via `Promise.race`

Returns: `dataFlowRisks`, `falsePositiveNotes`, `remediationPriority`, `suggestedRedesigns`, `summary`, `confidence`.

### Fix suggestions (`POST /analyze/fix`)

For any critical/high/medium violation:

1. Sends violation details + node parameters to Gemini
2. Gemini returns an explanation and a patched `parameters` object (or `null` for manual-only fixes like moving a secret to the credential vault)
3. The patch is applied in-memory and the analyzer re-runs — if the rule no longer fires on that node, `verified: true` is set

```json
{
  "explanation": "Replace the hardcoded header with an n8n HTTP Header Auth credential...",
  "patchedParameters": { "authentication": "headerAuth", ... },
  "verified": true,
  "verificationNote": "Re-analysis confirmed: applying this patch removes the violation."
}
```

### Evidence redaction

By default (`REDACT_EVIDENCE=true`), only the first 4 characters of a matched secret are kept:

```
sk_live_ABCDEFGHIJKLMNOPQRSTUVWX  →  sk_l****REDACTED****
```

---

## GitHub Integration

### SARIF output

`src/sarif.ts` converts any number of `AnalysisReport` objects into a single SARIF 2.1.0 document. SARIF is the format consumed by GitHub Code Scanning, GitLab SAST, Azure DevOps, and most CI security dashboards.

Key design decisions:

- **All 33 rules appear in `driver.rules`** regardless of whether any violations were found — this ensures the rule catalogue is always visible in Code Scanning.
- **Severity → SARIF level mapping:** `critical` and `high` → `"error"`, `medium` → `"warning"`, `low` → `"note"`.
- **Security severity scores** (used by GitHub for sorting and alerting): `critical` = 9.8, `high` = 7.5, `medium` = 5.0, `low` = 2.0.
- **Line numbers** are always reported as line 1. n8n workflow JSON has no meaningful line-level structure for violations — findings point at the file, not a line.
- **Artifact URIs** are computed as paths relative to `process.cwd()` so they are repo-root-relative when the Action runs from the checked-out repository.

### CLI SARIF mode

```bash
# Write SARIF to a file
npx tsx src/cli.ts --format sarif --output results.sarif workflows/

# Pipe to stdout
npx tsx src/cli.ts --format sarif workflows/ > results.sarif
```

The `--output` flag writes via `writeFileSync` directly. This avoids stdout contamination from the tsx env injector (`◇ injecting env...`) which would make the JSON invalid if written via stdout redirect.

### GitHub composite Action (`action.yml`)

The Action wraps the CLI in four steps:

1. **setup-node@v4** — installs Node.js 20
2. **npm ci** — installs dependencies from lockfile (`--ignore-scripts` for safety)
3. **Build types** — compiles the shared `@n8n-analyzer/types` package
4. **Run analysis** — invokes the CLI in SARIF mode, parses counts from the SARIF output using `jq`, writes the step summary, and applies the `fail-on` threshold

The `fail-on` logic reads critical and high counts from the generated SARIF file:

```bash
case "$FAIL_ON" in
  critical) [ "$CRITICAL" -gt 0 ] && SHOULD_FAIL=true ;;
  high)     [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] && SHOULD_FAIL=true ;;
  medium)   [ "$TOTAL" -gt 0 ] && SHOULD_FAIL=true ;;
  none)     SHOULD_FAIL=false ;;
esac
```

5. **upload-sarif** — calls `github/codeql-action/upload-sarif@v3` to post the findings to GitHub Code Scanning (conditional on `upload-sarif: "true"` and the SARIF file existing).

---

## Test suite

### Running tests

```bash
# All tests
npm test -w api

# Watch mode
npm run test:watch -w api

# Single file
cd packages/api && npx vitest run tests/rules/credentials.test.ts

# Pattern match
cd packages/api && npx vitest run --reporter=verbose -t "SEC-001"
```

### Design philosophy

Every rule has **true positive** tests (rule fires when it should) and **false positive** tests (rule stays silent on safe inputs). Tests use a fluent builder API:

```typescript
it("fires on ?api_key= in URL", () => {
  const wf = workflow([
    httpNode("API", { url: "https://api.example.com?api_key=supersecret123" }),
  ]);
  expectRule(run(credentialsRules, wf), "SEC-002");
});

it("does NOT fire on safe query params", () => {
  const wf = workflow([
    httpNode("Safe", { url: "https://api.example.com?page=1&limit=20" }),
  ]);
  expectNoRule(run(credentialsRules, wf), "SEC-002");
});
```

Config-driven rules (DP-003, DP-006) are tested by injecting a custom config alongside the default:

```typescript
function cfg(hosts: string[]): Config {
  return { ...defaultConfig, approvedEgressHosts: new Set(hosts) };
}

it("does not fire when allowlist is empty", () => {
  const wf = workflow([httpNode("Call", { url: "https://api.stripe.com/" })]);
  expectNoRule(run(dataPolicyRules, wf, defaultConfig), "DP-006");
});

it("fires when host is not in the allowlist", () => {
  const wf = workflow([httpNode("Call", { url: "https://api.stripe.com/" })]);
  expectRule(run(dataPolicyRules, wf, cfg(["api.approved.com"])), "DP-006");
});
```

### Test files

| File | Tests | Coverage |
|---|---|---|
| `tests/rules/credentials.test.ts` | 28 | SEC-001, SEC-002, SEC-003 |
| `tests/rules/network.test.ts` | 26 | NET-001, NET-002, NET-003, NET-004 |
| `tests/rules/data-policy.test.ts` | 40 | DP-001, DP-002, DP-003, DP-004, DP-005 |
| `tests/rules/data-policy-dp006.test.ts` | 14 | DP-006 (egress allowlist) |
| `tests/rules/dangerous-nodes.test.ts` | 18 | DN-001, DN-002, DN-003, DN-004 |
| `tests/rules/expression-injection.test.ts` | 26 | EXP-001, EXP-002, EXP-003, EXP-004 |
| `tests/rules/hygiene.test.ts` | 28 | HYG-001, HYG-002, HYG-003, HYG-004 |
| `tests/rules/supply-chain.test.ts` | 25 | SC-001, SC-002, SC-003, SC-004 |
| `tests/rules/data-flow.test.ts` | 17 | DF-001, DF-002, DF-003 |
| `tests/rules/loop-flow.test.ts` | 11 | LF-001, LF-002 |
| `tests/orchestrator.test.ts` | 18 | End-to-end pipeline, severity threshold, disabled rules, redaction |
| **Total** | **251** | |

### Test fixtures

| File | Violations |
|---|---|
| `clean-workflow.json` | 0 |
| `hardcoded-credentials.json` | SEC-001 (critical), SEC-002 (high), DP-001 (high) |
| `dangerous-nodes.json` | DN-001 (critical), DN-002 (critical), DN-003 (high), DN-004 (medium), DP-004 (medium) |
| `expression-injection.json` | EXP-001 (high), EXP-002 (medium) |

### Node builders (`tests/helpers.ts`)

| Builder | Node type |
|---|---|
| `httpNode(name, params)` | `n8n-nodes-base.httpRequest` |
| `webhookNode(name, params)` | `n8n-nodes-base.webhook` |
| `setNode(name, params)` | `n8n-nodes-base.set` |
| `codeNode(name, jsCode)` | `n8n-nodes-base.code` |
| `scheduleNode(name)` | `n8n-nodes-base.scheduleTrigger` |
| `errorTriggerNode(name)` | `n8n-nodes-base.errorTrigger` |
| `postgresNode(name, params)` | `n8n-nodes-base.postgres` |
| `slackNode(name, params)` | `n8n-nodes-base.slack` |
| `googleSheetsNode(name, params)` | `n8n-nodes-base.googleSheets` |
| `respondToWebhookNode(name, params)` | `n8n-nodes-base.respondToWebhook` |
| `executeWorkflowNode(name, workflowId)` | `n8n-nodes-base.executeWorkflow` |
| `communityNode(name, namespace, params)` | any custom type string |
| `genericNode(name, type, params)` | any type string |

---

## Local development

```bash
# Install all dependencies
npm install

# Build shared types (required once before running the API)
npm run build -w @n8n-analyzer/types

# Start API + UI together
npm run dev

# Or separately
npm run dev -w api   # → http://localhost:3000
npm run dev -w ui    # → http://localhost:5173

# Type-check
npm run lint

# Run tests
npm test -w api
```

---

## Adding a new rule

1. Pick an ID following the existing pattern (`SEC-004`, `NET-005`, etc.)
2. Add a `RuleRunner` object to the appropriate file in `packages/api/src/analyzer/rules/`
3. Export it from the file's array — the orchestrator picks it up automatically via `ALL_RULES` in `src/analyzer/rules/index.ts`
4. Add tests to the matching test file: at minimum one true-positive case and one false-positive guard
5. Update `RULES.md` with the new rule ID, severity, trigger condition, and plain-language consequence

If the rule needs a new config variable:

1. Add the field to `Config` in `src/config.ts` and parse it in `buildConfig()`
2. Add the field with a safe default to `defaultConfig` in `tests/helpers.ts`
3. Document the variable in `README.md` and `.env.example`
