# Development Guide

How the analyzer engine works, how the AI layer is built, and how to run and extend the test suite.

---

## How the engine works

The analyzer is a **static inspection engine** — it reads the workflow JSON structure without executing code, making network calls, or modifying anything.

```
Workflow JSON  ──or──  n8n REST API (Mode B)
        │
        ▼
┌─────────────────────────────────────────┐
│             Orchestrator                │
│  1. Load ALL_RULES (20 rules)           │
│  2. Remove DISABLED_RULES               │
│  3. Run each rule → collect Violations  │
│  4. Filter by SEVERITY_THRESHOLD        │
│  5. Build AnalysisReport                │
└─────────────────────────────────────────┘
        │
        ▼
Static AnalysisReport
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
  ├── dataPolicyRules     → DP-001, DP-002, DP-003, DP-004, DP-005
  ├── dangerousNodesRules → DN-001, DN-002, DN-003, DN-004
  ├── expressionInjRules  → EXP-001, EXP-002
  └── hygieneRules        → HYG-001, HYG-002, HYG-003, HYG-004
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

Used by: SEC-001, SEC-002, NET-001–004, DP-002, DP-004, EXP-002.

### 2. Secret pattern matching (SEC-001)

14 regex patterns targeting specific credential formats, plus a high-entropy heuristic for fields named `password`, `secret`, `token`, `apiKey`, etc. (≥20 chars, >10 unique chars).

False-positive guards: skips disabled nodes and `$credentials.` references.

### 3. URL parsing (SEC-002, NET-001–004)

Uses the built-in `URL` class — not regex — to parse URLs. Values containing `{{...}}` expressions are skipped. For NET-003, the hostname is checked against all RFC 1918 ranges, loopback, link-local (169.254.x — AWS metadata), and internal DNS suffixes.

### 4. Set node structure inspection (SEC-003)

n8n's Set node stores field names inside `{ name, value }` objects — not as JSON keys — so the parameter walker alone can't identify them. SEC-003 reads the Set node shape directly:

```
v1: parameters.values.string[0]            = { name: "apiKey", value: "..." }
v2: parameters.assignments.assignments[0]  = { name: "apiKey", value: "..." }
```

### 5. Connection graph traversal (EXP-001, HYG-002)

`buildAdjacencyList` converts n8n's `connections` object into a `Map<string, Set<string>>`. EXP-001 then runs a depth-first search to check whether **every** path from a webhook to a dangerous node passes through a sanitisation node (IF, Switch, Set, or Filter). If even one path bypasses sanitisation the violation fires.

```
Example — FIRES (direct bypass exists):
  Webhook → Validate Input (IF) → Run Script
          ↘ ──────────────────── → Run Script
  Path 1: sanitised ✓
  Path 2: NOT sanitised ✗  →  violation
```

### 6. PII expression matching (DP-002)

Matches n8n expressions referencing PII fields (`email`, `firstName`, `ssn`, etc.) in POST/PUT/PATCH request bodies. Uses `\b` word boundaries to prevent `emailTemplateId` false positives.

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

### Test files

| File | Tests | Coverage |
|---|---|---|
| `tests/rules/credentials.test.ts` | 27 | SEC-001, SEC-002, SEC-003 |
| `tests/rules/network.test.ts` | 26 | NET-001, NET-002, NET-003, NET-004 |
| `tests/rules/data-policy.test.ts` | 37 | DP-001, DP-002, DP-003, DP-004, DP-005 |
| `tests/rules/dangerous-nodes.test.ts` | 18 | DN-001, DN-002, DN-003, DN-004 |
| `tests/rules/expression-injection.test.ts` | 15 | EXP-001, EXP-002 |
| `tests/rules/hygiene.test.ts` | 20 | HYG-001, HYG-002, HYG-003 |
| `tests/orchestrator.test.ts` | 14 | End-to-end pipeline, severity threshold, disabled rules, redaction |

### Test fixtures

| File | Violations |
|---|---|
| `clean-workflow.json` | 0 |
| `hardcoded-credentials.json` | SEC-001 (critical), SEC-002 (high), DP-001 (high) |
| `dangerous-nodes.json` | DN-001 (critical), DN-002 (critical), DN-003 (high), DN-004 (medium), DP-004 (medium) |
| `expression-injection.json` | EXP-001 (high), EXP-002 (medium) |

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
