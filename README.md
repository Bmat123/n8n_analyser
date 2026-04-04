# n8n Workflow Security Analyzer

Static security and data-policy analysis for n8n workflows. Paste a workflow JSON and get a structured report of every vulnerability, misconfiguration, and policy violation — without ever executing the workflow.

---

## Table of Contents

- [How it works](#how-it-works)
  - [Input: Mode A and Mode B](#input-mode-a-and-mode-b)
  - [The rule engine](#the-rule-engine)
  - [Detection technique 1: Parameter walking](#detection-technique-1-parameter-walking)
  - [Detection technique 2: Secret pattern matching](#detection-technique-2-secret-pattern-matching-sec-001)
  - [Detection technique 3: URL parsing](#detection-technique-3-url-parsing-sec-002-net-001-net-002-net-003-net-004)
  - [Detection technique 4: Set node structure inspection](#detection-technique-4-set-node-structure-inspection-sec-003)
  - [Detection technique 5: Connection graph traversal](#detection-technique-5-connection-graph-traversal-exp-001-hyg-002)
  - [Detection technique 6: PII expression matching](#detection-technique-6-pii-expression-matching-dp-002)
  - [AI enhancement layer](#ai-enhancement-layer)
  - [AI fix suggestions](#ai-fix-suggestions)
  - [Evidence redaction](#evidence-redaction)
  - [What the analyzer does NOT do](#what-the-analyzer-does-not-do)
  - [Output](#output)
- [Rule catalogue](#rule-catalogue)
  - [Credentials](#credentials)
  - [Network](#network)
  - [Data policy](#data-policy)
  - [Dangerous nodes](#dangerous-nodes)
  - [Expression injection](#expression-injection)
  - [Workflow hygiene](#workflow-hygiene)
- [Quick start — CLI](#quick-start--cli)
- [Quick start — API server](#quick-start--api-server)
  - [Endpoints](#endpoints)
  - [Mode A: inline workflow JSON](#mode-a-inline-workflow-json)
  - [Mode B: fetch from live n8n](#mode-b-fetch-from-live-n8n)
  - [Batch analysis](#batch-analysis)
  - [AI enhancement](#ai-enhancement)
  - [Fix suggestions](#fix-suggestions)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Test suite](#test-suite)
  - [Running the tests](#running-the-tests)
  - [Test design philosophy](#test-design-philosophy)
  - [Test files](#test-files)
  - [Test fixtures](#test-fixtures)
- [Development](#development)

---

## How it works

The analyzer is a **static inspection engine** — it reads the workflow JSON structure and applies rules to it without running any code, making any network calls, or modifying anything. The full analysis pipeline is:

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

### Input: Mode A and Mode B

The analyzer accepts the standard n8n workflow export format — the JSON you get when you click **Export** in the n8n editor, or fetch from the n8n REST API. The top-level shape is:

```json
{
  "id": "abc123",
  "name": "My Workflow",
  "active": true,
  "nodes": [ ... ],
  "connections": { ... }
}
```

The two important fields are:

- **`nodes`** — an array of node objects, each with `id`, `name`, `type`, `position`, `parameters`, and optionally `credentials` and `disabled`
- **`connections`** — a map of `sourceNodeName → { main: [[{ node, type, index }]] }` edges that describe how data flows between nodes

There are two ways to provide a workflow to the API:

**Mode A — inline JSON.** Paste the exported workflow object directly into the request body. No n8n instance required; the JSON is analyzed in-process and never stored.

**Mode B — live n8n fetch.** Provide a `baseUrl`, `apiKey`, and `workflowId`. The API calls `GET /api/v1/workflows/:id` on your n8n instance with the `X-N8N-API-KEY` header, fetches the workflow, and analyzes it. The workflow JSON is never persisted.

```bash
# Analyze a file (CLI)
npx tsx src/cli.ts my-workflow.json

# Pipe from n8n export (CLI)
cat my-workflow.json | npx tsx src/cli.ts
```

### The rule engine

Every rule is a self-contained object implementing the `RuleRunner` interface:

```typescript
interface RuleRunner {
  definition: RuleDefinition;   // id, severity, category, title, description, remediation
  run(ctx: RuleContext): Violation[];  // pure function: no side effects
}
```

Rules are **pure functions**. Given the same workflow and config, they always return the same violations. They cannot read from the filesystem, make network calls, or share state with other rules. This makes them independently testable and safe to run in any order.

The orchestrator in `src/analyzer/index.ts` drives the pipeline:

```
ALL_RULES (20 rules)
  │
  ├── filter out DISABLED_RULES
  │
  ├── for each active rule:
  │     violations = rule.run({ workflow, config })
  │     if violations.length === 0 → add ruleId to passedRules
  │     else → add violations to allViolations
  │
  ├── filter allViolations by SEVERITY_THRESHOLD
  │
  └── build AnalysisReport {
        summary: { totalNodes, totalViolations, critical, high, medium, low, passed },
        violations: [...],
        passedRules: [...],
        skippedRules: [...],
        metadata: { analyzerVersion, rulesetVersion, nodeTypesFound }
      }
```

The rules are grouped into six categories and registered in a single barrel file (`src/analyzer/rules/index.ts`). Adding a new rule requires only adding it to the appropriate category file — the orchestrator picks it up automatically:

```
ALL_RULES
  ├── credentialsRules    → SEC-001, SEC-002, SEC-003
  ├── networkRules        → NET-001, NET-002, NET-003, NET-004
  ├── dataPolicyRules     → DP-001, DP-002, DP-003, DP-004, DP-005
  ├── dangerousNodesRules → DN-001, DN-002, DN-003, DN-004
  ├── expressionInjRules  → EXP-001, EXP-002
  └── hygieneRules        → HYG-001, HYG-002, HYG-003
```

### Detection technique 1: Parameter walking

The most common technique. n8n node parameters are arbitrary nested objects — the structure varies by node type and version. For example, an HTTP Request node might store a header value at:

```
parameters.headerParameters.values[0].value
```

while a Code node stores its script at:

```
parameters.jsCode
```

The walker in `src/analyzer/utils.ts → walkStringParams` recurses through the entire parameter tree and yields every string leaf along with its **dot-notation path**:

```
Input: node.parameters = {
  url: "https://api.example.com",
  headerParameters: {
    values: [
      { name: "Authorization", value: "Bearer sk-abc123..." }
    ]
  }
}

Output (as a generator):
  { path: "parameters.url",                              value: "https://api.example.com" }
  { path: "parameters.headerParameters.values[0].name",  value: "Authorization" }
  { path: "parameters.headerParameters.values[0].value", value: "Bearer sk-abc123..." }
```

This path is reported directly in the violation's `field` property, so you can find the exact location in the n8n editor without guessing.

Rules that use this technique: **SEC-001**, **SEC-002**, **NET-001**, **NET-002**, **NET-003**, **NET-004**, **DP-002**, **DP-004**, **EXP-002**.

### Detection technique 2: Secret pattern matching (SEC-001)

SEC-001 applies a library of 14 regular expressions to every string value found by the parameter walker. Each pattern targets a specific type of credential by its known prefix or structure:

| Pattern name | Regex (simplified) | Example match |
|---|---|---|
| OpenAI key | `sk-[a-zA-Z0-9]{20,}` | `sk-ABCDEFGHIJ...` |
| Anthropic key | `sk-ant-[a-zA-Z0-9_-]{20,}` | `sk-ant-api03-XXX...` |
| GitHub PAT | `ghp_[a-zA-Z0-9]{36}` | `ghp_ABCDEFGHIJ...` |
| Slack token | `xox[baprs]-[0-9a-zA-Z-]{10,}` | `xoxb-123456-...` |
| AWS access key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| Stripe live key | `sk_live_[a-zA-Z0-9]{24,}` | `sk_live_ABCD...` |
| Bearer token | `Bearer\s+[a-zA-Z0-9\-._~+/]{20,}` | `Bearer eyJhb...` |
| Basic auth | `[Bb]asic\s+[a-zA-Z0-9+/]{20,}` | `Basic dXNlcjpwYXNz` |

In addition to pattern matching, SEC-001 also detects **high-entropy strings** in fields whose names suggest they hold credentials (`password`, `secret`, `token`, `apiKey`, `api_key`, `clientSecret`, etc.). A string qualifies as high-entropy if it is at least 20 characters long and contains more than 10 unique characters — a heuristic that catches credentials that don't match known patterns.

**False-positive guards:**
- Skips nodes with `disabled: true`
- Skips values containing `$credentials.` (references to n8n's vault, which are safe)
- The high-entropy check requires both a credential-named field AND sufficient entropy — a short value like `"demo"` in an `apiKey` field does not fire

### Detection technique 3: URL parsing (SEC-002, NET-001, NET-002, NET-003, NET-004)

For rules that inspect URLs, the analyzer uses the built-in `URL` class to safely parse values rather than applying fragile string matches. Values that contain n8n expressions (`{{...}}`) are skipped because they cannot be parsed as valid URLs.

```
Value: "https://api.example.com/data?api_key=supersecret"
  │
  ├── URL.protocol → "https:"  → not flagged by NET-001
  ├── URL.hostname → "api.example.com"  → not a private IP (NET-003 clear)
  └── URL.searchParams → { api_key: "supersecret" }  → SEC-002 FIRES
```

For NET-003 (private IP / SSRF risk), the hostname is checked against a set of patterns covering all RFC 1918 private ranges plus special addresses:

```
10.0.0.0/8      → regex ^10\.\d+\.\d+\.\d+$
172.16.0.0/12   → regex ^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$
192.168.0.0/16  → regex ^192\.168\.\d+\.\d+$
127.0.0.0/8     → regex ^127\.
169.254.0.0/16  → regex ^169\.254\.  (AWS IMDS endpoint)
Loopback        → "localhost", "127.0.0.1", "::1"
Internal DNS    → suffixes: .internal, .local, .svc.cluster.local
```

For NET-004 (fully dynamic URL), the analyzer checks whether the entire URL value matches `^\s*=?\s*\{\{.*\}\}\s*$` — meaning the URL has no static component at all. A URL like `https://api.example.com/users/{{ $json.id }}` does **not** fire because the host is static and verifiable.

### Detection technique 4: Set node structure inspection (SEC-003)

n8n's Set node uses a specific nested structure to define output fields. The field name (what the user typed in the "Name" column) is stored as a `name` key inside each entry — not as a JSON key — so the parameter walker alone cannot identify it. SEC-003 reads the Set node parameters directly:

```
n8n v1 shape:
  parameters.values.string[0] = { name: "apiKey", value: "abc123" }
                                          ↑
                              This is what the user named the field

n8n v2 shape:
  parameters.assignments.assignments[0] = { name: "apiKey", value: "abc123" }
```

The rule extracts all `{ name, value }` pairs from both shapes and checks whether the user-defined **name** looks like a credential field, or whether the **value** matches a known secret pattern.

### Detection technique 5: Connection graph traversal (EXP-001, HYG-002)

Some vulnerabilities cannot be detected by looking at individual nodes — they require understanding how data flows through the whole workflow. Two rules use graph analysis.

**Building the graph**

n8n's `connections` object is a map of source-node-name to arrays of output connections:

```json
"connections": {
  "Webhook": {
    "main": [[{ "node": "Validate Input", "type": "main", "index": 0 }]]
  },
  "Validate Input": {
    "main": [[{ "node": "Run Script", "type": "main", "index": 0 }]]
  }
}
```

`buildAdjacencyList` converts this into a plain `Map<string, Set<string>>`:

```
"Webhook"        → { "Validate Input" }
"Validate Input" → { "Run Script" }
"Run Script"     → { }
```

**EXP-001: Sanitisation gap detection**

EXP-001 detects when a webhook's raw input reaches a Code or Execute Command node without passing through a sanitisation node first.

For each pair of `(webhook node, dangerous node)` where the dangerous node's code references `$json.body.*` or `$json.query.*`, the rule calls `hasSanitizationBetween`:

```
hasSanitizationBetween(graph, "Webhook", "Run Script", sanitisationNodes)
```

This function performs a **depth-first search** that tracks whether every path from the webhook to the dangerous node passes through a sanitisation node (IF, Switch, Set, or Filter). It returns `true` only if sanitisation is present on **every** path — if there is even one unsanitised route, the violation fires.

```
Example A — FIRES (no sanitisation):
  Webhook → Run Script
  Path: Webhook → Run Script   (no sanitisation node seen)
  Result: EXP-001 violation

Example B — does NOT fire (sanitised):
  Webhook → Validate Input (IF node) → Run Script
  Path: Webhook → Validate Input → Run Script
  Sanitisation seen at: "Validate Input"
  Result: clear

Example C — FIRES (only one path is sanitised):
  Webhook → Validate Input (IF) → Run Script
          ↘ ─────────────────── → Run Script   (direct bypass)
  Path 1: Webhook → Validate Input → Run Script  (sanitised)
  Path 2: Webhook → Run Script                   (NOT sanitised)
  Result: EXP-001 violation
```

**HYG-002: Orphan detection**

HYG-002 collects all node names that appear as either the source or target of any connection. Any non-trigger node whose name does not appear in this set is an orphan with no path to or from the main flow.

Trigger nodes (Webhook, Schedule, anything ending in `Trigger`) are excluded from the orphan check — they legitimately have no incoming edges.

### Detection technique 6: PII expression matching (DP-002)

DP-002 looks for n8n expressions that reference known PII field names flowing into the body or headers of an outbound POST/PUT/PATCH request.

The rule builds a single regex at startup that matches any n8n expression referencing a PII field:

```
\$(?:json|node\[["'][^"']+["']\]\.json)\.(?:email|firstName|lastName|phone|ssn|...)\b
```

This matches all of:
- `$json.email`
- `$json.firstName`
- `$node["Get User"].json.phone`
- `$json.ssn`

The `\b` word boundary at the end ensures that a field named `emailTemplateId` does not match — only exact PII field names trigger the rule.

Only POST, PUT, and PATCH methods are checked. GET requests do not normally carry a body, and flagging them would create significant noise.

### AI enhancement layer

When `GEMINI_API_KEY` is set and the request includes `"ai": true`, the analyzer sends a compact summary of the workflow and static violations to `gemini-2.5-flash` for a second-pass review.

**Design principles:**
- **Always additive** — if the AI call fails, times out, or returns an invalid response, the static report is returned unchanged with a `warnings` field noting the failure. The AI layer never blocks the static results.
- **Compact prompt** — to keep token usage predictable, the prompt includes at most 80 nodes, code snippets are capped at 300 characters, and URLs at 120 characters. For large workflows, only nodes with violations (or non-disabled nodes) are included.
- **30-second hard timeout** — implemented via `Promise.race` so a slow AI response never hangs the HTTP request.

**What the AI adds beyond static rules:**

| Field | Description |
|---|---|
| `dataFlowRisks` | Cross-node data flow risks the static rules cannot detect — e.g. sensitive data leaking from node A to node C via an intermediate Set node |
| `falsePositiveNotes` | Static violations that appear to be safe given the full workflow context, with reasoning |
| `remediationPriority` | Ordered list of what to fix first, with a brief "why" for each item |
| `suggestedRedesigns` | Architectural suggestions — splitting workflows, adding sanitisation sub-workflows, replacing dangerous nodes |
| `summary` | 2–4 sentence plain-English narrative of the overall security posture |
| `confidence` | `"high"` / `"medium"` / `"low"` — indicates how much of the workflow the AI could reason about |

The AI result is attached to the report as `aiAnalysis`. If AI was not requested or not configured, `aiAnalysis` is absent from the response.

### AI fix suggestions

For any **critical**, **high**, or **medium** violation, the dashboard shows a **Suggest fix** button. Clicking it calls `POST /analyze/fix` which:

1. Sends the violation details and the offending node's current parameters to Gemini
2. Asks for a plain-English explanation and a patched `parameters` object (or `null` if the fix requires a manual action such as moving a secret to the n8n credential vault)
3. **Verifies the fix** — applies the patch in-memory, re-runs the analyzer, and checks whether the same rule still fires on the same node. If the violation is gone the response is marked `verified: true`

```json
{
  "explanation": "Replace the hardcoded Authorization header with a reference to an n8n HTTP Header Auth credential...",
  "patchedParameters": { "authentication": "headerAuth", ... },
  "verified": true,
  "verificationNote": "Re-analysis confirmed: applying this patch removes the violation."
}
```

Requires `GEMINI_API_KEY` to be set. Returns a `503` if the key is absent.

### Evidence redaction

When a rule finds a secret string, it never returns the full value in the `evidence` field. By default (`REDACT_EVIDENCE=true`), only the first 4 characters are kept and the rest is masked:

```
sk_live_ABCDEFGHIJKLMNOPQRSTUVWX  →  sk_l****REDACTED****
Bearer eyJhbGciOiJIUzI1NiJ9...   →  Bear****REDACTED****
```

This means the report is safe to share, log, or store — it identifies the type and location of the secret without exposing it.

Set `REDACT_EVIDENCE=false` only in controlled local debugging environments where the full value is needed.

### What the analyzer does NOT do

- **No execution** — the workflow is never triggered or simulated
- **No persistence** — nothing is logged, stored, or cached between requests
- **No mutation** — the workflow JSON is never modified
- **No telemetry** — no external calls other than Mode B fetch (explicit, user-supplied credentials) and AI features (opt-in, requires `GEMINI_API_KEY`)
- **No network scanning** — URLs in the workflow are parsed statically; the analyzer never connects to them

### Output

Every violation contains:

| Field | Description |
|---|---|
| `ruleId` | e.g. `SEC-001` |
| `severity` | `critical` / `high` / `medium` / `low` |
| `category` | Rule category |
| `title` | One-line summary |
| `description` | Full explanation with workflow-specific context (node name, field, matched value) |
| `node` | The offending node — `id`, `name`, `type`, `position` |
| `field` | Dot-path to the exact parameter where the issue was found |
| `evidence` | The matched value, redacted by default |
| `remediation` | Concrete, actionable fix instructions |

The report also includes:

| Field | Description |
|---|---|
| `summary` | Count of violations by severity, total nodes, rules passed |
| `passedRules` | Rule IDs that ran and found nothing — useful for auditing |
| `skippedRules` | Rule IDs disabled via `DISABLED_RULES` |
| `metadata` | Analyzer version, ruleset version, list of unique node types found |

---

## Rule catalogue

### Credentials

| Rule | Severity | What it detects |
|---|---|---|
| **SEC-001** | Critical | Hardcoded secret string in any node parameter. Matches 14 patterns: OpenAI (`sk-`), Anthropic (`sk-ant-`), GitHub PAT (`ghp_`), Slack (`xoxb-`), AWS access key (`AKIA`), Stripe live/test keys, Bearer tokens, Basic auth headers, and high-entropy strings in fields named `password`, `secret`, `token`, `apiKey`, etc. |
| **SEC-002** | High | Credential present in a URL query string. Matches query parameter names: `api_key`, `token`, `secret`, `password`, `access_token`, `auth`, and variants. |
| **SEC-003** | Medium | Credential set in a plain Set node. Inspects the user-defined field names inside Set node entries (both v1 `values.string[]` and v2 `assignments.assignments[]` formats). Fires when a field is named like a credential, or when its value matches a known secret pattern. |

**How SEC-001 avoids false positives:** only matches against values in node parameters, skips disabled nodes, skips `$credentials.` references (n8n vault), and requires a minimum entropy threshold for the generic high-entropy field check.

### Network

| Rule | Severity | What it detects |
|---|---|---|
| **NET-001** | High | HTTP Request node using `http://` instead of `https://`. Excludes localhost and private IP ranges (those are flagged separately by NET-003). |
| **NET-002** | High | `allowUnauthorizedCerts: true` on an HTTP Request node. Checks both `parameters.allowUnauthorizedCerts` and `parameters.options.allowUnauthorizedCerts` to cover different n8n versions. |
| **NET-003** | Medium | HTTP Request node targeting a private/internal network address. Covers: `10.x.x.x`, `192.168.x.x`, `172.16–31.x.x`, `127.x`, `localhost`, `169.254.x.x` (AWS metadata endpoint), IPv6 loopback `::1`, and hostnames ending in `.internal`, `.local`, `.svc.cluster.local`. |
| **NET-004** | Low | HTTP Request node URL is entirely an n8n expression with no static host component (e.g. `={{ $json.targetUrl }}`). The destination cannot be statically verified. Does not fire when only the path or query string is dynamic. |

### Data policy

| Rule | Severity | What it detects |
|---|---|---|
| **DP-001** | High | Webhook trigger with `authentication: "none"` (or no authentication field set). Creates an unauthenticated public endpoint. |
| **DP-002** | High | PII field referenced in a POST/PUT/PATCH HTTP Request node body or headers. Checks for n8n expressions referencing: `email`, `firstName`, `lastName`, `phone`, `ssn`, `nationalId`, `dateOfBirth`, `iban`, `creditCard`, `passport` (and snake_case variants). Uses word-boundary matching to avoid false positives on names like `emailTemplateId`. |
| **DP-003** | Medium | Database node (Postgres, MySQL, MongoDB, Redis) connecting to a host not in the `APPROVED_DB_HOSTS` list. Only fires when the host is a static string (credential-referenced connections cannot be inspected). |
| **DP-004** | Medium | `console.log`, `console.error`, `console.warn`, `console.info`, or `console.debug` in a Code or Function node. These write to execution logs which may be stored or exported, potentially leaking sensitive data. |
| **DP-005** | Low | Workflow processes external data (HTTP requests, webhooks, database queries) but has no Error Trigger node. Failed executions surface raw node inputs/outputs in n8n's execution log. |

### Dangerous nodes

| Rule | Severity | What it detects |
|---|---|---|
| **DN-001** | Critical | `executeCommand` node present in the workflow. Runs arbitrary shell commands on the n8n host. |
| **DN-002** | Critical | `ssh` node present. Establishes remote shell sessions — a compromise gives RCE on the SSH target. |
| **DN-003** | High | `code`, `function`, or `functionItem` node present. Arbitrary JavaScript with full Node.js runtime access. Flagged for manual review. |
| **DN-004** | Medium | `readWriteFile`, `readBinaryFile`, or `writeBinaryFile` node present. Local filesystem access on the n8n host. |

All dangerous-node rules produce one violation per matching node and respect the `disabled` flag.

### Expression injection

| Rule | Severity | What it detects |
|---|---|---|
| **EXP-001** | High | Raw webhook input (`$json.body.*`, `$json.query.*`, `$input.body`) flows into a Code or Execute Command node without any sanitisation node (IF, Switch, Set, or Filter) on every path between them. Uses full connection graph traversal — not just immediate neighbours. |
| **EXP-002** | Medium | n8n expression interpolated directly into a SQL query string. Matches any parameter value that contains both a SQL keyword (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, etc.) and a `$json.*` expression. Checks Postgres nodes, MySQL nodes, and Code nodes that build SQL strings. |

### Workflow hygiene

| Rule | Severity | What it detects |
|---|---|---|
| **HYG-001** | Low | Workflow is marked `active: true` but contains no trigger node (Webhook, Schedule, Cron, or any node whose type ends in `Trigger`). |
| **HYG-002** | Low | Orphaned nodes — non-trigger nodes with no connections to the rest of the workflow. Trigger nodes with no connections are normal and are excluded. |
| **HYG-003** | Low | Workflow name is a default placeholder: `My workflow`, `Untitled`, `Untitled Workflow`, `New Workflow`, or empty string (case-insensitive). |

---

## Quick start — CLI

```bash
# Analyze a workflow file
cd packages/api
npx tsx src/cli.ts path/to/workflow.json

# Pipe directly from n8n export
cat my-workflow.json | npx tsx src/cli.ts

# Analyze with a custom severity threshold (only high and critical)
SEVERITY_THRESHOLD=high npx tsx src/cli.ts workflow.json

# Keep evidence unredacted (for debugging)
REDACT_EVIDENCE=false npx tsx src/cli.ts workflow.json

# Disable specific rules
DISABLED_RULES=HYG-002,DP-005 npx tsx src/cli.ts workflow.json
```

The CLI exits `0` when there are no critical or high violations, and `1` when there are — suitable for use in CI pipelines.

Sample output:

```
═══ n8n Workflow Security Report ═══
Workflow : Payment Processor
Nodes    : 8  |  Node types: webhook, httpRequest, postgres, set, code

Summary: 4 violation(s) — 1 critical · 2 high · 1 medium · 18 passed

─── CREDENTIALS ───

  ● CRITICAL  [SEC-001] Hardcoded Stripe key detected
  Node: "Call Stripe" (n8n-nodes-base.httpRequest)
  Field: parameters.headerParameters.values[0].value
  Evidence: sk_l****REDACTED****
  → Move this credential to n8n's credential vault.

─── EXPRESSION INJECTION ───

  ▲ HIGH      [EXP-001] Unsanitised webhook input reaches "Run Script"
  → Add an IF or Set node between the webhook and the code node.
```

---

## Quick start — API server

```bash
# Install dependencies and build shared types
npm install
npm run build -w types

# Start the API server (port 3000 by default)
npm run dev -w api

# Start with AI enhancement enabled
ANTHROPIC_API_KEY=sk-ant-... npm run dev -w api
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check — returns `{ status: "ok", version: "1.0.0" }` |
| `GET` | `/rules` | Full rule catalogue — supports `?category=` and `?severity=` filters |
| `POST` | `/analyze` | Analyze a single workflow (Mode A or Mode B, optional AI) |
| `POST` | `/analyze/batch` | Analyze up to 20 workflows in parallel |
| `POST` | `/analyze/fix` | AI-generated fix suggestion for a single violation, with verification |

### Mode A: inline workflow JSON

Send the exported workflow object in the request body. No n8n instance needed.

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "workflow": { "id": "abc", "name": "My Workflow", "active": true, "nodes": [...], "connections": {} }
  }'
```

### Mode B: fetch from live n8n

Provide your n8n base URL, API key, and a workflow ID. The server fetches the workflow using `GET /api/v1/workflows/:id` with the `X-N8N-API-KEY` header.

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "n8n": {
      "baseUrl": "https://my-n8n.example.com",
      "apiKey": "your-n8n-api-key",
      "workflowId": "abc123"
    }
  }'
```

**Mode B error responses:**

| HTTP status | Cause |
|---|---|
| `400` | Invalid n8n API key (401 from n8n) |
| `404` | Workflow ID not found on the n8n instance |
| `502` | n8n returned a non-workflow response |
| `504` | n8n did not respond within `N8N_FETCH_TIMEOUT_MS` |

### Batch analysis

```bash
curl -X POST http://localhost:3000/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{
    "workflows": [
      { "workflow": { ... } },
      { "n8n": { "baseUrl": "...", "apiKey": "...", "workflowId": "wf2" } }
    ],
    "ai": false
  }'
```

The response is an array where each entry is either an `AnalysisReport` or `{ "error": "..." }` if that individual workflow failed. Other workflows in the batch are unaffected.

### AI enhancement

Add `"ai": true` to any `/analyze` or `/analyze/batch` request. Requires `ANTHROPIC_API_KEY` to be set on the server.

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "workflow": { ... },
    "ai": true
  }'
```

The response includes an `aiAnalysis` object alongside the standard report:

```json
{
  "summary": { ... },
  "violations": [ ... ],
  "aiAnalysis": {
    "summary": "This workflow exposes a critical RCE vector...",
    "confidence": "high",
    "dataFlowRisks": ["Webhook body flows unvalidated into Execute Command node..."],
    "falsePositiveNotes": [],
    "remediationPriority": ["Fix EXP-001 first — direct RCE if triggered by an attacker..."],
    "suggestedRedesigns": ["Replace Execute Command with a Code node and whitelist allowed commands..."]
  }
}
```

If AI is unavailable or times out, `aiAnalysis` is `null` and `warnings` contains `"AI analysis unavailable"`. The static violations are always returned.

### Fix suggestions

```bash
curl -X POST http://localhost:3000/analyze/fix \
  -H "Content-Type: application/json" \
  -d '{
    "violation": { "ruleId": "SEC-001", "severity": "critical", ... },
    "node": { "name": "Call Stripe", "type": "n8n-nodes-base.httpRequest", "parameters": { ... } },
    "workflow": { ... }
  }'
```

Requires `GEMINI_API_KEY`. Returns `503` if the key is absent.

### Rules endpoint

```bash
# All rules
curl http://localhost:3000/rules

# Only critical-severity rules
curl "http://localhost:3000/rules?severity=critical"

# Only credential rules
curl "http://localhost:3000/rules?category=credentials"
```

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and adjust:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port for the API server |
| `CORS_ORIGIN` | `*` | CORS allowed origin for the dashboard |
| `REQUEST_SIZE_LIMIT` | `5mb` | Max body size for workflow JSON payloads |
| `APPROVED_DB_HOSTS` | `""` | Comma-separated approved database hostnames; suppresses DP-003 for these hosts. Example: `db.internal,postgres.prod` |
| `DISABLED_RULES` | `""` | Comma-separated rule IDs to skip globally. Example: `HYG-002,DP-005` |
| `SEVERITY_THRESHOLD` | `low` | Minimum severity to include in output: `low`, `medium`, `high`, or `critical` |
| `REDACT_EVIDENCE` | `true` | Mask matched secret strings in the `evidence` field. Keeps first 4 chars: `sk_l****REDACTED****` |
| `GEMINI_API_KEY` | `""` | Enables AI enhancement and fix suggestions (Gemini 2.5 Flash). Leave blank for static-analysis-only mode. |
| `N8N_FETCH_TIMEOUT_MS` | `5000` | Timeout in ms for Mode B fetches from a live n8n instance |

---

## Project structure

```
n8n-workflow-analyzer/
├── packages/
│   ├── types/                          # Shared TypeScript interfaces
│   │   └── src/index.ts                # N8nWorkflow, Violation, AnalysisReport, ...
│   │
│   ├── api/                            # Backend analyzer + REST API
│   │   ├── src/
│   │   │   ├── index.ts                # Fastify server bootstrap
│   │   │   ├── cli.ts                  # CLI runner for direct file analysis
│   │   │   ├── config.ts               # Env var parsing → typed Config object
│   │   │   ├── fetcher.ts              # Mode B: fetch workflow from live n8n
│   │   │   ├── routes/
│   │   │   │   ├── health.ts           # GET /health
│   │   │   │   ├── rules.ts            # GET /rules?category=&severity=
│   │   │   │   ├── analyze.ts          # POST /analyze, POST /analyze/batch
│   │   │   │   └── fix.ts              # POST /analyze/fix — AI fix suggestion + verification
│   │   │   └── analyzer/
│   │   │       ├── index.ts            # Orchestrator: runs all rules, builds report
│   │   │       ├── ai.ts               # AI layer: workflow analysis + fix suggestions (Gemini)
│   │   │       ├── types.ts            # RuleRunner, RuleContext interfaces
│   │   │       ├── utils.ts            # Parameter walker, URL helpers, graph tools
│   │   │       └── rules/
│   │   │           ├── credentials.ts  # SEC-001, SEC-002, SEC-003
│   │   │           ├── network.ts      # NET-001, NET-002, NET-003, NET-004
│   │   │           ├── data-policy.ts  # DP-001, DP-002, DP-003, DP-004, DP-005
│   │   │           ├── dangerous-nodes.ts  # DN-001, DN-002, DN-003, DN-004
│   │   │           ├── expression-injection.ts  # EXP-001, EXP-002
│   │   │           ├── hygiene.ts      # HYG-001, HYG-002, HYG-003
│   │   │           └── index.ts        # Barrel: exports ALL_RULES[]
│   │   └── tests/
│   │       ├── helpers.ts              # Node builders, workflow builder, assertions
│   │       ├── orchestrator.test.ts    # End-to-end orchestrator tests
│   │       ├── fixtures/               # Real workflow JSON files for integration tests
│   │       └── rules/                  # One test file per rule category
│   │
│   └── ui/                             # React dashboard
│       └── src/
│           ├── App.tsx
│           ├── components/Nav.tsx      # Top navigation bar
│           ├── api/client.ts           # Typed axios wrapper (submitWorkflow, suggestFix, getRules)
│           └── pages/
│               ├── SubmitPage.tsx      # Workflow submission form + inline report + fix suggestions
│               └── RulesPage.tsx       # Filterable rule catalogue
│
├── .env.example                        # Environment variable template (commit this)
├── .env                                # Your local secrets (gitignored)
├── .gitignore
└── package.json                        # npm workspaces root
```

---

## Test suite

### Running the tests

```bash
# Run all tests once
npm test -w api

# Run in watch mode (re-runs on file change)
npm run test:watch -w api

# Run a single test file
cd packages/api && npx vitest run tests/rules/credentials.test.ts

# Run tests matching a pattern
cd packages/api && npx vitest run --reporter=verbose -t "SEC-001"
```

### Test design philosophy

Every rule has two kinds of test cases:

**True positive tests** — confirm the rule fires when it should. Each test constructs the minimal workflow that triggers the rule, runs it, and asserts the correct `ruleId` appears in the violations.

**False positive tests** — confirm the rule stays silent when it should. These are labelled `does NOT fire on...` and cover the most likely sources of noise: safe variants of the dangerous pattern, disabled nodes, non-matching node types, and edge cases in the detection logic.

Tests use a fluent builder API in `tests/helpers.ts` so each test reads like a specification:

```ts
it("fires on ?api_key= in URL", () => {
  const wf = workflow([
    httpNode("API", { url: "https://api.example.com/data?api_key=supersecret123" }),
  ]);
  expectRule(run(credentialsRules, wf), "SEC-002");
});

it("does NOT fire on a URL with only safe query params", () => {
  const wf = workflow([
    httpNode("Safe", { url: "https://api.example.com/users?page=1&limit=20" }),
  ]);
  expectNoRule(run(credentialsRules, wf), "SEC-002");
});
```

### Test files

#### `tests/rules/credentials.test.ts` — 27 tests

| Group | Tests |
|---|---|
| **SEC-001 — hardcoded secret** | Fires on: Bearer token, OpenAI `sk-`, Anthropic `sk-ant-`, GitHub PAT `ghp_`, Slack `xoxb-`, AWS AKIA, Stripe `sk_live_`, high-entropy `password` field, high-entropy `apiKey` field. Does not fire on: plain URL, short low-entropy string, node with no params, disabled node. |
| **SEC-002 — credential in URL** | Fires on: `?api_key=`, `?token=`, `?secret=`, `?password=`, `?access_token=`. Does not fire on: safe query params, no query string, plain description string, fully dynamic URL expression. |
| **SEC-003 — Set node credential** | Fires on: field named `apiKey`, field named `password`, field value matching a secret pattern. Does not fire on: innocent field names, HTTP node (wrong type), disabled Set node. |

#### `tests/rules/network.test.ts` — 26 tests

| Group | Tests |
|---|---|
| **NET-001 — unencrypted HTTP** | Fires on: `http://external.com`, mixed-case `HTTP://`. Does not fire on: `https://`, `http://localhost` (NET-003 territory), `http://127.0.0.1`, non-HTTP node, fully dynamic URL. |
| **NET-002 — SSL disabled** | Fires on: `allowUnauthorizedCerts: true` at top level, `allowUnauthorizedCerts: true` inside `options`. Does not fire on: `false`, absent flag, disabled node. |
| **NET-003 — private host / SSRF** | Fires on all 8 private address classes: `10.x`, `192.168.x`, `172.16–31.x`, `localhost`, `127.0.0.1`, `169.254.x` (AWS metadata), `.internal` suffix, `.local` suffix. Does not fire on: public HTTPS URL, private IP in a description string (not a URL). |
| **NET-004 — fully dynamic URL** | Fires on: `={{ $json.targetUrl }}`, `{{ $json.url }}`. Does not fire on: static URL, URL with static host and dynamic path only. |

#### `tests/rules/data-policy.test.ts` — 37 tests

| Group | Tests |
|---|---|
| **DP-001 — unauthenticated webhook** | Fires on: `authentication: "none"`, missing field, empty string. Does not fire on: `headerAuth`, `basicAuth`, non-webhook node, disabled node. |
| **DP-002 — PII in HTTP request** | Fires on all 10 PII fields (`email`, `firstName`, `lastName`, `phone`, `ssn`, `nationalId`, `dateOfBirth`, `iban`, `creditCard`, `passport`) in POST bodies; also PUT. Does not fire on: GET requests, no PII fields, `emailTemplateId` (word-boundary guard). |
| **DP-003 — unapproved DB host** | Fires on: postgres with unapproved host, any DB node when approved list is empty. Does not fire on: host in approved list, credential-referenced (no static host), non-DB nodes. Case-insensitive matching. |
| **DP-004 — console.log** | Fires on: `console.log`, `console.error`, `console.warn`; also Function node type. Does not fire on: code with no console calls, `console.log` text in a non-code node description, disabled node. |
| **DP-005 — no error handler** | Fires on: HTTP node without error trigger, webhook without error trigger, postgres without error trigger. Does not fire on: error trigger present, no external data nodes, empty workflow. |

#### `tests/rules/dangerous-nodes.test.ts` — 18 tests

| Group | Tests |
|---|---|
| **DN-001 — executeCommand** | Fires when present; produces one violation per node. Does not fire on: schedule trigger, disabled node. |
| **DN-002 — SSH** | Fires when present. Does not fire on: other node types, disabled node. |
| **DN-003 — Code node** | Fires on `code`, `function`, `functionItem` types; one violation per node. Does not fire on: non-code nodes, disabled node. |
| **DN-004 — filesystem** | Fires on all three file node types (`readWriteFile`, `readBinaryFile`, `writeBinaryFile`). Does not fire on: code node (different rule), disabled node. |

#### `tests/rules/expression-injection.test.ts` — 15 tests

| Group | Tests |
|---|---|
| **EXP-001 — unsanitised webhook → code** | Fires on: webhook → code node with `$json.body` reference, webhook → executeCommand with `$json.body`, webhook → code with `$json.query`. Does not fire on: Set node sanitising between them, IF node sanitising between them, code with no `$json.body` reference, no webhook in workflow, code node not reachable from webhook. |
| **EXP-002 — SQL injection** | Fires on: `SELECT ... WHERE field = '{{ $json.x }}'` in postgres, MySQL, INSERT with interpolation, code node building SQL string. Does not fire on: parameterised query (`WHERE email = $1`), query string with no SQL keyword, SQL-like text in a non-DB node. |

#### `tests/rules/hygiene.test.ts` — 20 tests

| Group | Tests |
|---|---|
| **HYG-001 — no trigger** | Fires on: `active: true` with no trigger node. Does not fire on: `active: false`, webhook trigger present, schedule trigger present, `active` undefined. |
| **HYG-002 — orphaned nodes** | Fires on: disconnected non-trigger node; counts multiple orphans correctly. Does not fire on: trigger node with no connections (normal), node connected as a target, fully connected chain, disabled orphan, empty workflow. |
| **HYG-003 — default name** | Fires on 7 default name variants: `My workflow`, `my workflow` (case-insensitive), `Untitled`, `UNTITLED`, `Untitled Workflow`, `New Workflow`, `""`. Does not fire on: meaningful name, name containing the word "workflow" in a non-default context, `undefined` name. |

#### `tests/orchestrator.test.ts` — 14 tests

End-to-end tests covering the full analysis pipeline:

| Group | Tests |
|---|---|
| **Clean workflow** | Zero violations on a safe workflow; correct metadata (id, name, version, node types, ISO8601 timestamp). |
| **Severity threshold** | All violations at `low`; only high+ at `medium` threshold; only critical at `critical` threshold. |
| **Disabled rules** | Disabled rules absent from violations and listed in `skippedRules`; other rules still run. |
| **Passed rules** | Rules that fired no violations appear in `passedRules`; violated rules do not. |
| **Evidence redaction** | `REDACT_EVIDENCE=true` masks secrets; `REDACT_EVIDENCE=false` returns them in full. |
| **Summary counts** | `totalNodes` matches workflow node count; `critical + high + medium + low == totalViolations`. |
| **Fixture files** | Clean fixture → 0 violations; credentials fixture → SEC-001 critical; dangerous-nodes fixture → DN-001/DN-002 critical; injection fixture → EXP-001 + EXP-002. |

### Test fixtures

Four JSON workflow files in `tests/fixtures/` are used as integration test inputs:

| File | Purpose | Violations expected |
|---|---|---|
| `clean-workflow.json` | A correctly built workflow with no issues | 0 |
| `hardcoded-credentials.json` | Stripe key in URL, Bearer token in header, GitHub PAT in Set node, unauthenticated webhook | SEC-001 (critical), SEC-002 (high), DP-001 (high) |
| `dangerous-nodes.json` | executeCommand, SSH, Code with console.log, filesystem read | DN-001 (critical), DN-002 (critical), DN-003 (high), DN-004 (medium), DP-004 (medium) |
| `expression-injection.json` | Webhook → Code with `eval($json.body.script)`, SQL with `$json.body.username` | EXP-001 (high), EXP-002 (medium) |

---

## Development

```bash
# Install all dependencies
npm install

# Build all packages
npm run build

# Start the API server in watch mode (default port 3000)
npm run dev -w api

# Start with AI enhancement (set in .env or inline)
GEMINI_API_KEY=your-key npm run dev -w api

# Type-check without building
npm run lint -w api
npm run lint -w ui

# Analyze a workflow directly (no server needed)
cd packages/api
npx tsx src/cli.ts tests/fixtures/hardcoded-credentials.json

# Quick API smoke test (server must be running)
curl http://localhost:3000/health
curl "http://localhost:3000/rules?severity=critical"
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/dangerous-nodes.json  # wrap in { "workflow": ... }
```

### Adding a new rule

1. Pick a rule ID following the existing pattern (`SEC-004`, `NET-005`, etc.)
2. Add the `RuleRunner` object to the appropriate file in `src/analyzer/rules/`
3. Export it from the file's array (e.g. `credentialsRules`)
4. It is automatically registered — no changes needed to `index.ts` or the orchestrator
5. Add tests: at least one true-positive case and one false-positive guard
