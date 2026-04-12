# n8n Workflow Analyzer

Static analysis for n8n workflows covering security, reliability, performance, maintainability, and operational hygiene. Paste a workflow JSON and get a structured report of every vulnerability, misconfiguration, and design quality issue — without ever executing the workflow.

→ **[Rule Catalogue](RULES.md)** — all 61 rules with descriptions and remediation guidance  
→ **[Development Guide](DEVELOPMENT.md)** — how the engine works, detection techniques, AI layer, test suite

---

## Quick start

```bash
# 1. Install dependencies
npm install

# 2. Copy env template and fill in what you need (Gemini key is optional)
cp .env.example .env

# 3. Start everything
npm run dev        # API on :3000 + UI on :5173
```

Open **http://localhost:5173** — paste a workflow JSON, click **Analyze workflow**.

---

## Quick start — CLI

Analyze a workflow file without the server:

```bash
cd packages/api

# Single file
npx tsx src/cli.ts path/to/workflow.json

# Entire directory (recursive)
npx tsx src/cli.ts workflows/

# From stdin
cat my-workflow.json | npx tsx src/cli.ts

# Only report high and critical
SEVERITY_THRESHOLD=high npx tsx src/cli.ts workflow.json

# Disable specific rules
DISABLED_RULES=HYG-002,DP-005 npx tsx src/cli.ts workflow.json

# Enforce an egress allowlist (DP-006)
APPROVED_EGRESS_HOSTS=api.stripe.com,hooks.slack.com npx tsx src/cli.ts workflow.json

# SARIF output (for GitHub Code Scanning / CI)
npx tsx src/cli.ts --format sarif --output results.sarif workflows/
```

The CLI exits `0` when there are no critical or high violations and `1` when there are — suitable for CI pipelines.

---

## GitHub Integration

Export your n8n workflows as JSON, commit them to your repo, and add the Action to automatically scan them on every push and pull request. Findings appear inline in the **Security → Code scanning** tab.

**1. Add the workflow file** at `.github/workflows/n8n-security.yml`:

```yaml
name: n8n Security Scan
on:
  push:
    branches: [main]
    paths: ["**.json"]
  pull_request:
    paths: ["**.json"]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Bmat123/n8n_analyser@main
        with:
          workflow-path: "."      # directory containing your workflow JSON files
          severity-threshold: low
          fail-on: high           # fail CI on critical or high violations
          upload-sarif: "true"    # post findings to GitHub Code Scanning
```

**2. Export workflows** from n8n: `Workflow → ⋮ → Export → Download`, commit the JSON files to your repo.

**3. Results** appear in three places:
- **Actions tab** — step summary with violation counts per run
- **Security → Code scanning** — full findings with rule descriptions and remediation guidance
- **Pull request checks** — inline annotations on changed workflow files

A pre-built example is at [`.github/workflows/n8n-security.yml`](.github/workflows/n8n-security.yml).

| Action input | Default | Description |
|---|---|---|
| `workflow-path` | `.` | File or directory to scan |
| `severity-threshold` | `low` | Minimum severity to include |
| `fail-on` | `high` | Fail CI at this severity or above (`critical`/`high`/`medium`/`none`) |
| `disabled-rules` | `""` | Comma-separated rule IDs to skip |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning |

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

─── DATA POLICY ───

  ◆ MEDIUM    [DP-006] HTTP Request contacts unapproved host: "api.unknown-tracker.io"
  Node: "Send Analytics" (n8n-nodes-base.httpRequest)
  Field: parameters.url
  Evidence: api.unknown-tracker.io
  → Add this host to APPROVED_EGRESS_HOSTS if authorised, or remove the node.

─── RELIABILITY ───

  ▲ HIGH      [DQ-001] 'Continue on Error' set on critical node "Insert Record"
  Node: "Insert Record" (n8n-nodes-base.postgres)
  → Remove continueOnFail or add an explicit IF node to handle the failure case.

─── EXPRESSION INJECTION ───

  ▲ HIGH      [EXP-001] Unsanitised webhook input reaches "Run Script"
  → Add an IF or Set node between the webhook and the code node.
```

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `GET` | `/rules` | Rule catalogue — supports `?category=` and `?severity=` |
| `POST` | `/analyze` | Analyze a single workflow (Mode A or Mode B, optional AI) |
| `POST` | `/analyze/batch` | Analyze up to 20 workflows in parallel |
| `POST` | `/analyze/fix` | AI-generated fix suggestion for a single violation, with verification |

### Mode A — inline JSON

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{ "workflow": { "id": "abc", "name": "My Workflow", "nodes": [...], "connections": {} } }'
```

### Mode B — fetch from live n8n

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

| HTTP status | Cause |
|---|---|
| `400` | Invalid n8n API key |
| `404` | Workflow ID not found |
| `502` | Unexpected response from n8n |
| `504` | n8n timed out |

### AI enhancement

Add `"ai": true` to any `/analyze` request. Requires `GEMINI_API_KEY`.

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{ "workflow": { ... }, "ai": true }'
```

The response gains an `aiAnalysis` object with `summary`, `dataFlowRisks`, `remediationPriority`, `falsePositiveNotes`, `suggestedRedesigns`, and `confidence`. If the AI call fails, `aiAnalysis` is `null` and the static violations are still returned.

### Fix suggestions

For any critical/high/medium violation the dashboard shows a **Suggest fix** button, which calls:

```bash
curl -X POST http://localhost:3000/analyze/fix \
  -H "Content-Type: application/json" \
  -d '{ "violation": { ... }, "node": { ... }, "workflow": { ... } }'
```

Gemini returns an explanation and a patched `parameters` object. The API then re-runs the analyzer to verify the fix actually removes the violation before returning.

---

## Configuration

Copy `.env.example` to `.env` and set the values you need:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port for the API server |
| `CORS_ORIGIN` | `*` | CORS allowed origin |
| `REQUEST_SIZE_LIMIT` | `5mb` | Max request body size |
| `APPROVED_DB_HOSTS` | `""` | Comma-separated DB hostnames that suppress DP-003 |
| `APPROVED_EGRESS_HOSTS` | `""` | Comma-separated allowed outbound HTTP hostnames. When set, enables DP-006 and flags any HTTP Request node calling a host outside this list |
| `DISABLED_RULES` | `""` | Comma-separated rule IDs to skip globally |
| `SEVERITY_THRESHOLD` | `low` | Minimum severity to include in output |
| `REDACT_EVIDENCE` | `true` | Mask matched secrets in the `evidence` field |
| `GEMINI_API_KEY` | `""` | Enables AI analysis and fix suggestions |
| `N8N_FETCH_TIMEOUT_MS` | `5000` | Timeout for Mode B n8n fetches |
| `MAX_NODES_BEFORE_DECOMP_WARNING` | `20` | Node count threshold for DQ-005 monolithic workflow warning |
| `MAX_NODES_HARD_LIMIT` | `40` | Node count that escalates DQ-005 to high severity |
| `LOOP_RATE_LIMIT_EXEMPTIONS` | `""` | Comma-separated loop node names exempt from DQ-003 |
| `INCLUDE_ADVISORY` | `true` | Include low-confidence advisory violations (DQ-013, PERF-003) |
| `CURRENCY_FIELD_NAMES` | `price,amount,total,cost,fee,rate,tax,discount,subtotal` | Field names DQ-012 treats as monetary values |

### Egress allowlist (DP-006)

Setting `APPROVED_EGRESS_HOSTS` turns on an outbound HTTP allowlist. Every HTTP Request node whose destination hostname is not on the list triggers a medium violation. This is the primary control for catching data leaking to unexpected third parties.

```bash
# .env
APPROVED_EGRESS_HOSTS=api.stripe.com,api.sendgrid.com,hooks.slack.com,api.github.com
```

Leave it empty (the default) to run without egress enforcement — useful when you are still inventorying your workflows.

---

## Rule categories

| Category | Rules | Focus |
|---|---|---|
| Credentials | SEC-001 – SEC-003 | Hardcoded secrets, keys in URLs, credentials in Set nodes |
| Network | NET-001 – NET-004 | Unencrypted HTTP, disabled TLS, SSRF, dynamic URLs |
| Data Policy | DP-001 – DP-006 | Webhook auth, PII in requests, unapproved DB/egress hosts, console.log, missing error handlers |
| Dangerous Nodes | DN-001 – DN-003 | Shell execution, SSH, file read/write |
| Expression Injection | EXP-001 – EXP-004 | Unsanitised webhook input, `$env.*` leakage, sandbox escapes |
| Hygiene | HYG-001 – HYG-004 | No trigger, inactive workflows, missing sticky notes, all triggers disabled |
| Supply Chain | SC-001 – SC-004 | n8n self-API pivot, community nodes, dangerous code patterns, raw content hosts |
| Data Flow | DF-001 – DF-003 | Webhook echo, DB→cloud exfiltration, DB→chat leakage |
| Loop & Flow | LF-001 – LF-002 | Sub-minute cron, self-recursive workflow |
| Reliability | REL-001, REL-002, REL-004, DQ-001, DQ-002, DQ-008, OP-003 | Timeouts, retry backoff, idempotency, continueOnFail overuse, HTTP response validation, DB error handlers |
| Performance | DQ-003, DQ-004, PERF-001 – PERF-004 | Unthrottled loops, full table scans, N+1 queries, sub-minute polling, unbounded result sets, duplicate API calls |
| Maintainability | DQ-005 – DQ-007, DQ-011, OP-004, MAINT-001, MAINT-002 | Monolithic workflows, default node names, missing documentation, credential sprawl, deep expression chains |
| Data Quality | DQ-009, DQ-010, DQ-012, DQ-013 | Webhook input validation, timezone-naive dates, currency rounding, hardcoded business constants |
| Observability | OP-001, OP-002, OP-005, OP-006 | Execution saving disabled, silent error workflows, ambiguous success states, debug console.log |

Full descriptions and remediation guidance for all 61 rules: **[RULES.md](RULES.md)**

---

## Violation confidence levels

Most rules fire only when the evidence is conclusive. Rules that involve graph heuristics or pattern-matching can produce occasional false positives and are tagged with a `confidence` level:

| Level | Meaning |
|---|---|
| *(none)* | Certain — the pattern is unambiguous |
| `probable` | High likelihood but graph traversal may miss context (e.g. dedup check is 5 hops upstream) |
| `advisory` | Low-confidence heuristic — useful signal but verify before acting. Suppressed by `INCLUDE_ADVISORY=false` |

---

## Project structure

```
n8n-workflow-analyzer/
├── packages/
│   ├── types/                          # Shared TypeScript interfaces
│   │   └── src/index.ts
│   │
│   ├── api/                            # Fastify API + rule engine
│   │   ├── src/
│   │   │   ├── index.ts                # Server bootstrap
│   │   │   ├── cli.ts                  # CLI runner
│   │   │   ├── config.ts               # Env → typed Config
│   │   │   ├── fetcher.ts              # Mode B: fetch from live n8n
│   │   │   ├── sarif.ts                # SARIF 2.1.0 serializer
│   │   │   ├── routes/
│   │   │   │   ├── health.ts
│   │   │   │   ├── rules.ts
│   │   │   │   ├── analyze.ts
│   │   │   │   └── fix.ts
│   │   │   └── analyzer/
│   │   │       ├── index.ts            # Orchestrator
│   │   │       ├── ai.ts               # Gemini: analysis + fix suggestions
│   │   │       ├── utils.ts            # Walker, URL helpers, graph tools
│   │   │       └── rules/
│   │   │           ├── credentials.ts  # SEC rules
│   │   │           ├── network.ts      # NET rules
│   │   │           ├── data-policy.ts  # DP rules
│   │   │           ├── dangerous-nodes.ts  # DN rules
│   │   │           ├── expression-injection.ts  # EXP rules
│   │   │           ├── hygiene.ts      # HYG rules
│   │   │           ├── supply-chain.ts # SC rules
│   │   │           ├── data-flow.ts    # DF rules
│   │   │           ├── loop-flow.ts    # LF rules
│   │   │           ├── reliability.ts  # REL/DQ/OP reliability rules
│   │   │           ├── performance.ts  # DQ/PERF performance rules
│   │   │           ├── maintainability.ts  # DQ/OP/MAINT rules
│   │   │           ├── data-quality.ts # DQ data quality rules
│   │   │           └── observability.ts  # OP observability rules
│   │   └── tests/
│   │       ├── helpers.ts
│   │       ├── orchestrator.test.ts
│   │       ├── fixtures/
│   │       └── rules/                  # One test file per rule module
│   │
│   └── ui/                             # React dashboard
│       └── src/
│           ├── App.tsx
│           ├── components/Nav.tsx
│           ├── api/client.ts
│           └── pages/
│               ├── SubmitPage.tsx      # Submit + inline report + fix suggestions
│               └── RulesPage.tsx       # Rule catalogue browser
│
├── action.yml                          # GitHub composite Action
├── .github/workflows/n8n-security.yml  # Example CI workflow
├── .env.example                        # Template — safe to commit
├── .env                                # Your secrets — gitignored
├── .gitignore
└── package.json
```

---

## License

Non-commercial use only. See [LICENSE](LICENSE).
