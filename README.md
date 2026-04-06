# n8n Workflow Security Analyzer

Static security and data-policy analysis for n8n workflows. Paste a workflow JSON and get a structured report of every vulnerability, misconfiguration, and policy violation — without ever executing the workflow.

→ **[Rule Catalogue](RULES.md)** — all 20 rules with descriptions and remediation guidance  
→ **[Development Guide](DEVELOPMENT.md)** — how the engine works, detection techniques, AI layer, test suite

---

## Quick start

```bash
# 1. Install dependencies
npm install

# 2. Copy env template and add your Gemini key (optional — needed for AI features)
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
| `DISABLED_RULES` | `""` | Comma-separated rule IDs to skip globally |
| `SEVERITY_THRESHOLD` | `low` | Minimum severity to include in output |
| `REDACT_EVIDENCE` | `true` | Mask matched secrets in the `evidence` field |
| `GEMINI_API_KEY` | `""` | Enables AI analysis and fix suggestions |
| `N8N_FETCH_TIMEOUT_MS` | `5000` | Timeout for Mode B n8n fetches |

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
│   │   │   ├── routes/
│   │   │   │   ├── health.ts
│   │   │   │   ├── rules.ts
│   │   │   │   ├── analyze.ts
│   │   │   │   └── fix.ts
│   │   │   └── analyzer/
│   │   │       ├── index.ts            # Orchestrator
│   │   │       ├── ai.ts               # Gemini: analysis + fix suggestions
│   │   │       ├── utils.ts            # Walker, URL helpers, graph tools
│   │   │       └── rules/              # SEC, NET, DP, DN, EXP, HYG
│   │   └── tests/
│   │       ├── helpers.ts
│   │       ├── orchestrator.test.ts
│   │       ├── fixtures/
│   │       └── rules/
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
├── .env.example                        # Template — safe to commit
├── .env                                # Your secrets — gitignored
├── .gitignore
└── package.json
```

---

## License

Non-commercial use only. See [LICENSE](LICENSE).
