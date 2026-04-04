# Rule Catalogue

20 rules across 6 categories. Every rule is a pure function — given the same workflow and config it always returns the same violations.

Browse rules in the dashboard at **http://localhost:5173/rules**, or query the API:

```bash
curl "http://localhost:3000/rules"
curl "http://localhost:3000/rules?severity=critical"
curl "http://localhost:3000/rules?category=credentials"
```

---

## Credentials

| Rule | Severity | What it detects |
|---|---|---|
| **SEC-001** | Critical | Hardcoded secret in any node parameter. Matches 14 patterns: OpenAI (`sk-`), Anthropic (`sk-ant-`), GitHub PAT (`ghp_`), Slack (`xoxb-`), AWS access key (`AKIA`), Stripe live/test keys, Bearer tokens, Basic auth headers, plus high-entropy strings in fields named `password`, `secret`, `token`, `apiKey`, etc. |
| **SEC-002** | High | Credential in a URL query string. Matches query parameter names: `api_key`, `token`, `secret`, `password`, `access_token`, `auth`, and variants. |
| **SEC-003** | Medium | Credential stored in a Set node field. Reads both n8n v1 (`values.string[]`) and v2 (`assignments.assignments[]`) shapes. Fires when a field name looks like a credential or when its value matches a known secret pattern. |

**SEC-001 false-positive guards:** skips disabled nodes, skips `$credentials.` references (n8n vault), requires minimum entropy for the high-entropy field heuristic.

---

## Network

| Rule | Severity | What it detects |
|---|---|---|
| **NET-001** | High | HTTP Request node using `http://` instead of `https://`. Excludes localhost and private IPs (those are NET-003). |
| **NET-002** | High | `allowUnauthorizedCerts: true` on an HTTP Request node. Checks both `parameters.allowUnauthorizedCerts` and `parameters.options.allowUnauthorizedCerts`. |
| **NET-003** | Medium | HTTP Request targeting a private/internal address: `10.x`, `192.168.x`, `172.16–31.x`, `127.x`, `localhost`, `169.254.x` (AWS metadata), `::1`, or hostnames ending in `.internal`, `.local`, `.svc.cluster.local`. |
| **NET-004** | Low | URL is entirely a dynamic expression with no static host (e.g. `={{ $json.targetUrl }}`). Does not fire when only the path or query string is dynamic. |

---

## Data Policy

| Rule | Severity | What it detects |
|---|---|---|
| **DP-001** | High | Webhook trigger with `authentication: "none"` or no authentication field — creates an unauthenticated public endpoint. |
| **DP-002** | High | PII field referenced in a POST/PUT/PATCH request body or headers. Detects n8n expressions for: `email`, `firstName`, `lastName`, `phone`, `ssn`, `nationalId`, `dateOfBirth`, `iban`, `creditCard`, `passport` (and snake_case variants). Word-boundary matching prevents false positives on names like `emailTemplateId`. |
| **DP-003** | Medium | Database node (Postgres, MySQL, MongoDB, Redis) connecting to a host not in the `APPROVED_DB_HOSTS` list. Only fires for static hostnames. |
| **DP-004** | Medium | `console.log/error/warn/info/debug` in a Code or Function node — execution logs may be stored or exported, potentially leaking data. |
| **DP-005** | Low | Workflow processes external data (HTTP, webhooks, database) but has no Error Trigger node. Failed executions expose raw node inputs/outputs in n8n's execution log. |

---

## Dangerous Nodes

| Rule | Severity | What it detects |
|---|---|---|
| **DN-001** | Critical | `executeCommand` node — runs arbitrary shell commands on the n8n host. |
| **DN-002** | Critical | `ssh` node — remote shell access; a compromise gives RCE on the target. |
| **DN-003** | High | `code`, `function`, or `functionItem` node — arbitrary JavaScript with full Node.js runtime access. Flagged for manual review. |
| **DN-004** | Medium | `readWriteFile`, `readBinaryFile`, or `writeBinaryFile` node — local filesystem access on the n8n host. |

All rules produce one violation per matching node and respect the `disabled` flag.

---

## Expression Injection

| Rule | Severity | What it detects |
|---|---|---|
| **EXP-001** | High | Raw webhook input (`$json.body.*`, `$json.query.*`) flows into a Code or Execute Command node without a sanitisation node (IF, Switch, Set, or Filter) on **every** path between them. Uses full connection graph traversal — not just immediate neighbours. |
| **EXP-002** | Medium | n8n expression interpolated directly into a SQL string. Fires when a parameter contains both a SQL keyword (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, etc.) and a `$json.*` expression. |

---

## Workflow Hygiene

| Rule | Severity | What it detects |
|---|---|---|
| **HYG-001** | Low | Workflow is `active: true` but has no trigger node (Webhook, Schedule, Cron, or any type ending in `Trigger`). |
| **HYG-002** | Low | Orphaned nodes — non-trigger nodes with no connections to or from the rest of the workflow. |
| **HYG-003** | Low | Workflow name is a default placeholder: `My workflow`, `Untitled`, `Untitled Workflow`, `New Workflow`, or empty string (case-insensitive). |

---

## Adding a new rule

1. Pick an ID following the existing pattern (`SEC-004`, `NET-005`, etc.)
2. Add a `RuleRunner` object to the appropriate file in `packages/api/src/analyzer/rules/`
3. Export it from the file's array — the orchestrator picks it up automatically
4. Add tests: at least one true-positive case and one false-positive guard

See [DEVELOPMENT.md](DEVELOPMENT.md) for a detailed walkthrough of how rules are structured and tested.
