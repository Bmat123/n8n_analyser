# Rule Catalogue

32 rules across 9 categories. Every rule is a pure function — given the same workflow and config it always returns the same violations.

Browse rules in the dashboard at **<http://localhost:5173/rules>**, or query the API:

```bash
curl "http://localhost:3000/rules"
curl "http://localhost:3000/rules?severity=critical"
curl "http://localhost:3000/rules?category=credentials"
```

***

## Credentials

| Rule        | Severity | What it detects                                                                                                                                                                                                                                                                                                      |
| ----------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SEC-001** | Critical | Hardcoded secret in any node parameter. Matches 14 patterns: OpenAI (`sk-`), Anthropic (`sk-ant-`), GitHub PAT (`ghp_`), Slack (`xoxb-`), AWS access key (`AKIA`), Stripe live/test keys, Bearer tokens, Basic auth headers, plus high-entropy strings in fields named `password`, `secret`, `token`, `apiKey`, etc. |
| **SEC-002** | High     | Credential in a URL query string. Matches query parameter names: `api_key`, `token`, `secret`, `password`, `access_token`, `auth`, and variants.                                                                                                                                                                     |
| **SEC-003** | Medium   | Credential stored in a Set node field. Reads both n8n v1 (`values.string[]`) and v2 (`assignments.assignments[]`) shapes. Fires when a field name looks like a credential or when its value matches a known secret pattern.                                                                                          |

**SEC-001 false-positive guards:** skips disabled nodes, skips `$credentials.` references (n8n vault), requires minimum entropy for the high-entropy field heuristic.

***

## Network

| Rule        | Severity | What it detects                                                                                                                                                                                                     |
| ----------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **NET-001** | High     | HTTP Request node using `http://` instead of `https://`. Excludes localhost and private IPs (those are NET-003).                                                                                                    |
| **NET-002** | High     | `allowUnauthorizedCerts: true` on an HTTP Request node. Checks both `parameters.allowUnauthorizedCerts` and `parameters.options.allowUnauthorizedCerts`.                                                            |
| **NET-003** | Medium   | HTTP Request targeting a private/internal address: `10.x`, `192.168.x`, `172.16–31.x`, `127.x`, `localhost`, `169.254.x` (AWS metadata), `::1`, or hostnames ending in `.internal`, `.local`, `.svc.cluster.local`. |
| **NET-004** | Low      | URL is entirely a dynamic expression with no static host (e.g. `={{ $json.targetUrl }}`). Does not fire when only the path or query string is dynamic.                                                              |

***

## Data Policy

| Rule       | Severity | What it detects                                                                                                                                                                                                                                                                                                             |
| ---------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DP-001** | High     | Webhook trigger with `authentication: "none"` or no authentication field — creates an unauthenticated public endpoint.                                                                                                                                                                                                      |
| **DP-002** | High     | PII field referenced in a POST/PUT/PATCH request body or headers. Detects n8n expressions for: `email`, `firstName`, `lastName`, `phone`, `ssn`, `nationalId`, `dateOfBirth`, `iban`, `creditCard`, `passport` (and snake\_case variants). Word-boundary matching prevents false positives on names like `emailTemplateId`. |
| **DP-003** | Medium   | Database node (Postgres, MySQL, MongoDB, Redis) connecting to a host not in the `APPROVED_DB_HOSTS` list. Only fires for static hostnames.                                                                                                                                                                                  |
| **DP-004** | Medium   | `console.log/error/warn/info/debug` in a Code or Function node — execution logs may be stored or exported, potentially leaking data.                                                                                                                                                                                        |
| **DP-005** | Low      | Workflow processes external data (HTTP, webhooks, database) but has no Error Trigger node. Failed executions expose raw node inputs/outputs in n8n's execution log.                                                                                                                                                         |

***

## Dangerous Nodes

| Rule       | Severity | What it detects                                                                                                                |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **DN-001** | Critical | `executeCommand` node — runs arbitrary shell commands on the n8n host.                                                         |
| **DN-002** | Critical | `ssh` node — remote shell access; a compromise gives RCE on the target.                                                        |
| **DN-003** | High     | `code`, `function`, or `functionItem` node — arbitrary JavaScript with full Node.js runtime access. Flagged for manual review. |
| **DN-004** | Medium   | `readWriteFile`, `readBinaryFile`, or `writeBinaryFile` node — local filesystem access on the n8n host.                        |

All rules produce one violation per matching node and respect the `disabled` flag.

***

## Expression Injection

| Rule        | Severity | What it detects                                                                                                                                                                                                                                              |
| ----------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **EXP-001** | High     | Raw webhook input (`$json.body.*`, `$json.query.*`) flows into a Code or Execute Command node without a sanitisation node (IF, Switch, Set, or Filter) on **every** path between them. Uses full connection graph traversal — not just immediate neighbours. |
| **EXP-002** | Medium   | n8n expression interpolated directly into a SQL string. Fires when a parameter contains both a SQL keyword (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, etc.) and a `$json.*` expression.                                                                |
| **EXP-003** | Critical | Any node parameter references `$env.<VARIABLE>` — valid n8n syntax that reads a host environment variable. If the resolved value reaches an HTTP endpoint, chat, or log, the secret is exfiltrated.                                                          |
| **EXP-004** | High     | Parameter contains a known JavaScript sandbox escape pattern: `__proto__`, `constructor.constructor` / `constructor["constructor"]`, or `process.env` inside an expression template (`{{ ... }}`).                                                           |

***

## Workflow Hygiene

| Rule        | Severity | What it detects                                                                                                                                                                                             |
| ----------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **HYG-001** | Low      | Workflow is `active: true` but has no trigger node (Webhook, Schedule, Cron, or any type ending in `Trigger`).                                                                                              |
| **HYG-002** | Low      | Orphaned nodes — non-trigger nodes with no connections to or from the rest of the workflow.                                                                                                                 |
| **HYG-003** | Low      | Workflow name is a default placeholder: `My workflow`, `Untitled`, `Untitled Workflow`, `New Workflow`, or empty string (case-insensitive).                                                                 |
| **HYG-004** | Medium   | All trigger nodes are disabled — the workflow has trigger nodes but every one is switched off, so it can never execute. Fires regardless of the `active` flag; produces one violation per disabled trigger. |

***

## Supply Chain

| Rule       | Severity | What it detects                                                                                                                                                                                                                               |
| ---------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SC-001** | Critical | HTTP Request node targets the n8n REST API on localhost (`:5678` or `/api/v1/` on a local address). A workflow calling n8n's own API can read credentials, modify workflows, and pivot to full instance control.                              |
| **SC-002** | High     | Workflow contains a node from an unofficial namespace (not `n8n-nodes-base.*` or `@n8n/n8n-nodes-langchain.*`). Community nodes are third-party code that runs with full n8n host privileges. One violation per unique node type.             |
| **SC-003** | High     | Code/Function node contains dangerous runtime patterns: `require()`, dynamic `import()`, `process.env`, `child_process`, `eval()`, or `new Function()`. These can break out of the intended sandbox on self-hosted n8n.                       |
| **SC-004** | Medium   | HTTP Request node fetches from a raw-content hosting site (`raw.githubusercontent.com`, `pastebin.com`, `hastebin.com`, etc.). Content pulled from these URLs can change at any time, making the workflow vulnerable to supply chain attacks. |

***

## Data Flow

| Rule       | Severity | What it detects                                                                                                                                                                                                                                   |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DF-001** | High     | Respond to Webhook node returns the full `$json` object as the response body (`={{ $json }}`), reflecting every processed field — including PII or secrets — back to the caller.                                                                  |
| **DF-002** | High     | Database node (Postgres, MySQL, MongoDB, Redis) feeds data directly into a cloud write destination (Google Sheets, Airtable, email) without a Set node between them to filter fields. Entire DB rows may be copied to a third-party SaaS service. |
| **DF-003** | Medium   | Chat node (Slack, Telegram, Discord, Teams) is downstream of a database read or webhook trigger. A common accidental exfiltration pattern where "notify me" workflows end up piping full records or webhook payloads into a chat message.         |

***

## Loop & Flow Control

| Rule       | Severity | What it detects                                                                                                                                                                                              |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **LF-001** | High     | Schedule Trigger uses a seconds-based interval, or Cron node uses a 6-field expression with a non-zero seconds field. Sub-minute trigger frequency can exhaust worker threads and flood downstream services. |
| **LF-002** | Medium   | Execute Workflow node targets the current workflow's own ID — direct self-recursion. Without a termination condition this creates an infinite execution loop.                                                |

***

## Adding a new rule

1. Pick an ID following the existing pattern (`SEC-004`, `NET-005`, etc.)
2. Add a `RuleRunner` object to the appropriate file in `packages/api/src/analyzer/rules/`
3. Export it from the file's array — the orchestrator picks it up automatically
4. Add tests: at least one true-positive case and one false-positive guard

See [DEVELOPMENT.md](DEVELOPMENT.md) for a detailed walkthrough of how rules are structured and tested.
