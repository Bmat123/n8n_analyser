# Rule Catalogue

33 rules across 9 categories. Every rule is a pure function — given the same workflow and config it always returns the same violations.

Browse rules in the dashboard at **<http://localhost:5173/rules>**, or query the API:

```bash
curl "http://localhost:3000/rules"
curl "http://localhost:3000/rules?severity=critical"
curl "http://localhost:3000/rules?category=credentials"
```

***

## Credentials

These rules look for secret keys and passwords left in plain sight inside your workflow. Think of it like leaving your house keys taped to the front door — anyone who can read the workflow file can use them.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **SEC-001** | Critical | Any node — HTTP Request, Code, Set, etc. — whose parameters contain a recognisable secret: OpenAI keys (`sk-`), Anthropic keys (`sk-ant-`), GitHub tokens (`ghp_`), Slack tokens (`xoxb-`), AWS access keys (`AKIA`), Stripe live/test keys, Bearer tokens, Basic auth headers, or high-entropy strings in fields named `password`, `secret`, `token`, `apiKey`, etc. | Anyone with read access to the workflow file — a developer, a contractor, a leaked export — can immediately use that credential to access your payment system, cloud account, or AI service. No hacking required. |
| **SEC-002** | High | HTTP Request node where the URL contains credentials as query parameters, e.g. `https://api.example.com/data?api_key=abc123`. | URLs are routinely written to server logs, browser history, Slack messages, and monitoring tools. The credential travels far beyond where you intended and is extremely hard to revoke once it has leaked. |
| **SEC-003** | Medium | Set node that stores a credential-like value in a named field — for example a field called `token` or `password` containing a real secret. | Set nodes are often used to "pass along" data to the next step. A credential stored here can be logged in execution history, exported in workflow JSON, and read by anyone who can view workflow runs. |

**SEC-001 false-positive guards:** disabled nodes are skipped; `$credentials.` references (n8n vault lookups) are safe and are never flagged; high-entropy field detection requires minimum entropy to avoid flagging random short strings.

***

## Network

These rules check how your workflow communicates over the internet. An insecure connection is like sending a letter without an envelope — anyone who can intercept the traffic can read or modify the contents.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **NET-001** | High | HTTP Request node using `http://` instead of `https://`. | All data sent or received — including customer records, credentials, and API responses — travels in plain text. Any network device between n8n and the destination (a router, a cloud proxy, an ISP) can read or silently modify it. |
| **NET-002** | High | HTTP Request node with `allowUnauthorizedCerts: true`, which disables TLS certificate verification. | Your workflow will connect to any server claiming to be the destination, even a fake one. An attacker who intercepts the connection can silently read everything and inject false responses — a classic "man-in-the-middle" attack. |
| **NET-003** | Medium | HTTP Request node targeting a private or internal address: `10.x`, `192.168.x`, `172.16–31.x`, `127.x`, `localhost`, AWS metadata endpoint `169.254.169.254`, or hostnames ending in `.internal`, `.local`, `.svc.cluster.local`. | If the destination URL can be influenced by data arriving in the workflow (e.g. from a webhook or form input), an attacker can steer requests at internal servers that are not meant to be reachable from the internet — exposing internal APIs, cloud credentials, and infrastructure. |
| **NET-004** | Low | HTTP Request node whose entire URL is an n8n expression with no fixed host, e.g. `={{ $json.targetUrl }}`. | The destination of every request is completely unknown until the workflow runs. There is no way to review or approve where data is being sent. |

***

## Data Policy

These rules protect personal data and enforce your data governance rules. They focus on what data leaves your systems, where it goes, and whether you have proper controls in place.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **DP-001** | High | Webhook node with authentication set to `none` or no authentication configured at all, creating a public URL that anyone can call. | Anyone who discovers or guesses the webhook URL can trigger the workflow with any data they choose — submitting fake orders, flooding your system, or triggering actions intended only for trusted sources. |
| **DP-002** | High | HTTP Request node making a POST, PUT, or PATCH request whose body or headers reference personal data fields — `email`, `firstName`, `lastName`, `phone`, `ssn`, `nationalId`, `dateOfBirth`, `iban`, `creditCard`, `passport` — via n8n expressions. | Personal data is being sent to a third-party service. If that service is not covered by a data processing agreement, or if the connection is not secure, this is a likely GDPR or data protection violation. |
| **DP-003** | Medium | Database node (Postgres, MySQL, MongoDB, Redis) connecting to a hostname that is not in your `APPROVED_DB_HOSTS` list. Only fires when the list is configured. | The workflow is reading from or writing to a database host that has not been reviewed and approved. This could be a shadow database, a developer's local instance accidentally left in production, or an attacker-controlled host substituted via misconfiguration. |
| **DP-004** | Medium | Code or Function node containing `console.log()`, `console.error()`, `console.warn()`, `console.info()`, or `console.debug()`. | Whatever is printed — customer records, API responses, authentication tokens — is written into n8n's execution log. Execution logs are often retained for days, accessible to all n8n operators, and sometimes forwarded to external logging platforms like Datadog or Splunk. |
| **DP-005** | Low | Workflow that handles external data (via Webhook, HTTP Request, or database nodes) but has no Error Trigger node connected to an error handler workflow. | When the workflow crashes, n8n saves the full input and output of every node at the time of failure in the execution history. This raw data — which may include personal details, credentials, or confidential records — is visible to anyone with access to the n8n interface. |
| **DP-006** | Medium | HTTP Request node calling a hostname not in your `APPROVED_EGRESS_HOSTS` allowlist. **Opt-in** — only active when `APPROVED_EGRESS_HOSTS` is configured. Skips private/internal addresses (NET-003) and fully dynamic URLs (NET-004). One violation per unique unapproved hostname per node. | Data is leaving your systems and going to a destination that has not been reviewed or approved. This is how customer data quietly ends up with analytics trackers, marketing tools, or other third parties that you did not intend to share it with. |

**DP-006 usage:** set `APPROVED_EGRESS_HOSTS=api.stripe.com,api.sendgrid.com` (comma-separated) to define your permitted outbound destinations. Any HTTP Request node calling a host outside this list will be flagged. Leave unset to disable the rule entirely — useful when you are still inventorying your workflows.

***

## Dangerous Nodes

These rules flag node types that give a workflow direct access to your server, operating system, or file system. A misconfigured or malicious workflow using these nodes can cause serious damage — the equivalent of handing someone the keys to your server room.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **DN-001** | Critical | Execute Command node — runs a shell command directly on the server where n8n is installed. | A workflow with this node can delete files, install software, read any file on the server, create backdoors, or completely take over the machine. One misconfiguration or malicious input is enough to compromise everything running on that server. |
| **DN-002** | Critical | SSH node — connects to a remote server over SSH and executes commands on it. | Same consequences as DN-001, but on a remote machine. A compromised workflow can pivot from n8n into your production infrastructure, cloud VMs, or internal servers. |
| **DN-003** | High | Code, Function, or Function Item node — runs arbitrary JavaScript with full access to the Node.js runtime. Flagged for manual review rather than as an automatic block. | Code nodes can import system libraries, make outbound connections, read environment variables, and write to the filesystem. They require human review to confirm they do only what is intended. |
| **DN-004** | Medium | Read/Write File, Read Binary File, or Write Binary File node — accesses the local filesystem on the n8n server. | The workflow can read configuration files, credentials stored on disk, system files, or any other file accessible to the n8n process. It can also overwrite or create files, potentially interfering with other applications running on the same server. |

All rules produce one violation per matching node and respect the `disabled` flag.

***

## Expression Injection

These rules detect situations where data arriving from outside your workflow — from a user form, a webhook, an API — can influence code execution or database queries. This is the digital equivalent of someone writing instructions on a form that your system then blindly executes.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **EXP-001** | High | Webhook node feeding data directly into a Code or Execute Command node without any filtering node (IF, Switch, Set, or Filter) on every path between them. Uses full connection graph traversal — not just direct neighbours. | A user submitting a request to your webhook can craft a payload that, when processed by the code node, executes unintended commands on your server. For example, submitting `;rm -rf /` as a form field value if it reaches a shell command without sanitisation. |
| **EXP-002** | Medium | Any node where an n8n expression like `$json.userInput` is directly interpolated into a SQL string alongside keywords like `SELECT`, `INSERT`, `UPDATE`, `DELETE`, or `DROP`. | SQL injection — a decades-old but still extremely common attack. An attacker submits specially crafted input that breaks out of the intended query and can read any data in your database, modify records, or delete entire tables. |
| **EXP-003** | Critical | Any node parameter containing `$env.VARIABLE_NAME` — valid n8n syntax for reading a host environment variable directly into a workflow. | Environment variables on your n8n server typically hold the most sensitive secrets: database passwords, API master keys, encryption keys, cloud credentials. If this value flows into an HTTP request, a chat message, or a log, that secret has left your control. |
| **EXP-004** | High | Any node parameter containing JavaScript prototype pollution patterns (`__proto__`), constructor chain escapes (`constructor.constructor` or `constructor["constructor"]`), or `process.env` inside an expression template `{{ ... }}`. | These are known techniques for escaping JavaScript sandboxes. If an attacker can influence the content of an expression, they may be able to execute arbitrary code within the n8n process, access environment variables, or corrupt shared application state. |

***

## Workflow Hygiene

These rules catch workflow configurations that suggest something is broken, abandoned, or was never properly set up. While not direct security vulnerabilities, they indicate workflows that may behave unexpectedly — or never run at all, silently failing without anyone noticing.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **HYG-001** | Low | Workflow marked as `active: true` but containing no trigger node (no Webhook, Schedule, Cron, or any node type ending in `Trigger`). | The workflow is switched on but has nothing to start it. It will never run. If this workflow was supposed to be processing orders, sending notifications, or syncing data, that work is silently not happening. |
| **HYG-002** | Low | Non-trigger nodes with no connections to or from the rest of the workflow — isolated "islands" of nodes. | These disconnected nodes are dead code. They may represent incomplete logic that was meant to be wired in, or leftover nodes from a previous version. They create confusion and make the workflow harder to audit. |
| **HYG-003** | Low | Workflow whose name is a default placeholder: `My workflow`, `Untitled`, `Untitled Workflow`, `New Workflow`, or an empty string. | Unnamed workflows are nearly impossible to audit, search for, or identify in an incident. When something goes wrong, "which workflow sent that request?" becomes very hard to answer. |
| **HYG-004** | Medium | Workflow that has at least one trigger node, but every trigger node is individually disabled — so the workflow can never start. One violation is raised per disabled trigger. | Unlike HYG-001, the workflow was properly designed with a trigger, but someone disabled it — probably for testing or debugging — and never re-enabled it. Critical automation (like payment processing, alerts, or data sync) is silently not running. |

***

## Supply Chain

These rules detect risks introduced through the software and services your workflows depend on. Just as a compromised ingredient can contaminate a finished product, a compromised node type, script, or external content source can compromise your entire workflow.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **SC-001** | Critical | HTTP Request node whose URL targets the n8n REST API on the same machine — specifically URLs containing `:5678` or `/api/v1/` pointing to a local address. | A workflow calling n8n's own API can read all stored credentials, list and modify other workflows, and take full control of the n8n instance. This is a common pattern in "workflow hijacking" where one compromised workflow is used to escalate access to everything else. |
| **SC-002** | High | Any node whose type does not begin with the official n8n prefixes (`n8n-nodes-base.`, `@n8n/n8n-nodes-langchain.`, etc.) — indicating a community-installed or custom node. One violation per unique node type. | Community nodes are third-party packages installed from npm. They run with the same permissions as n8n itself. A malicious or compromised community node package can read your credentials, exfiltrate data, or take over the server — and it will do so every time any workflow uses that node. |
| **SC-003** | High | Code or Function node whose code contains patterns like `require()`, dynamic `import()`, `process.env`, `child_process`, `eval()`, or `new Function()`. | These patterns attempt to break out of the intended JavaScript sandbox. `require('child_process')` can run shell commands; `process.env` can read all server secrets; `eval()` can execute arbitrary code injected through data. Even if the intent is innocent, these patterns make the workflow very difficult to audit safely. |
| **SC-004** | Medium | HTTP Request node fetching content from a raw-content or paste hosting site: `raw.githubusercontent.com`, `pastebin.com`, `hastebin.com`, and similar. | The content at these URLs can be changed at any time by whoever controls the link — including an attacker who has compromised a GitHub account or Pastebin paste. Your workflow could be executing completely different code or loading completely different data tomorrow than it does today, without any warning. |

***

## Data Flow

These rules trace where data actually travels through a workflow and flag paths where sensitive information ends up somewhere it should not — even when each individual step looks harmless in isolation.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **DF-001** | High | Respond to Webhook node that returns the entire `$json` object as the response body — using `={{ $json }}` or `JSON.stringify($json)`. | The response sends back every field processed by the workflow, not just what you intended. If the workflow touched a database record or enriched the input with customer data, all of that is now visible to whoever called the webhook — including fields they were never meant to see. |
| **DF-002** | High | Database node (Postgres, MySQL, MongoDB, Redis) whose output flows into a cloud writing destination — Google Sheets, Airtable, Gmail, or a Send Email node — without a Set node between them to select which fields to include. | Entire database rows, potentially containing sensitive personal data, financial records, or internal notes, are being copied wholesale into a third-party SaaS platform. Google Sheets and Airtable in particular are often shared broadly within organisations, dramatically widening who can see that data. |
| **DF-003** | Medium | Chat node (Slack, Telegram, Discord, or Microsoft Teams) that is reachable downstream from a database read or webhook trigger in the workflow graph. | A common "just notify me" pattern that silently pipes full database records or raw webhook payloads into a chat channel. Slack channels are often accessible to many team members, logged indefinitely, and sometimes connected to third-party bots — meaning customer data, order details, or internal records end up in a chat log that was never designed to hold sensitive information. |

***

## Loop & Flow Control

These rules detect workflow configurations that can cause runaway execution — workflows that trigger themselves repeatedly or run far more often than intended, potentially overwhelming your systems or running up significant API costs.

| Rule | Severity | Triggered by | What can go wrong |
|---|---|---|---|
| **LF-001** | High | Schedule Trigger node configured to run on a seconds-based interval, or a Cron node using a 6-field expression where the seconds field is not `0` — meaning the workflow fires multiple times per minute. | A workflow running every few seconds can exhaust n8n worker threads, flood downstream APIs with requests (triggering rate limits or bans), generate enormous cloud costs, and duplicate data at high speed. What seems like a minor timing configuration can spiral into thousands of unintended executions per hour. |
| **LF-002** | Medium | Execute Workflow node that references the same workflow it is part of — calling itself directly. | Without a reliable exit condition, the workflow will call itself indefinitely, creating an infinite loop. Each iteration consumes memory and worker capacity; the loop continues until n8n crashes or an execution limit is hit. This can make the entire n8n instance unresponsive for all other workflows. |

***

## Adding a new rule

1. Pick an ID following the existing pattern (`SEC-004`, `NET-005`, etc.)
2. Add a `RuleRunner` object to the appropriate file in `packages/api/src/analyzer/rules/`
3. Export it from the file's array — the orchestrator picks it up automatically
4. Add tests: at least one true-positive case and one false-positive guard

See [DEVELOPMENT.md](DEVELOPMENT.md) for a detailed walkthrough of how rules are structured and tested.
