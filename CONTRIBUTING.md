# Contributing

Thank you for considering a contribution. This document covers everything you need to get started: setting up a development environment, running the test suite, and the conventions we follow for new rules and pull requests.

---

## Getting started

**Prerequisites:** Node.js 20+, npm 9+

```bash
# 1. Fork and clone the repo
git clone https://github.com/Bmat123/n8n_analyser.git
cd n8n_analyser/n8n-workflow-analyzer

# 2. Install dependencies
npm install

# 3. Build the shared types package (required once before first run)
npm run build -w @n8n-analyzer/types

# 4. Copy the env template
cp .env.example .env
# GEMINI_API_KEY is optional — only needed for AI features

# 5. Start the API and UI
npm run dev
# API → http://localhost:3000
# UI  → http://localhost:5173
```

---

## Running the test suite

```bash
# Run all tests once
npm test -w api

# Watch mode (re-runs on file change)
npm run test:watch -w api

# Single test file
cd packages/api && npx vitest run tests/rules/credentials.test.ts

# Filter by test name
cd packages/api && npx vitest run --reporter=verbose -t "SEC-001"
```

All 251 tests should pass before you open a PR. The CI check will verify this automatically.

---

## Type-checking

```bash
# Check all packages
npm run lint

# Check a single package
npm run lint -w api
npm run lint -w ui
```

If you change `packages/types/src/index.ts`, rebuild the types package before type-checking the others:

```bash
npm run build -w @n8n-analyzer/types
npm run lint
```

---

## What we welcome

| Contribution | Notes |
|---|---|
| New detection rules | See the rule guide below |
| False-positive fixes | Include a test that demonstrates the false positive |
| Test coverage | Extra true-positive and false-positive cases for existing rules |
| Documentation fixes | Typos, clarity improvements, missing examples |
| Bug reports | Use GitHub Issues — include a minimal workflow JSON that reproduces the problem |

We are unlikely to accept:
- Rules with a high false-positive rate and no configurable suppression mechanism
- Changes to the AI layer that require a different AI provider
- Breaking changes to the public API response shape without a versioning discussion first

---

## Adding a new rule

### 1. Pick a rule ID

Follow the existing pattern. Choose the most appropriate category:

| Category | Prefix | File |
|---|---|---|
| Credentials | `SEC-` | `packages/api/src/analyzer/rules/credentials.ts` |
| Network | `NET-` | `packages/api/src/analyzer/rules/network.ts` |
| Data Policy | `DP-` | `packages/api/src/analyzer/rules/data-policy.ts` |
| Dangerous Nodes | `DN-` | `packages/api/src/analyzer/rules/dangerous-nodes.ts` |
| Expression Injection | `EXP-` | `packages/api/src/analyzer/rules/expression-injection.ts` |
| Workflow Hygiene | `HYG-` | `packages/api/src/analyzer/rules/hygiene.ts` |
| Supply Chain | `SC-` | `packages/api/src/analyzer/rules/supply-chain.ts` |
| Data Flow | `DF-` | `packages/api/src/analyzer/rules/data-flow.ts` |
| Loop & Flow Control | `LF-` | `packages/api/src/analyzer/rules/loop-flow.ts` |

### 2. Implement the rule

Every rule is a `RuleRunner` — a pure function with no side effects:

```typescript
const myRule: RuleRunner = {
  definition: {
    id: "DP-007",
    severity: "medium",        // critical | high | medium | low
    category: "data_policy",
    title: "Short human-readable title",
    description: "What the rule detects and why it is a problem.",
    remediation: "What the user should do to fix it.",
  },
  run({ workflow, config }) {
    const violations: Violation[] = [];

    for (const node of workflow.nodes) {
      if (node.disabled) continue;
      // ... detection logic
    }

    return violations;
  },
};
```

Add it to the export array at the bottom of the file:

```typescript
export const dataPolicyRules: RuleRunner[] = [dp001, dp002, ..., myRule];
```

The orchestrator picks it up automatically via `ALL_RULES` — no other registration needed.

### 3. Write tests

Add tests to the matching test file in `packages/api/tests/rules/`. Every rule needs at minimum:

- At least one **true positive** — the rule fires when it should
- At least one **false positive guard** — the rule stays silent on safe input
- A test that **disabled nodes are skipped**

```typescript
import { myRuleFile } from "../../src/analyzer/rules/my-rule.js";
import { workflow, httpNode, run, expectRule, expectNoRule } from "../helpers.js";

it("fires when ...", () => {
  const wf = workflow([httpNode("Bad Node", { url: "https://example.com/bad" })]);
  expectRule(run(myRuleFile, wf), "DP-007");
});

it("does not fire when ...", () => {
  const wf = workflow([httpNode("Safe Node", { url: "https://example.com/safe" })]);
  expectNoRule(run(myRuleFile, wf), "DP-007");
});

it("does not fire on disabled nodes", () => {
  const wf = workflow([httpNode("Disabled", { url: "https://example.com/bad" }, { disabled: true })]);
  expectNoRule(run(myRuleFile, wf), "DP-007");
});
```

### 4. Update RULES.md

Add a row to the appropriate category table following the existing format:

```markdown
| **DP-007** | Medium | The node type and condition that triggers it | What can go wrong in plain language — focus on real-world consequences, not technical jargon |
```

### 5. If the rule needs a new config variable

1. Add the field to the `Config` interface in `packages/api/src/config.ts`
2. Parse it from `process.env` in `buildConfig()`
3. Add the field with a safe default to `defaultConfig` in `packages/api/tests/helpers.ts`
4. Document it in `README.md` (configuration table) and `.env.example`

---

## Pull request checklist

Before opening a PR, confirm:

- [ ] `npm test -w api` passes (all tests green)
- [ ] `npm run lint` passes (no TypeScript errors)
- [ ] New rule has true-positive and false-positive tests
- [ ] New rule has a row in `RULES.md`
- [ ] If a new config variable was added: `config.ts`, `helpers.ts`, `README.md`, and `.env.example` are all updated
- [ ] PR description explains what the rule detects, why it matters, and any false-positive trade-offs you considered

---

## Project structure reference

```
packages/
├── types/src/index.ts          — shared TypeScript interfaces (RuleCategory, Violation, etc.)
├── api/src/
│   ├── config.ts               — env → typed Config
│   ├── analyzer/
│   │   ├── index.ts            — orchestrator
│   │   ├── utils.ts            — parameter walker, graph tools, URL helpers
│   │   └── rules/              — one file per category
│   └── sarif.ts                — SARIF 2.1.0 serializer
└── ui/src/
    └── pages/
        ├── SubmitPage.tsx      — submit + report + fix suggestions
        └── RulesPage.tsx       — rule catalogue browser
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for a deeper explanation of each detection technique.

---

## Reporting a security vulnerability

If you find a security issue in the analyzer itself, please do not open a public GitHub issue. Instead, open a private vulnerability report via **GitHub → Security → Report a vulnerability**. We will respond within 72 hours.
