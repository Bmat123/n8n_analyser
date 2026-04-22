# @wflow-analyzer/core

Static analysis engine for [n8n](https://n8n.io) workflow JSON files.

Detects security vulnerabilities, reliability issues, and design pattern violations across 40+ rules — plus a graph-based analysis engine for data-flow and structural pattern detection.

## Install

```bash
npm install @wflow-analyzer/core
```

## Usage

```ts
import { analyzeWorkflow, buildConfig } from "@wflow-analyzer/core";

const config = buildConfig(process.env);
const report = await analyzeWorkflow(workflow, config);

console.log(report.violations);
console.log(report.summary);
```

## Graph analysis

```ts
import { buildPropertyGraph, runGraphPatterns, buildConfig } from "@wflow-analyzer/core";

const graph = buildPropertyGraph(workflow);
const violations = runGraphPatterns(graph, config);
```

## Serialise to Mermaid / adjacency list

```ts
import { toMermaid, toAdjacencyListText, enumerateAllPaths } from "@wflow-analyzer/core";

const graph = buildPropertyGraph(workflow);
console.log(toMermaid(graph));
```

## Rules

40+ rules across categories: credentials, network, data policy, dangerous nodes, expression injection, workflow hygiene, supply chain, data flow, loop flow, reliability, performance, maintainability, data quality, observability.

Graph pattern rules (GP-001–GP-012): taint propagation, PII reachability, unbounded cycles, high-centrality bottlenecks, webhook→DB injection, fan-out without merge, parallel writes, dead branches, schema mismatch, shared credentials, cyclomatic complexity.

## Self-hosted server

For the full HTTP API (Fastify), see [@wflow-analyzer/server](https://www.npmjs.com/package/@wflow-analyzer/server).

## License

MIT
