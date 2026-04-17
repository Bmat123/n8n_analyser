/**
 * Graph Pattern Rules GP-001 through GP-012.
 * Each pattern takes a PropertyGraph and returns GraphViolationInternal[].
 */
import type { Config } from "../config.js";
import { NodeCategory, type PropertyGraph, type GraphViolationInternal } from "./types.js";
import {
  buildAdjList,
  buildReverseAdjList,
  detectCycles,
  pathsBetween,
  betweennessCentrality,
  findOrphanedNodes,
} from "./algorithms.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pathContainsFilter(path: string[], graph: PropertyGraph): boolean {
  return path.some((name) => graph.nodes.get(name)?.category === NodeCategory.FILTER);
}

function nodeNamesToLabels(names: string[], graph: PropertyGraph): string {
  return names.map((n) => {
    const node = graph.nodes.get(n);
    return node ? `"${n}" (${node.category})` : `"${n}"`;
  }).join(" → ");
}

const EXTERNAL_SINK_CATEGORIES = new Set<string>([
  NodeCategory.EXTERNAL_CALL,
  NodeCategory.EMAIL,
  NodeCategory.CHAT,
  NodeCategory.SPREADSHEET,
]);

// ─── GP-001 — Tainted data reaches external sink without sanitisation ─────────

function gp001(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];
  const adj = buildAdjList(graph);

  const SINKS = new Set<string>([
    NodeCategory.DATABASE_WRITE,
    NodeCategory.EXTERNAL_CALL,
    NodeCategory.CODE,
    NodeCategory.EXECUTE_WORKFLOW,
    NodeCategory.DANGEROUS,
  ]);

  for (const [sourceName, sourceNode] of graph.nodes) {
    if (sourceNode.category !== NodeCategory.TRIGGER_WEBHOOK) continue;

    // BFS tracking whether a filter was seen on this path
    type Entry = { name: string; seenFilter: boolean; path: string[] };
    const queue: Entry[] = [{ name: sourceName, seenFilter: false, path: [sourceName] }];
    const reported = new Set<string>();
    const visitedKey = (name: string, sf: boolean) => `${name}:${sf}`;
    const visited = new Set<string>([visitedKey(sourceName, false)]);

    while (queue.length > 0) {
      const { name, seenFilter, path } = queue.shift()!;
      const node = graph.nodes.get(name);
      const isFilter = node?.category === NodeCategory.FILTER;
      const nowFiltered = seenFilter || isFilter;

      if (!nowFiltered && SINKS.has(node?.category ?? "") && name !== sourceName && !reported.has(name)) {
        reported.add(name);
        violations.push({
          ruleId: "GP-001",
          severity: "critical",
          title: `Tainted webhook data reaches "${name}" without sanitisation`,
          description: `Data from webhook "${sourceName}" flows directly to a ${node?.category} node without passing through any IF or Switch validation node.`,
          confidence: "probable",
          affectedNodes: path,
          affectedPath: path,
          evidence: nodeNamesToLabels(path, graph),
          remediation: "Add an IF node immediately after the webhook trigger that validates required fields and rejects malformed payloads before data enters the processing chain.",
          escalateToLLM: true,
        });
      }

      for (const next of adj.get(name) ?? []) {
        const key = visitedKey(next, nowFiltered);
        if (!visited.has(key)) {
          visited.add(key);
          queue.push({ name: next, seenFilter: nowFiltered, path: [...path, next] });
        }
      }
    }
  }
  return violations;
}

// ─── GP-002 — PII reachability to external destination ───────────────────────

function gp002(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];
  const reported = new Set<string>();

  for (const edge of graph.edges) {
    const piiFields = edge.dataSchema?.piiFields ?? [];
    if (piiFields.length === 0) continue;

    const paths = pathsBetween(graph, edge.targetName, edge.targetName, 1);
    // BFS from this edge's target to find external sinks
    const adj = buildAdjList(graph);
    const queue: { name: string; path: string[] }[] = [{ name: edge.targetName, path: [edge.targetName] }];
    const visited = new Set<string>([edge.targetName]);

    while (queue.length > 0) {
      const { name, path } = queue.shift()!;
      const node = graph.nodes.get(name);
      if (node && EXTERNAL_SINK_CATEGORIES.has(node.category)) {
        const key = `${edge.sourceName}→${name}`;
        if (!reported.has(key)) {
          reported.add(key);
          violations.push({
            ruleId: "GP-002",
            severity: "high",
            title: `PII field(s) "${piiFields.join(", ")}" reach external node "${name}"`,
            description: `A Set node defines fields (${piiFields.join(", ")}) that appear to contain PII, and those fields flow downstream to external destination "${name}" (${node.category}).`,
            confidence: "probable",
            affectedNodes: path,
            affectedPath: path,
            evidence: `PII fields: ${piiFields.join(", ")} | path: ${path.join(" → ")}`,
            remediation: "Add a Set node before the external destination to explicitly whitelist only the fields required. Never pass $json wholesale to external systems.",
            escalateToLLM: true,
          });
        }
      }
      for (const next of adj.get(name) ?? []) {
        if (!visited.has(next)) {
          visited.add(next);
          queue.push({ name: next, path: [...path, next] });
        }
      }
    }
  }
  return violations;
}

// ─── GP-003 — Unbounded cycle: loop with no exit condition ────────────────────

function gp003(graph: PropertyGraph): GraphViolationInternal[] {
  const { cycles } = detectCycles(graph);
  const violations: GraphViolationInternal[] = [];
  const adj = buildAdjList(graph);

  for (const cycle of cycles) {
    const cycleSet = new Set(cycle);
    // Check if any FILTER node in the cycle has an exit branch out of the cycle
    const hasExit = cycle.some((name) => {
      const node = graph.nodes.get(name);
      if (node?.category !== NodeCategory.FILTER) return false;
      // Look for edges from this filter that lead outside the cycle
      return (adj.get(name) ?? []).some((next) => !cycleSet.has(next));
    });

    if (!hasExit) {
      violations.push({
        ruleId: "GP-003",
        severity: "high",
        title: `Potential unbounded cycle detected`,
        description: `The following nodes form a cycle with no visible exit condition: ${cycle.join(" → ")}. Without an IF node providing an exit branch, this loop may run indefinitely.`,
        confidence: "certain",
        affectedNodes: cycle,
        evidence: cycle.join(" → "),
        remediation: "Every loop must have an explicit exit condition. Add an IF node inside the loop that checks a counter or a 'has more pages' flag, routing the false branch to a node outside the loop.",
        escalateToLLM: false,
      });
    }
  }
  return violations;
}

// ─── GP-005 — High betweenness centrality (single point of failure) ───────────

function gp005(graph: PropertyGraph, config: Config): GraphViolationInternal[] {
  if (graph.nodes.size < 5) return []; // not meaningful on tiny workflows

  const scores = betweennessCentrality(graph);
  const values = [...scores.values()];
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const stddev = Math.sqrt(values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length);
  const threshold = mean + (config.centralityStddevThreshold ?? 2.0) * stddev;

  const violations: GraphViolationInternal[] = [];
  const HIGH_RISK = new Set<string>([NodeCategory.EXTERNAL_CALL, NodeCategory.DATABASE_READ, NodeCategory.CODE]);

  for (const [name, score] of scores) {
    if (score <= threshold) continue;
    const node = graph.nodes.get(name);
    if (!node) continue;
    const pct = Math.round((score / values.reduce((s, v) => s + v, 1)) * 100);
    const severity = HIGH_RISK.has(node.category) ? "high" : "medium";
    violations.push({
      ruleId: "GP-005",
      severity,
      title: `Node "${name}" is a single point of failure (high centrality)`,
      description: `"${name}" (${node.category}) sits on ~${pct}% of execution paths. A failure or latency spike here affects the majority of workflow executions.`,
      confidence: "advisory",
      affectedNodes: [name],
      evidence: `centrality score: ${score.toFixed(2)} (mean: ${mean.toFixed(2)}, threshold: ${threshold.toFixed(2)})`,
      remediation: "Consider adding a fallback path via an IF node checking this node's output, or introducing caching upstream to reduce dependency on it.",
      escalateToLLM: true,
    });
  }
  return violations;
}

// ─── GP-006 — Unsanitised webhook-to-database path ───────────────────────────

function gp006(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];
  const reported = new Set<string>();

  for (const [webhookName, webhookNode] of graph.nodes) {
    if (webhookNode.category !== NodeCategory.TRIGGER_WEBHOOK) continue;

    for (const [dbName, dbNode] of graph.nodes) {
      if (dbNode.category !== NodeCategory.DATABASE_WRITE) continue;

      const paths = pathsBetween(graph, webhookName, dbName, 50);
      for (const path of paths) {
        if (!pathContainsFilter(path, graph)) {
          const key = `${webhookName}→${dbName}`;
          if (!reported.has(key)) {
            reported.add(key);
            violations.push({
              ruleId: "GP-006",
              severity: "critical",
              title: `Unsanitised webhook payload flows directly to database write "${dbName}"`,
              description: `Webhook "${webhookName}" has a direct path to database write "${dbName}" with no IF or Switch validation node on any path between them.`,
              confidence: "certain",
              affectedNodes: path,
              affectedPath: path,
              evidence: path.join(" → "),
              remediation: "Never write webhook payload data directly to a database. Add an IF node to validate required fields before any database operation.",
              escalateToLLM: false,
            });
          }
        }
      }
    }
  }
  return violations;
}

// ─── GP-007 — Fan-out to multiple external sinks without merge ────────────────

function gp007(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];
  const adj = buildAdjList(graph);

  for (const [name, neighbours] of adj) {
    if (neighbours.length < 3) continue;

    // Check how many branches eventually reach external sinks
    const branchesWithExternalSinks: string[] = [];
    for (const next of neighbours) {
      const visited = new Set<string>([next]);
      const queue = [next];
      let hasExternal = false;
      while (queue.length > 0 && !hasExternal) {
        const cur = queue.shift()!;
        const curNode = graph.nodes.get(cur);
        if (curNode && EXTERNAL_SINK_CATEGORIES.has(curNode.category)) {
          hasExternal = true;
        }
        for (const n of adj.get(cur) ?? []) {
          if (!visited.has(n)) { visited.add(n); queue.push(n); }
        }
      }
      if (hasExternal) branchesWithExternalSinks.push(next);
    }

    if (branchesWithExternalSinks.length < 2) continue;

    // Check if branches converge at a MERGE node
    const reachable = new Set<string>();
    for (const branch of branchesWithExternalSinks) {
      const visited = new Set<string>([branch]);
      const queue = [branch];
      while (queue.length > 0) {
        const cur = queue.shift()!;
        reachable.add(cur);
        for (const n of adj.get(cur) ?? []) {
          if (!visited.has(n)) { visited.add(n); queue.push(n); }
        }
      }
    }
    const hasMerge = [...reachable].some((n) => graph.nodes.get(n)?.category === NodeCategory.MERGE);
    if (hasMerge) continue;

    violations.push({
      ruleId: "GP-007",
      severity: "medium",
      title: `Node "${name}" fans out to ${branchesWithExternalSinks.length} external sinks without convergence`,
      description: `"${name}" has ${neighbours.length} outgoing branches, ${branchesWithExternalSinks.length} of which reach external destinations. These branches never converge at a Merge node, so failures on one branch are invisible to the others.`,
      confidence: "advisory",
      affectedNodes: [name, ...branchesWithExternalSinks],
      evidence: `Branches with external sinks: ${branchesWithExternalSinks.join(", ")}`,
      remediation: "Ensure each branch sends only the fields it needs (use Set nodes per branch). Add error handling per branch so a failure of one doesn't silently corrupt the overall execution.",
      escalateToLLM: true,
    });
  }
  return violations;
}

// ─── GP-008 — Parallel writes to same database table ─────────────────────────

function extractTableName(params: Record<string, unknown>): string | null {
  const query = (params.query as string | undefined) ?? "";
  const m = query.match(/(?:INTO|UPDATE|FROM)\s+["'`]?(\w+)["'`]?/i);
  if (m) return m[1].toLowerCase();
  const table = params.table ?? params.tableName ?? params.collection;
  return typeof table === "string" ? table.toLowerCase() : null;
}

function gp008(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];
  const reverseAdj = buildReverseAdjList(graph);

  // Group DATABASE_WRITE nodes by table
  const byTable = new Map<string, string[]>();
  for (const [name, node] of graph.nodes) {
    if (node.category !== NodeCategory.DATABASE_WRITE) continue;
    const table = extractTableName(node.parameters);
    if (!table) continue;
    if (!byTable.has(table)) byTable.set(table, []);
    byTable.get(table)!.push(name);
  }

  for (const [table, writers] of byTable) {
    if (writers.length < 2) continue;

    // Check if any pair is on parallel branches (neither reachable from the other)
    for (let i = 0; i < writers.length; i++) {
      for (let j = i + 1; j < writers.length; j++) {
        const pathsAtoB = pathsBetween(graph, writers[i], writers[j], 5);
        const pathsBtoA = pathsBetween(graph, writers[j], writers[i], 5);
        if (pathsAtoB.length === 0 && pathsBtoA.length === 0) {
          violations.push({
            ruleId: "GP-008",
            severity: "medium",
            title: `Parallel writes to table "${table}" create race condition risk`,
            description: `Nodes "${writers[i]}" and "${writers[j]}" both write to table "${table}" on parallel branches. Concurrent executions may produce non-deterministic results.`,
            confidence: "probable",
            affectedNodes: [writers[i], writers[j]],
            evidence: `Table: ${table} | writers: ${writers.join(", ")}`,
            remediation: "Serialise the writes by chaining them sequentially, use ON CONFLICT DO UPDATE, or redesign to write from a single node with a bulk INSERT.",
            escalateToLLM: true,
          });
        }
      }
    }
  }
  return violations;
}

// ─── GP-009 — Dead branch (always-false/true condition) ───────────────────────

const STATIC_TRUE_RE = /^\s*\{\{\s*true\s*\}\}\s*$|^\s*true\s*$/i;
const STATIC_FALSE_RE = /^\s*\{\{\s*false\s*\}\}\s*$|^\s*false\s*$/i;
const ALWAYS_TRUE_EXPR_RE = /\{\{\s*(?:true|\d+\s*===\s*\d+|["'][^"']*["']\s*===\s*["'][^"']*["'])\s*\}\}/;
const ALWAYS_FALSE_EXPR_RE = /\{\{\s*(?:false|\d+\s*!==?\s*\d+|1\s*===\s*2|0\s*===\s*1)\s*\}\}/;

function gp009(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];
  const adj = buildAdjList(graph);

  for (const [name, node] of graph.nodes) {
    if (node.category !== NodeCategory.FILTER) continue;

    // Try to statically evaluate the condition
    const condStr = JSON.stringify(node.parameters.conditions ?? node.parameters.rules ?? "");
    let alwaysTrue = STATIC_TRUE_RE.test(condStr) || ALWAYS_TRUE_EXPR_RE.test(condStr);
    let alwaysFalse = STATIC_FALSE_RE.test(condStr) || ALWAYS_FALSE_EXPR_RE.test(condStr);

    if (!alwaysTrue && !alwaysFalse) continue;

    const branches = adj.get(name) ?? [];
    const deadBranchIndex = alwaysFalse ? 0 : 1; // if always false, true-branch is dead; vice versa
    if (branches.length <= deadBranchIndex) continue;

    const deadStart = branches[deadBranchIndex];
    // Collect nodes only reachable via the dead branch
    const visited = new Set<string>([name]);
    const deadNodes: string[] = [];
    const queue = [deadStart];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      if (visited.has(cur)) continue;
      visited.add(cur);
      deadNodes.push(cur);
      for (const n of adj.get(cur) ?? []) {
        if (!visited.has(n)) queue.push(n);
      }
    }

    if (deadNodes.length > 0) {
      violations.push({
        ruleId: "GP-009",
        severity: "low",
        title: `IF node "${name}" has a statically-determinable dead branch`,
        description: `The condition on "${name}" appears to be always-${alwaysFalse ? "false" : "true"}, making the ${alwaysFalse ? "true" : "false"} branch unreachable. Downstream nodes ${deadNodes.join(", ")} will never execute.`,
        confidence: "advisory",
        affectedNodes: [name, ...deadNodes],
        evidence: `condition: ${condStr.slice(0, 100)} | dead branch leads to: ${deadNodes.join(", ")}`,
        remediation: "Remove the dead branch and its downstream nodes. If the condition is a placeholder, replace it with the intended runtime condition.",
        escalateToLLM: true,
      });
    }
  }
  return violations;
}

// ─── GP-010 — Schema mismatch at Merge node ───────────────────────────────────

function gp010(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];

  for (const [name, node] of graph.nodes) {
    if (node.category !== NodeCategory.MERGE) continue;

    const incomingEdges = graph.edges.filter((e) => e.targetName === name && e.dataSchema);
    if (incomingEdges.length < 2) continue;

    const schemas = incomingEdges.map((e) => new Set(e.dataSchema!.fields));
    // Find fields not common to all branches
    const allFields = new Set(incomingEdges.flatMap((e) => e.dataSchema!.fields));
    const commonFields = [...allFields].filter((f) => schemas.every((s) => s.has(f)));
    const conflictingFields = [...allFields].filter((f) => !commonFields.includes(f));

    if (conflictingFields.length > 0) {
      violations.push({
        ruleId: "GP-010",
        severity: "medium",
        title: `Merge node "${name}" receives branches with mismatched schemas`,
        description: `The branches feeding into Merge node "${name}" carry different field sets. Fields present in only some branches: ${conflictingFields.join(", ")}. Downstream nodes may fail when those fields are absent.`,
        confidence: "advisory",
        affectedNodes: [name, ...incomingEdges.map((e) => e.sourceName)],
        evidence: `conflicting fields: ${conflictingFields.join(", ")}`,
        remediation: "Add a Set node at the end of each branch to normalise fields to a common shape before merging.",
        escalateToLLM: true,
      });
    }
  }
  return violations;
}

// ─── GP-011 — Credential shared across high-risk and low-risk nodes ───────────

function gp011(graph: PropertyGraph): GraphViolationInternal[] {
  const violations: GraphViolationInternal[] = [];
  const HIGH_RISK = new Set<string>([NodeCategory.DANGEROUS, NodeCategory.CODE, NodeCategory.EXTERNAL_CALL]);
  const LOW_RISK = new Set<string>([NodeCategory.EMAIL, NodeCategory.CHAT]);

  // Group nodes by credential ID
  const byCredId = new Map<string, { type: string; nodes: string[] }>();
  for (const node of graph.nodes.values()) {
    for (const cred of node.credentials) {
      if (!byCredId.has(cred.credentialId)) {
        byCredId.set(cred.credentialId, { type: cred.credentialType, nodes: [] });
      }
      byCredId.get(cred.credentialId)!.nodes.push(node.name);
    }
  }

  for (const [credId, { type, nodes }] of byCredId) {
    if (nodes.length < 2) continue;
    const highRiskNodes = nodes.filter((n) => HIGH_RISK.has(graph.nodes.get(n)?.category ?? ""));
    const lowRiskNodes = nodes.filter((n) => LOW_RISK.has(graph.nodes.get(n)?.category ?? ""));
    if (highRiskNodes.length > 0 && lowRiskNodes.length > 0) {
      violations.push({
        ruleId: "GP-011",
        severity: "medium",
        title: `Credential "${type}" (${credId}) shared between high-risk and low-risk nodes`,
        description: `The same credential is used by both high-risk nodes (${highRiskNodes.join(", ")}) and low-risk nodes (${lowRiskNodes.join(", ")}). A compromise of the low-risk path exposes the high-risk capability.`,
        confidence: "certain",
        affectedNodes: nodes,
        evidence: `credential type: ${type} | high-risk: ${highRiskNodes.join(", ")} | low-risk: ${lowRiskNodes.join(", ")}`,
        remediation: "Create separate credentials with minimal required permissions for each distinct use case rather than sharing a high-privilege credential.",
        escalateToLLM: false,
      });
    }
  }
  return violations;
}

// ─── GP-012 — Cyclomatic complexity threshold exceeded ───────────────────────

function gp012(graph: PropertyGraph, config: Config): GraphViolationInternal[] {
  const cc = graph.metadata.cyclomaticComplexity;
  const mediumThreshold = config.maxCyclomaticMedium ?? 10;
  const highThreshold = config.maxCyclomaticHigh ?? 20;

  if (cc <= mediumThreshold) return [];

  return [{
    ruleId: "GP-012",
    severity: cc > highThreshold ? "high" : "medium",
    title: `Workflow cyclomatic complexity is ${cc} (threshold: ${cc > highThreshold ? highThreshold : mediumThreshold})`,
    description: `The workflow has ${cc} independent execution paths. High cyclomatic complexity makes the workflow hard to reason about, debug, and test.`,
    confidence: "certain",
    affectedNodes: [],
    evidence: `cyclomatic complexity: ${cc} | nodes: ${graph.metadata.totalNodes} | edges: ${graph.metadata.totalEdges}`,
    remediation: "Decompose into sub-workflows along natural branch boundaries. Each sub-workflow should ideally have a complexity score below 5.",
    escalateToLLM: false,
  }];
}

// ─── Runner ───────────────────────────────────────────────────────────────────

export function runGraphPatterns(graph: PropertyGraph, config: Config): GraphViolationInternal[] {
  const results: GraphViolationInternal[] = [];

  try { results.push(...gp001(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp002(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp003(graph)); } catch { /* non-fatal */ }
  // GP-004 (cross-workflow cycles) is batch-mode only — skipped for single workflow
  try { results.push(...gp005(graph, config)); } catch { /* non-fatal */ }
  try { results.push(...gp006(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp007(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp008(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp009(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp010(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp011(graph)); } catch { /* non-fatal */ }
  try { results.push(...gp012(graph, config)); } catch { /* non-fatal */ }

  return results;
}
