/**
 * Serialises a PropertyGraph into human-readable and LLM-friendly formats.
 */
import type { PropertyGraph, GraphNode } from "./types.js";
import { buildAdjList } from "./algorithms.js";
import { pathsBetween } from "./algorithms.js";

// ─── Adjacency List (text) ────────────────────────────────────────────────────

export function toAdjacencyListText(graph: PropertyGraph): string {
  const lines: string[] = [];
  const adj = buildAdjList(graph);
  for (const [name, neighbours] of adj) {
    const node = graph.nodes.get(name);
    const label = node ? `[${node.category}] "${name}"` : `"${name}"`;
    if (neighbours.length === 0) {
      lines.push(`${label} → (terminal)`);
    } else {
      for (const target of neighbours) {
        const tNode = graph.nodes.get(target);
        const tLabel = tNode ? `[${tNode.category}] "${target}"` : `"${target}"`;
        lines.push(`${label} → ${tLabel}`);
      }
    }
  }
  return lines.join("\n");
}

// ─── Compact adjacency map ────────────────────────────────────────────────────

export function toAdjacencyMap(graph: PropertyGraph): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  const adj = buildAdjList(graph);
  for (const [name, neighbours] of adj) {
    result[name] = neighbours;
  }
  return result;
}

// ─── Mermaid ──────────────────────────────────────────────────────────────────

function sanitiseMermaidId(name: string): string {
  return name.replace(/[^a-zA-Z0-9]/g, "_");
}

function mermaidShape(node: GraphNode): string {
  const id = sanitiseMermaidId(node.name);
  const label = node.name.replace(/"/g, "'");
  if (node.isTrigger) return `${id}([\"${label}\"])`;
  if (node.isTerminal) return `${id}[\"${label}\"]`;
  if (node.category === "logic:filter") return `${id}{\"${label}\"}`;
  if (node.category === "logic:loop") return `${id}[/\"${label}\"/]`;
  return `${id}[\"${label}\"]`;
}

export function toMermaid(graph: PropertyGraph): string {
  const lines = ["flowchart LR"];
  for (const node of graph.nodes.values()) {
    lines.push(`  ${mermaidShape(node)}`);
  }
  for (const edge of graph.edges) {
    const src = sanitiseMermaidId(edge.sourceName);
    const tgt = sanitiseMermaidId(edge.targetName);
    const label = edge.sourceBranch > 0 ? ` |${edge.branchType}|` : "";
    lines.push(`  ${src} -->${label} ${tgt}`);
  }
  return lines.join("\n");
}

// ─── Path Enumeration ─────────────────────────────────────────────────────────

export function enumerateAllPaths(graph: PropertyGraph): string[][] {
  const paths: string[][] = [];
  for (const triggerName of graph.metadata.triggerNodes) {
    for (const terminalName of graph.metadata.terminalNodes) {
      if (triggerName !== terminalName) {
        paths.push(...pathsBetween(graph, triggerName, terminalName, 100));
      }
    }
  }
  return paths;
}

// ─── Knowledge Graph Triples ──────────────────────────────────────────────────

export function toKnowledgeGraphTriples(graph: PropertyGraph): [string, string, string][] {
  const triples: [string, string, string][] = [];

  for (const node of graph.nodes.values()) {
    triples.push([node.name, "hasType", node.type]);
    triples.push([node.name, "hasCategory", node.category]);
    if (node.isTrigger) triples.push([node.name, "isTrigger", "true"]);
    if (node.isTerminal) triples.push([node.name, "isTerminal", "true"]);
    for (const cred of node.credentials) {
      triples.push([node.name, "usesCredential", `${cred.credentialType}:${cred.credentialId}`]);
    }
  }

  for (const edge of graph.edges) {
    const predicate = edge.sourceBranch === 0 ? "flowsTo" : `flowsTo_${edge.branchType}`;
    triples.push([edge.sourceName, predicate, edge.targetName]);
    if (edge.dataSchema?.piiFields.length) {
      for (const f of edge.dataSchema.piiFields) {
        triples.push([edge.id, "carriesPII", f]);
      }
    }
  }

  return triples;
}
