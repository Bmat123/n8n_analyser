/**
 * Pure graph algorithm functions.
 * All operate on adjacency lists or PropertyGraph. No side effects.
 */
import type { PropertyGraph } from "./types.js";

// ─── Adjacency List Helpers ───────────────────────────────────────────────────

export function buildAdjList(graph: PropertyGraph): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const name of graph.nodes.keys()) adj.set(name, []);
  for (const e of graph.edges) {
    adj.get(e.sourceName)?.push(e.targetName);
  }
  return adj;
}

export function buildReverseAdjList(graph: PropertyGraph): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const name of graph.nodes.keys()) adj.set(name, []);
  for (const e of graph.edges) {
    if (!adj.has(e.targetName)) adj.set(e.targetName, []);
    adj.get(e.targetName)!.push(e.sourceName);
  }
  return adj;
}

// ─── reachableNodes ───────────────────────────────────────────────────────────

export interface ReachableOptions {
  maxHops?: number;
  stopAtCategories?: string[];
}

export interface ReachableResult {
  nodeNames: string[];
  paths: string[][];
}

export function reachableNodes(
  graph: PropertyGraph,
  startName: string,
  options: ReachableOptions = {}
): ReachableResult {
  const { maxHops = Infinity, stopAtCategories = [] } = options;
  const stopSet = new Set(stopAtCategories);
  const adj = buildAdjList(graph);
  const visited = new Set<string>();
  const allPaths: string[][] = [];

  function dfs(name: string, depth: number, path: string[]) {
    if (visited.has(name) || depth > maxHops) return;
    visited.add(name);

    const node = graph.nodes.get(name);
    if (node && stopSet.has(node.category)) return;

    for (const next of adj.get(name) ?? []) {
      if (!visited.has(next)) {
        const newPath = [...path, next];
        allPaths.push(newPath);
        dfs(next, depth + 1, newPath);
      }
    }
  }

  dfs(startName, 0, [startName]);
  return { nodeNames: [...visited].filter((n) => n !== startName), paths: allPaths };
}

// ─── pathsBetween ─────────────────────────────────────────────────────────────

export function pathsBetween(
  graph: PropertyGraph,
  sourceName: string,
  targetName: string,
  maxPaths = 1000
): string[][] {
  const adj = buildAdjList(graph);
  const paths: string[][] = [];

  function dfs(current: string, path: string[], visited: Set<string>) {
    if (paths.length >= maxPaths) return;
    if (current === targetName) {
      paths.push([...path]);
      return;
    }
    for (const next of adj.get(current) ?? []) {
      if (!visited.has(next)) {
        visited.add(next);
        path.push(next);
        dfs(next, path, visited);
        path.pop();
        visited.delete(next);
      }
    }
  }

  const visited = new Set<string>([sourceName]);
  dfs(sourceName, [sourceName], visited);
  return paths;
}

// ─── Tarjan's SCC ─────────────────────────────────────────────────────────────

export function tarjanSCC(adj: Map<string, string[]>): string[][] {
  const index = new Map<string, number>();
  const lowlink = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const sccs: string[][] = [];
  let counter = 0;

  function strongConnect(v: string) {
    index.set(v, counter);
    lowlink.set(v, counter);
    counter++;
    stack.push(v);
    onStack.add(v);

    for (const w of adj.get(v) ?? []) {
      if (!index.has(w)) {
        strongConnect(w);
        lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
      } else if (onStack.has(w)) {
        lowlink.set(v, Math.min(lowlink.get(v)!, index.get(w)!));
      }
    }

    if (lowlink.get(v) === index.get(v)) {
      const scc: string[] = [];
      let w: string;
      do {
        w = stack.pop()!;
        onStack.delete(w);
        scc.push(w);
      } while (w !== v);
      sccs.push(scc);
    }
  }

  for (const v of adj.keys()) {
    if (!index.has(v)) strongConnect(v);
  }

  return sccs;
}

export function detectCycles(graph: PropertyGraph): { cycles: string[][]; hasCycles: boolean } {
  const adj = buildAdjList(graph);
  const sccs = tarjanSCC(adj);
  const cycles = sccs.filter((scc) => scc.length > 1);
  return { cycles, hasCycles: cycles.length > 0 };
}

// ─── Topological Sort (Kahn's) ────────────────────────────────────────────────

export function topoSort(graph: PropertyGraph): { sorted: string[]; cycleNodes: string[] } {
  const adj = buildAdjList(graph);
  const inDegree = new Map<string, number>();
  for (const name of graph.nodes.keys()) inDegree.set(name, 0);
  for (const e of graph.edges) {
    inDegree.set(e.targetName, (inDegree.get(e.targetName) ?? 0) + 1);
  }

  const queue = [...inDegree.entries()].filter(([, d]) => d === 0).map(([n]) => n);
  const sorted: string[] = [];

  while (queue.length > 0) {
    const v = queue.shift()!;
    sorted.push(v);
    for (const w of adj.get(v) ?? []) {
      const d = (inDegree.get(w) ?? 1) - 1;
      inDegree.set(w, d);
      if (d === 0) queue.push(w);
    }
  }

  const cycleNodes = [...graph.nodes.keys()].filter((n) => !sorted.includes(n));
  return { sorted, cycleNodes };
}

// ─── Betweenness Centrality (Brandes) ─────────────────────────────────────────

export function betweennessCentrality(graph: PropertyGraph): Map<string, number> {
  const nodes = [...graph.nodes.keys()];
  const adj = buildAdjList(graph);
  const cb = new Map<string, number>();
  for (const n of nodes) cb.set(n, 0);

  for (const s of nodes) {
    const S: string[] = [];
    const P = new Map<string, string[]>();
    const sigma = new Map<string, number>();
    const d = new Map<string, number>();

    for (const n of nodes) {
      P.set(n, []);
      sigma.set(n, 0);
      d.set(n, -1);
    }
    sigma.set(s, 1);
    d.set(s, 0);

    const Q: string[] = [s];
    while (Q.length > 0) {
      const v = Q.shift()!;
      S.push(v);
      for (const w of adj.get(v) ?? []) {
        if (d.get(w) === -1) {
          Q.push(w);
          d.set(w, d.get(v)! + 1);
        }
        if (d.get(w) === d.get(v)! + 1) {
          sigma.set(w, sigma.get(w)! + sigma.get(v)!);
          P.get(w)!.push(v);
        }
      }
    }

    const delta = new Map<string, number>();
    for (const n of nodes) delta.set(n, 0);

    while (S.length > 0) {
      const w = S.pop()!;
      for (const v of P.get(w)!) {
        const c = (sigma.get(v)! / sigma.get(w)!) * (1 + delta.get(w)!);
        delta.set(v, delta.get(v)! + c);
      }
      if (w !== s) cb.set(w, cb.get(w)! + delta.get(w)!);
    }
  }

  return cb;
}

// ─── Diameter ────────────────────────────────────────────────────────────────

export function computeDiameter(adj: Map<string, string[]>): number {
  let diameter = 0;
  for (const start of adj.keys()) {
    const dist = new Map<string, number>();
    dist.set(start, 0);
    const q = [start];
    while (q.length > 0) {
      const v = q.shift()!;
      for (const w of adj.get(v) ?? []) {
        if (!dist.has(w)) {
          dist.set(w, dist.get(v)! + 1);
          if (dist.get(w)! > diameter) diameter = dist.get(w)!;
          q.push(w);
        }
      }
    }
  }
  return diameter;
}

// ─── Cyclomatic Complexity ────────────────────────────────────────────────────

export function computeCyclomaticComplexity(
  nodeCount: number,
  edgeCount: number,
  connectedComponents: number
): number {
  // M = E - N + 2P
  return Math.max(1, edgeCount - nodeCount + 2 * connectedComponents);
}

// ─── Orphaned Nodes ───────────────────────────────────────────────────────────

export function findOrphanedNodes(graph: PropertyGraph): string[] {
  const hasIncoming = new Set(graph.edges.map((e) => e.targetName));
  const hasOutgoing = new Set(graph.edges.map((e) => e.sourceName));
  return [...graph.nodes.keys()].filter(
    (n) => !hasIncoming.has(n) && !hasOutgoing.has(n) && !graph.nodes.get(n)!.isTrigger
  );
}
