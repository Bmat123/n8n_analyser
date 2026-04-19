/**
 * LLM Semantic Layer — optional escalation for ambiguous graph violations.
 * Uses the same Gemini model already configured via GEMINI_API_KEY.
 * Gated behind config.enableLlmAnalysis. Falls back gracefully on any failure.
 */
import { GoogleGenerativeAI } from "@google/generative-ai";
import type { PropertyGraph, GraphViolationInternal } from "./types.js";

// ─── Subgraph Serialisation ───────────────────────────────────────────────────

function serialiseSubgraph(graph: PropertyGraph, nodeNames: string[]): string {
  const nameSet = new Set(nodeNames);
  const lines: string[] = [];

  for (const name of nodeNames) {
    const node = graph.nodes.get(name);
    if (!node) continue;
    const outgoing = graph.edges
      .filter((e) => e.sourceName === name && nameSet.has(e.targetName))
      .map((e) => `[${graph.nodes.get(e.targetName)?.category ?? "?"}] "${e.targetName}"`);
    const label = `[${node.category}] "${name}"`;
    lines.push(outgoing.length ? `${label} → ${outgoing.join(", ")}` : `${label} → (terminal)`);
  }

  return lines.join("\n");
}

function serialiseNodeDetails(graph: PropertyGraph, nodeNames: string[]): string {
  return nodeNames
    .slice(0, 20)
    .map((name) => {
      const node = graph.nodes.get(name);
      if (!node) return `  - "${name}" (unknown)`;
      const params = Object.entries(node.parameters)
        .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
        .slice(0, 5)
        .map(([k, v]) => {
          const str = String(v);
          const redacted = /key|secret|token|password|auth|credential/i.test(k)
            ? "[REDACTED]"
            : str.length > 80 ? str.slice(0, 80) + "…" : str;
          return `${k}=${redacted}`;
        })
        .join(", ");
      return `  - "${name}" (${node.type}, ${node.category})${params ? `: ${params}` : ""}`;
    })
    .join("\n");
}

// ─── Prompt ───────────────────────────────────────────────────────────────────

function buildPrompt(graph: PropertyGraph, violation: GraphViolationInternal): string {
  const affectedPath = violation.affectedPath ?? violation.affectedNodes;
  return `You are a workflow security and design analyst. You will be shown a subgraph from an n8n automation workflow and asked to assess a potential issue detected by static analysis.

Workflow name: ${graph.workflowName ?? "(unnamed)"}
Detected issue: ${violation.title} (${violation.ruleId})
Detection reason: ${violation.description}

Affected path:
${serialiseSubgraph(graph, affectedPath)}

Node details:
${serialiseNodeDetails(graph, affectedPath)}

Please assess:
1. Is this a genuine security or reliability risk, or a likely false positive?
2. What appears to be the business intent of this workflow path?
3. Are there any structural factors that mitigate the detected risk?
4. If this is a genuine risk, what is the most practical remediation?

Respond ONLY with valid JSON — no markdown, no explanation outside the JSON:
{
  "confirmed": boolean,
  "confidence": "high" | "medium" | "low",
  "reasoning": "string (max 200 words)",
  "businessIntent": "string",
  "mitigatingFactors": ["string"],
  "suggestedRemediation": "string"
}`;
}

// ─── Public Interface ─────────────────────────────────────────────────────────

export interface LlmConfig {
  geminiApiKey: string;
  timeoutMs: number;
  maxEscalations: number;
}

export async function runLLMEscalation(
  graph: PropertyGraph,
  violations: GraphViolationInternal[],
  llmConfig: LlmConfig
): Promise<GraphViolationInternal[]> {
  const toEscalate = violations
    .filter((v) => v.escalateToLLM)
    .slice(0, llmConfig.maxEscalations);

  if (toEscalate.length === 0) return violations;

  const genAI = new GoogleGenerativeAI(llmConfig.geminiApiKey);
  const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

  const escalatedResults = await Promise.allSettled(
    toEscalate.map(async (violation): Promise<GraphViolationInternal> => {
      const prompt = buildPrompt(graph, violation);

      try {
        const result = await Promise.race([
          model.generateContent(prompt),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("LLM escalation timed out")), llmConfig.timeoutMs)
          ),
        ]);

        const raw = result.response.text()
          .replace(/^```(?:json)?\s*/m, "")
          .replace(/\s*```$/m, "")
          .trim();

        const parsed = JSON.parse(raw) as {
          confirmed?: boolean;
          confidence?: "high" | "medium" | "low";
          reasoning?: string;
        };

        return {
          ...violation,
          confidence: parsed.confirmed === false ? "advisory" : violation.confidence,
          llmReasoning: parsed.reasoning ?? "",
          llmConfirmed: parsed.confirmed ?? true,
        };
      } catch {
        return {
          ...violation,
          confidence: "advisory",
          llmReasoning: "LLM escalation failed; treating as advisory.",
          llmConfirmed: false,
        };
      }
    })
  );

  // Merge escalated results back by matching ruleId + first affected node
  const escalatedMap = new Map<string, GraphViolationInternal>();
  for (const r of escalatedResults) {
    if (r.status === "fulfilled") {
      const key = r.value.ruleId + "|" + (r.value.affectedNodes[0] ?? "");
      escalatedMap.set(key, r.value);
    }
  }

  return violations.map((v) => {
    const key = v.ruleId + "|" + (v.affectedNodes[0] ?? "");
    return escalatedMap.get(key) ?? v;
  });
}
