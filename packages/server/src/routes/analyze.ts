import type { FastifyInstance } from "fastify";
import {
  analyzeWorkflow,
  enhanceWithAI,
  fetchWorkflowFromN8n,
  FetchAuthError,
  FetchNotFoundError,
  FetchTimeoutError,
  FetchValidationError,
  FetchError,
  buildPropertyGraph,
  runGraphPatterns,
  runLLMEscalation,
  betweennessCentrality,
} from "@n8n-analyzer/core";
import { config } from "../config.js";
import type { Config } from "@n8n-analyzer/core";
import type { N8nWorkflow, GraphAnalysis } from "@n8n-analyzer/types";

// ─── JSON schemas for Fastify validation ─────────────────────────────────────

const workflowInputSchema = {
  type: "object",
  properties: {
    workflow: { type: "object" },
    n8n: {
      type: "object",
      required: ["baseUrl", "apiKey", "workflowId"],
      properties: {
        baseUrl: { type: "string" },
        apiKey: { type: "string" },
        workflowId: { type: "string" },
      },
    },
    ai: { type: "boolean" },
  },
  additionalProperties: false,
};

const batchSchema = {
  type: "object",
  required: ["workflows"],
  properties: {
    workflows: {
      type: "array",
      items: workflowInputSchema,
      minItems: 1,
      maxItems: 20,
    },
    ai: { type: "boolean" },
  },
  additionalProperties: false,
};

// ─── Helper: resolve workflow from request body ───────────────────────────────

async function resolveWorkflow(body: Record<string, unknown>): Promise<N8nWorkflow> {
  if (body.workflow) {
    return body.workflow as N8nWorkflow;
  }

  if (body.n8n) {
    const { baseUrl, apiKey, workflowId } = body.n8n as {
      baseUrl: string;
      apiKey: string;
      workflowId: string;
    };
    return fetchWorkflowFromN8n(baseUrl, apiKey, workflowId, config.n8nFetchTimeoutMs);
  }

  throw new Error("Request must include either 'workflow' or 'n8n' field.");
}

// ─── Graph Analysis Helper ────────────────────────────────────────────────────

async function runGraphAnalysis(workflow: N8nWorkflow, cfg: Config): Promise<GraphAnalysis> {
  const graph = buildPropertyGraph(workflow);
  let violations = runGraphPatterns(graph, cfg);

  // LLM escalation — optional, reuses the existing Gemini key
  let escalatedCount = 0;
  let confirmedCount = 0;
  if (cfg.enableLlmAnalysis && cfg.geminiApiKey) {
    violations = await runLLMEscalation(graph, violations, {
      geminiApiKey: cfg.geminiApiKey,
      timeoutMs: cfg.llmTimeoutMs,
      maxEscalations: cfg.maxLlmEscalations,
    });
    escalatedCount = violations.filter((v) => v.escalateToLLM).length;
    confirmedCount = violations.filter((v) => v.llmConfirmed === true).length;
  }

  // Compute high-centrality nodes (> centralityStddevThreshold stddev above mean)
  const centralityMap = betweennessCentrality(graph);
  const scores = [...centralityMap.values()];
  const mean = scores.reduce((a, b) => a + b, 0) / (scores.length || 1);
  const variance = scores.reduce((a, b) => a + (b - mean) ** 2, 0) / (scores.length || 1);
  const stddev = Math.sqrt(variance);
  const threshold = mean + cfg.centralityStddevThreshold * stddev;
  const highCentralityNodes = [...centralityMap.entries()]
    .filter(([, score]) => score > threshold)
    .map(([name]) => name);

  return {
    enabled: true,
    metrics: {
      cyclomaticComplexity: graph.metadata.cyclomaticComplexity,
      diameter: graph.metadata.diameter,
      hasCycles: graph.metadata.hasCycles,
      orphanedNodes: graph.metadata.orphanedNodes,
      highCentralityNodes,
    },
    graphViolations: violations.map((v) => ({
      ruleId: v.ruleId,
      severity: v.severity,
      title: v.title,
      description: v.description,
      confidence: v.confidence,
      affectedNodes: v.affectedNodes,
      affectedPath: v.affectedPath,
      evidence: v.evidence,
      remediation: v.remediation,
      llmReasoning: v.llmReasoning,
      llmConfirmed: v.llmConfirmed,
    })),
    llmAnalysis: {
      enabled: cfg.enableLlmAnalysis && !!cfg.geminiApiKey,
      escalatedViolations: escalatedCount,
      confirmedByLLM: confirmedCount,
    },
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

export async function analyzeRoutes(app: FastifyInstance) {

  // POST /analyze
  app.post(
    "/analyze",
    { schema: { body: workflowInputSchema } },
    async (request, reply) => {
      const body = request.body as Record<string, unknown>;

      let workflow: N8nWorkflow;
      try {
        workflow = await resolveWorkflow(body);
      } catch (err) {
        if (err instanceof FetchAuthError)      return reply.code(400).send({ error: err.message });
        if (err instanceof FetchNotFoundError)  return reply.code(404).send({ error: err.message });
        if (err instanceof FetchTimeoutError)   return reply.code(504).send({ error: err.message });
        if (err instanceof FetchValidationError) return reply.code(502).send({ error: err.message });
        if (err instanceof FetchError)          return reply.code(502).send({ error: err.message });
        return reply.code(400).send({ error: String(err) });
      }

      const report = await analyzeWorkflow(workflow, config);

      // Graph analysis — optional, gated by ENABLE_GRAPH_ANALYSIS
      if (config.enableGraphAnalysis) {
        try {
          report.graphAnalysis = await runGraphAnalysis(workflow, config);
        } catch {
          report.graphAnalysis = null;
          report.warnings = [...(report.warnings ?? []), "Graph analysis unavailable"];
        }
      }

      // AI enhancement — optional, never blocks the response
      if (body.ai === true && config.geminiApiKey) {
        try {
          report.aiAnalysis = await enhanceWithAI(report, workflow, config.geminiApiKey);
        } catch {
          report.aiAnalysis = null;
          report.warnings = [...(report.warnings ?? []), "AI analysis unavailable"];
        }
      }

      return reply.code(200).send(report);
    }
  );

  // POST /analyze/batch
  app.post(
    "/analyze/batch",
    { schema: { body: batchSchema } },
    async (request, reply) => {
      const { workflows, ai } = request.body as {
        workflows: Record<string, unknown>[];
        ai?: boolean;
      };

      const results = await Promise.allSettled(
        workflows.map(async (item) => {
          const workflow = await resolveWorkflow(item);
          const report = await analyzeWorkflow(workflow, config);

          if (config.enableGraphAnalysis) {
            try {
              report.graphAnalysis = await runGraphAnalysis(workflow, config);
            } catch {
              report.graphAnalysis = null;
              report.warnings = [...(report.warnings ?? []), "Graph analysis unavailable"];
            }
          }

          if (ai && config.geminiApiKey) {
            try {
              report.aiAnalysis = await enhanceWithAI(report, workflow, config.geminiApiKey);
            } catch {
              report.aiAnalysis = null;
              report.warnings = [...(report.warnings ?? []), "AI analysis unavailable"];
            }
          }

          return report;
        })
      );

      const response = results.map((r) =>
        r.status === "fulfilled"
          ? r.value
          : { error: r.reason instanceof Error ? r.reason.message : String(r.reason) }
      );

      return reply.code(200).send(response);
    }
  );
}
