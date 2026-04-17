import type { FastifyInstance } from "fastify";
import {
  fetchWorkflowFromN8n,
  FetchAuthError,
  FetchNotFoundError,
  FetchTimeoutError,
  FetchValidationError,
  FetchError,
} from "../fetcher.js";
import { config } from "../config.js";
import { buildPropertyGraph } from "../graph/builder.js";
import {
  toAdjacencyListText,
  toAdjacencyMap,
  toMermaid,
  enumerateAllPaths,
  toKnowledgeGraphTriples,
} from "../graph/serialisers.js";
import type { N8nWorkflow } from "@n8n-analyzer/types";

// ─── JSON schemas ─────────────────────────────────────────────────────────────

const graphBodySchema = {
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
    format: { type: "string" },
  },
  additionalProperties: false,
};

// ─── Available formats ────────────────────────────────────────────────────────

const FORMATS = [
  {
    id: "adjacency_list",
    description: "Compact node-edge representation with semantic labels",
    example: '[trigger:webhook] "Receive Order" → [logic:filter] "Has Email?" → [io:external_call] "POST to Payment API"',
  },
  {
    id: "adjacency_map",
    description: "JSON map of node name to list of successor node names",
  },
  {
    id: "path_enumeration",
    description: "All source-to-terminal paths as ordered sequences",
  },
  {
    id: "mermaid",
    description: "Mermaid graph diagram syntax, renderable and LLM-friendly",
  },
  {
    id: "knowledge_graph_triples",
    description: "Subject-predicate-object triples capturing node relationships and ontology",
  },
];

// ─── Helper ───────────────────────────────────────────────────────────────────

async function resolveWorkflow(body: Record<string, unknown>): Promise<N8nWorkflow> {
  if (body.workflow) return body.workflow as N8nWorkflow;
  if (body.n8n) {
    const { baseUrl, apiKey, workflowId } = body.n8n as {
      baseUrl: string; apiKey: string; workflowId: string;
    };
    return fetchWorkflowFromN8n(baseUrl, apiKey, workflowId, config.n8nFetchTimeoutMs);
  }
  throw new Error("Request must include either 'workflow' or 'n8n' field.");
}

function serialiseNodes(graph: ReturnType<typeof buildPropertyGraph>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, node] of graph.nodes) {
    out[name] = {
      id: node.id,
      type: node.type,
      category: node.category,
      isTrigger: node.isTrigger,
      isTerminal: node.isTerminal,
      credentials: node.credentials,
      position: node.position,
    };
  }
  return out;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

export async function graphRoutes(app: FastifyInstance) {

  // GET /graph/formats
  app.get("/graph/formats", async (_request, reply) => {
    return reply.code(200).send({ formats: FORMATS });
  });

  // POST /graph
  app.post(
    "/graph",
    { schema: { body: graphBodySchema } },
    async (request, reply) => {
      const body = request.body as Record<string, unknown>;
      const format = (body.format as string | undefined)?.toLowerCase() ?? "adjacency_list";

      let workflow: N8nWorkflow;
      try {
        workflow = await resolveWorkflow(body);
      } catch (err) {
        if (err instanceof FetchAuthError)       return reply.code(400).send({ error: err.message });
        if (err instanceof FetchNotFoundError)   return reply.code(404).send({ error: err.message });
        if (err instanceof FetchTimeoutError)    return reply.code(504).send({ error: err.message });
        if (err instanceof FetchValidationError) return reply.code(502).send({ error: err.message });
        if (err instanceof FetchError)           return reply.code(502).send({ error: err.message });
        return reply.code(400).send({ error: String(err) });
      }

      const graph = buildPropertyGraph(workflow);

      // Compute the requested format representation
      let formatData: unknown;
      switch (format) {
        case "adjacency_map":
          formatData = toAdjacencyMap(graph);
          break;
        case "path_enumeration":
          formatData = enumerateAllPaths(graph);
          break;
        case "mermaid":
          formatData = toMermaid(graph);
          break;
        case "knowledge_graph_triples":
          formatData = toKnowledgeGraphTriples(graph);
          break;
        case "adjacency_list":
        default:
          formatData = toAdjacencyListText(graph);
          break;
      }

      return reply.code(200).send({
        workflowId: graph.workflowId,
        workflowName: graph.workflowName,
        format,
        formatData,
        nodes: serialiseNodes(graph),
        edges: graph.edges,
        metadata: graph.metadata,
      });
    }
  );
}
