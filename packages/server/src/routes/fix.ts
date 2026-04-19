import type { FastifyInstance } from "fastify";
import { suggestFix } from "@n8n-analyzer/core";
import { config } from "../config.js";

const fixSchema = {
  type: "object",
  required: ["violation", "node", "workflow"],
  properties: {
    violation: { type: "object" },
    node: { type: "object" },
    workflow: { type: "object" },
  },
  additionalProperties: false,
};

export async function fixRoutes(app: FastifyInstance) {
  app.post("/analyze/fix", { schema: { body: fixSchema } }, async (request, reply) => {
    if (!config.geminiApiKey) {
      return reply.code(503).send({ error: "AI fix suggestions require GEMINI_API_KEY to be set on the server." });
    }

    const { violation, node, workflow } = request.body as Record<string, unknown>;

    try {
      const suggestion = await suggestFix(
        violation as never,
        node as never,
        workflow as never,
        config.geminiApiKey,
        config
      );
      return reply.code(200).send(suggestion);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Fix suggestion failed";
      return reply.code(502).send({ error: msg });
    }
  });
}
