import type { FastifyInstance } from "fastify";

const VERSION = "1.0.0";

export async function healthRoutes(app: FastifyInstance) {
  app.get(
    "/health",
    {
      schema: {
        response: {
          200: {
            type: "object",
            properties: {
              status: { type: "string" },
              version: { type: "string" },
            },
          },
        },
      },
    },
    async () => ({ status: "ok", version: VERSION })
  );
}
