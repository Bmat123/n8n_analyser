import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { config } from "./config.js";
import { healthRoutes } from "./routes/health.js";
import { rulesRoutes } from "./routes/rules.js";
import { analyzeRoutes } from "./routes/analyze.js";
import { fixRoutes } from "./routes/fix.js";
import { graphRoutes } from "./routes/graph.js";

const app = Fastify({
  logger: false,
  // Inline schema compiler — disables Fastify's strict serialization check
  // so extra fields (like aiAnalysis) are passed through without being stripped
  ajv: {
    customOptions: { strict: false },
  },
});

async function bootstrap() {
  await app.register(cors, { origin: config.corsOrigin });

  await app.register(rateLimit, {
    max: 60,
    timeWindow: "1 minute",
  });

  // Parse body size limit (e.g. "5mb" → bytes)
  const bodyLimit = parseBodyLimit(config.requestSizeLimit);
  app.addContentTypeParser(
    "application/json",
    { parseAs: "string", bodyLimit },
    (_, body, done) => {
      try {
        done(null, JSON.parse(body as string));
      } catch (err) {
        const e = new Error("Invalid JSON body") as Error & { statusCode: number };
        e.statusCode = 400;
        done(e, undefined);
      }
    }
  );

  // Global error handler — no stack traces in responses
  app.setErrorHandler((error, _request, reply) => {
    const status = error.statusCode ?? 500;
    if (status >= 500) {
      app.log.error(error);
      return reply.code(500).send({ error: "Internal server error" });
    }
    return reply.code(status).send({ error: error.message });
  });

  await app.register(healthRoutes);
  await app.register(rulesRoutes);
  await app.register(analyzeRoutes);
  await app.register(fixRoutes);
  await app.register(graphRoutes);

  await app.listen({ port: config.port, host: "0.0.0.0" });
  console.log(`n8n Workflow Analyzer API listening on port ${config.port}`);
  console.log(`AI analysis: ${config.geminiApiKey ? "enabled (Gemini)" : "disabled (no GEMINI_API_KEY)"}`);
}

function parseBodyLimit(raw: string): number {
  const units: Record<string, number> = { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3 };
  const match = raw.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/);
  if (!match) return 5 * 1024 * 1024; // default 5mb
  const value = parseFloat(match[1]);
  const unit = match[2] ?? "b";
  return Math.floor(value * (units[unit] ?? 1));
}

bootstrap().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
