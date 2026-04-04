import type { FastifyInstance } from "fastify";
import { ALL_RULES } from "../analyzer/rules/index.js";
import type { RuleCategory, Severity } from "@n8n-analyzer/types";

const VALID_CATEGORIES: RuleCategory[] = [
  "credentials", "network", "data_policy",
  "dangerous_nodes", "expression_injection", "workflow_hygiene",
];
const VALID_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

// Pre-sort once at startup: by category then by rule ID
const SORTED_DEFINITIONS = [...ALL_RULES]
  .map((r) => r.definition)
  .sort((a, b) =>
    a.category.localeCompare(b.category) || a.id.localeCompare(b.id)
  );

export async function rulesRoutes(app: FastifyInstance) {
  app.get(
    "/rules",
    {
      schema: {
        querystring: {
          type: "object",
          properties: {
            category: { type: "string", enum: VALID_CATEGORIES },
            severity: { type: "string", enum: VALID_SEVERITIES },
          },
          additionalProperties: false,
        },
      },
    },
    async (request) => {
      const { category, severity } = request.query as {
        category?: RuleCategory;
        severity?: Severity;
      };

      let rules = SORTED_DEFINITIONS;
      if (category) rules = rules.filter((r) => r.category === category);
      if (severity) rules = rules.filter((r) => r.severity === severity);

      return rules;
    }
  );
}
