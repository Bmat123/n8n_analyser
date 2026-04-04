/**
 * Internal types for the rule engine.
 * Public-facing API types live in @n8n-analyzer/types.
 */

import type {
  N8nWorkflow,
  RuleDefinition,
  Violation,
} from "@n8n-analyzer/types";
import type { Config } from "../config.js";

export interface RuleContext {
  workflow: N8nWorkflow;
  config: Config;
}

export interface RuleRunner {
  definition: RuleDefinition;
  run(ctx: RuleContext): Violation[];
}
