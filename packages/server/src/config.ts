import { resolve } from "node:path";
import { config as loadEnv } from "dotenv";
import { buildConfig } from "@wflow-analyzer/core";
export type { Config } from "@wflow-analyzer/core";

// Load .env from the monorepo root before any process.env access
loadEnv({ path: resolve(__dirname, "../../../.env") });

export { buildConfig };
export const config = buildConfig(process.env);
