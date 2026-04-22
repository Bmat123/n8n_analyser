/**
 * Mode B fetcher — pulls a workflow JSON from a live n8n instance via its REST API.
 * Called only when the caller explicitly provides { n8n: { baseUrl, apiKey, workflowId } }.
 */

import axios, { AxiosError } from "axios";
import type { N8nWorkflow } from "@wflow-analyzer/types";

// ─── Typed error classes ──────────────────────────────────────────────────────

export class FetchError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number = 500
  ) {
    super(message);
    this.name = "FetchError";
  }
}

export class FetchAuthError extends FetchError {
  constructor(baseUrl: string) {
    super(
      `Authentication failed fetching from ${baseUrl}. Check that the API key is valid and has workflow:read permission.`,
      401
    );
    this.name = "FetchAuthError";
  }
}

export class FetchNotFoundError extends FetchError {
  constructor(workflowId: string) {
    super(`Workflow "${workflowId}" not found in the n8n instance.`, 404);
    this.name = "FetchNotFoundError";
  }
}

export class FetchTimeoutError extends FetchError {
  constructor(baseUrl: string, timeoutMs: number) {
    super(
      `Request to ${baseUrl} timed out after ${timeoutMs}ms. Check that the n8n instance is reachable.`,
      504
    );
    this.name = "FetchTimeoutError";
  }
}

export class FetchValidationError extends FetchError {
  constructor(workflowId: string) {
    super(
      `Response from n8n for workflow "${workflowId}" did not contain a valid workflow (missing nodes array).`,
      502
    );
    this.name = "FetchValidationError";
  }
}

// ─── Fetcher ──────────────────────────────────────────────────────────────────

/**
 * Fetch a single workflow from a live n8n instance using its REST API.
 *
 * n8n API endpoint: GET /api/v1/workflows/:id
 * Required header:  X-N8N-API-KEY
 *
 * The response envelope is: { data: { id, name, nodes, connections, ... } }
 */
export async function fetchWorkflowFromN8n(
  baseUrl: string,
  apiKey: string,
  workflowId: string,
  timeoutMs: number
): Promise<N8nWorkflow> {
  // Normalise base URL — strip trailing slash
  const base = baseUrl.replace(/\/+$/, "");
  const url = `${base}/api/v1/workflows/${workflowId}`;

  let response: { data: unknown };

  try {
    const result = await axios.get<{ data: unknown }>(url, {
      timeout: timeoutMs,
      headers: {
        "X-N8N-API-KEY": apiKey,
        Accept: "application/json",
      },
      // Don't throw on 4xx/5xx — we handle status codes manually below
      validateStatus: () => true,
    });

    if (result.status === 401 || result.status === 403) {
      throw new FetchAuthError(base);
    }

    if (result.status === 404) {
      throw new FetchNotFoundError(workflowId);
    }

    if (result.status < 200 || result.status >= 300) {
      throw new FetchError(
        `n8n API returned HTTP ${result.status} for workflow "${workflowId}".`,
        502
      );
    }

    response = result.data as { data: unknown };
  } catch (err) {
    // Re-throw our own typed errors as-is
    if (err instanceof FetchError) throw err;

    // Axios timeout
    if (axios.isAxiosError(err)) {
      const axiosErr = err as AxiosError;
      if (axiosErr.code === "ECONNABORTED" || axiosErr.message.includes("timeout")) {
        throw new FetchTimeoutError(base, timeoutMs);
      }
      throw new FetchError(
        `Network error fetching workflow "${workflowId}": ${axiosErr.message}`,
        502
      );
    }

    throw new FetchError(
      `Unexpected error fetching workflow "${workflowId}": ${String(err)}`,
      500
    );
  }

  // Unwrap the n8n API envelope
  const workflow = response?.data ?? response;

  // Minimal validation — must have a nodes array
  if (
    !workflow ||
    typeof workflow !== "object" ||
    !Array.isArray((workflow as Record<string, unknown>).nodes)
  ) {
    throw new FetchValidationError(workflowId);
  }

  return workflow as N8nWorkflow;
}
