import axios from "axios";
import type {
  AnalysisReport,
  RuleDefinition,
  AnalyzeWorkflowRequest,
  AnalyzeN8nRequest,
  BatchAnalyzeResponse,
  Violation,
  N8nNode,
  N8nWorkflow,
  FixSuggestion,
} from "@wflow-analyzer/types";

const http = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "/api",
  headers: { "Content-Type": "application/json" },
});

export const apiClient = {
  submitWorkflow(
    payload: AnalyzeWorkflowRequest | AnalyzeN8nRequest
  ): Promise<AnalysisReport> {
    return http.post<AnalysisReport>("/analyze", payload).then((r) => r.data);
  },

  submitBatch(
    workflows: Array<AnalyzeWorkflowRequest | AnalyzeN8nRequest>,
    ai = false
  ): Promise<BatchAnalyzeResponse> {
    return http
      .post<BatchAnalyzeResponse>("/analyze/batch", { workflows, ai })
      .then((r) => r.data);
  },

  getRules(params?: {
    category?: string;
    severity?: string;
  }): Promise<RuleDefinition[]> {
    return http
      .get<RuleDefinition[]>("/rules", { params })
      .then((r) => r.data);
  },

  getHealth(): Promise<{ status: string; version: string }> {
    return http
      .get<{ status: string; version: string }>("/health")
      .then((r) => r.data);
  },

  suggestFix(
    violation: Violation,
    node: N8nNode,
    workflow: N8nWorkflow
  ): Promise<FixSuggestion> {
    return http
      .post<FixSuggestion>("/analyze/fix", { violation, node, workflow })
      .then((r) => r.data);
  },
};
