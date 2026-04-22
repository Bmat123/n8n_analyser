/**
 * AI enhancement layer — calls Gemini to provide contextual analysis on top of
 * the static rule results. Always additive: if it fails, the static report is
 * returned unchanged with a warning.
 */

import { GoogleGenerativeAI } from "@google/generative-ai";
import type { AnalysisReport, AiAnalysis, N8nWorkflow, N8nNode, Violation, FixSuggestion } from "@wflow-analyzer/types";
import { analyzeWorkflow } from "./index.js";
import type { Config } from "../config.js";

const AI_TIMEOUT_MS = 30_000;
const MAX_NODES_IN_PROMPT = 80;
const MAX_CODE_CHARS = 300;

// ─── Prompt building ──────────────────────────────────────────────────────────

function summariseNode(node: N8nNode): Record<string, unknown> {
  const summary: Record<string, unknown> = {
    name: node.name,
    type: node.type,
  };

  const p = node.parameters;

  if (typeof p.url === "string")            summary.url = p.url.slice(0, 120);
  if (typeof p.requestMethod === "string")  summary.method = p.requestMethod;
  if (typeof p.method === "string")         summary.method = p.method;
  if (typeof p.authentication === "string") summary.authentication = p.authentication;
  if (typeof p.operation === "string")      summary.operation = p.operation;
  if (typeof p.host === "string")           summary.host = p.host;
  if (typeof p.command === "string")        summary.command = p.command.slice(0, 120);

  for (const key of ["jsCode", "functionCode", "code"]) {
    if (typeof p[key] === "string") {
      summary.code = (p[key] as string).slice(0, MAX_CODE_CHARS);
      break;
    }
  }

  if (typeof p.query === "string") summary.query = p.query.slice(0, 200);

  return summary;
}

function buildPrompt(report: AnalysisReport, workflow: N8nWorkflow): string {
  const violatedNodeNames = new Set(
    report.violations.map((v) => v.node?.name).filter(Boolean)
  );

  let nodesToInclude = workflow.nodes;
  if (nodesToInclude.length > MAX_NODES_IN_PROMPT) {
    nodesToInclude = nodesToInclude
      .filter((n) => violatedNodeNames.has(n.name) || !n.disabled)
      .slice(0, MAX_NODES_IN_PROMPT);
  }

  const workflowSummary = {
    name: workflow.name,
    active: workflow.active,
    nodeCount: workflow.nodes.length,
    nodes: nodesToInclude.map(summariseNode),
    connectionCount: Object.keys(workflow.connections).length,
  };

  const violationSummary = report.violations.map((v) => ({
    rule: v.ruleId,
    severity: v.severity,
    node: v.node?.name,
    title: v.title,
    field: v.field,
  }));

  return JSON.stringify(
    { workflow: workflowSummary, staticViolations: violationSummary },
    null,
    2
  );
}

// ─── System instruction ───────────────────────────────────────────────────────

const SYSTEM_INSTRUCTION = `You are a senior application security engineer reviewing an n8n automation workflow.

You have been given:
1. A summary of the workflow structure (node names, types, key parameters)
2. Violations already detected by a static analysis engine

Your job is to add value BEYOND what the static rules already found. Specifically:

1. **dataFlowRisks**: Identify cross-node data flow risks the static rules may have missed. Think about how sensitive data moves from node to node across the whole workflow — not just individual nodes. Be specific about which nodes are involved.

2. **falsePositiveNotes**: Flag any static violations that appear to be false positives given the full workflow context. Explain why with reference to the node names and types. If all violations look legitimate, return an empty array.

3. **remediationPriority**: Given all the violations, return an ordered list of what to fix first. Start with the highest risk. For each item, explain briefly WHY it is the top priority (e.g. "RCE risk if triggered by untrusted input").

4. **suggestedRedesigns**: Suggest architectural changes that would improve the overall security posture — for example, splitting a workflow, adding a sanitisation sub-workflow, or replacing a dangerous node with a safer alternative.

5. **summary**: A 2–4 sentence plain-English narrative of the overall security posture of this workflow.

6. **confidence**: Your confidence in this analysis: "high" if the workflow structure is clear, "medium" if some nodes are ambiguous, "low" if the workflow is too large or complex to reason about fully.

Respond ONLY with valid JSON matching exactly this structure — no markdown, no explanation outside the JSON:
{
  "dataFlowRisks": ["string", ...],
  "falsePositiveNotes": ["string", ...],
  "remediationPriority": ["string", ...],
  "suggestedRedesigns": ["string", ...],
  "summary": "string",
  "confidence": "high" | "medium" | "low"
}`;

// ─── Main export ──────────────────────────────────────────────────────────────

export async function enhanceWithAI(
  report: AnalysisReport,
  workflow: N8nWorkflow,
  apiKey: string
): Promise<AiAnalysis> {
  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({
    model: "gemini-2.5-flash",
    systemInstruction: SYSTEM_INSTRUCTION,
  });

  const userContent = buildPrompt(report, workflow);

  const result = await Promise.race([
    model.generateContent(userContent),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("AI analysis timed out")), AI_TIMEOUT_MS)
    ),
  ]);

  const raw = result.response.text();

  // Strip markdown code fences if the model wraps the JSON
  const text = raw
    .replace(/^```(?:json)?\s*/m, "")
    .replace(/\s*```$/m, "")
    .trim();

  const parsed = JSON.parse(text) as AiAnalysis;

  if (
    typeof parsed.summary !== "string" ||
    !Array.isArray(parsed.dataFlowRisks) ||
    !Array.isArray(parsed.remediationPriority)
  ) {
    throw new Error("AI response did not match expected schema");
  }

  return parsed;
}

// ─── Fix suggestion ───────────────────────────────────────────────────────────

const FIX_SYSTEM_INSTRUCTION = `You are a senior application security engineer.
You will be given a security violation found in an n8n workflow node, along with the node's current parameters.

Your job:
1. Explain in plain English how to fix this specific violation (2-4 sentences).
2. If the fix can be expressed as a replacement of the node's "parameters" object, provide the full patched parameters JSON.
   - Keep all existing parameters that are unrelated to the violation.
   - Only change what is necessary to resolve the violation.
   - If the fix requires moving a secret to n8n's credential vault or other UI-only actions, set patchedParameters to null.

Respond ONLY with valid JSON — no markdown, no explanation outside the JSON:
{
  "explanation": "string",
  "patchedParameters": { ...full replacement parameters object... } | null
}`;

export async function suggestFix(
  violation: Violation,
  node: N8nNode,
  workflow: N8nWorkflow,
  apiKey: string,
  config: Config
): Promise<FixSuggestion> {
  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({
    model: "gemini-2.5-flash",
    systemInstruction: FIX_SYSTEM_INSTRUCTION,
  });

  const prompt = JSON.stringify({
    violation: {
      ruleId: violation.ruleId,
      severity: violation.severity,
      title: violation.title,
      description: violation.description,
      field: violation.field,
      evidence: violation.evidence,
      remediation: violation.remediation,
    },
    nodeName: node.name,
    nodeType: node.type,
    currentParameters: node.parameters,
  }, null, 2);

  const result = await Promise.race([
    model.generateContent(prompt),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("Fix suggestion timed out")), AI_TIMEOUT_MS)
    ),
  ]);

  const raw = result.response.text()
    .replace(/^```(?:json)?\s*/m, "")
    .replace(/\s*```$/m, "")
    .trim();

  const parsed = JSON.parse(raw) as { explanation: string; patchedParameters: Record<string, unknown> | null };

  if (typeof parsed.explanation !== "string") {
    throw new Error("Fix response did not match expected schema");
  }

  // ── Verification ──────────────────────────────────────────────────────────
  // Apply the patch in-memory and re-run the analyzer. If the same ruleId no
  // longer fires on the same node, the fix is verified.
  if (parsed.patchedParameters === null) {
    return {
      explanation: parsed.explanation,
      patchedParameters: null,
      verified: false,
      verificationNote: "Fix requires a manual action (e.g. moving a secret to the credential vault) — cannot be automatically verified.",
    };
  }

  const patchedWorkflow: N8nWorkflow = {
    ...workflow,
    nodes: workflow.nodes.map((n) =>
      n.name === node.name ? { ...n, parameters: parsed.patchedParameters! } : n
    ),
  };

  const recheck = await analyzeWorkflow(patchedWorkflow, config);
  const stillFiring = recheck.violations.some(
    (v) => v.ruleId === violation.ruleId && v.node?.name === violation.node?.name
  );

  return {
    explanation: parsed.explanation,
    patchedParameters: parsed.patchedParameters,
    verified: !stillFiring,
    verificationNote: stillFiring
      ? "Re-analysis shows the violation is still present after applying this patch — review the suggestion carefully before using it."
      : "Re-analysis confirmed: applying this patch removes the violation.",
  };
}
