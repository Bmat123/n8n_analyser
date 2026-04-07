import { useState, useCallback } from "react";
import { useDropzone } from "react-dropzone";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { apiClient } from "../api/client";
import type { AnalysisReport, Violation, Severity, AiAnalysis, FixSuggestion, N8nWorkflow, N8nNode } from "@n8n-analyzer/types";

type Mode = "paste" | "n8n";

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; color: string; badgeCls: string; textCls: string }
> = {
  critical: {
    label: "CRITICAL",
    color: "#ef4444",
    badgeCls: "bg-red-500/20 text-red-400 border border-red-500/30",
    textCls: "text-red-400",
  },
  high: {
    label: "HIGH",
    color: "#f97316",
    badgeCls: "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    textCls: "text-orange-400",
  },
  medium: {
    label: "MEDIUM",
    color: "#eab308",
    badgeCls: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    textCls: "text-yellow-400",
  },
  low: {
    label: "LOW",
    color: "#3b82f6",
    badgeCls: "bg-blue-500/20 text-blue-400 border border-blue-500/30",
    textCls: "text-blue-400",
  },
};

const CATEGORY_LABELS: Record<string, string> = {
  credentials: "Credentials",
  network: "Network",
  data_policy: "Data Policy",
  dangerous_nodes: "Dangerous Nodes",
  expression_injection: "Expression Injection",
  workflow_hygiene: "Workflow Hygiene",
  supply_chain: "Supply Chain",
  data_flow: "Data Flow",
  loop_flow: "Loop & Flow Control",
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const MAX_VISIBLE = 10;

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-mono font-semibold ${cfg.badgeCls}`}>
      {cfg.label}
    </span>
  );
}

function ViolationRow({
  violation,
  index,
  workflow,
}: {
  violation: Violation;
  index: number;
  workflow: N8nWorkflow;
}) {
  const [open, setOpen] = useState(false);
  const [fixLoading, setFixLoading] = useState(false);
  const [fix, setFix] = useState<FixSuggestion | null>(null);
  const [fixError, setFixError] = useState<string | null>(null);
  const cfg = SEVERITY_CONFIG[violation.severity];

  const canSuggestFix =
    violation.node &&
    (violation.severity === "critical" ||
      violation.severity === "high" ||
      violation.severity === "medium");

  const handleSuggestFix = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!violation.node) return;
    setFixLoading(true);
    setFix(null);
    setFixError(null);
    setOpen(true);
    try {
      const fullNode = workflow.nodes.find((n) => n.name === violation.node!.name) as N8nNode;
      const result = await apiClient.suggestFix(violation, fullNode, workflow);
      setFix(result);
    } catch (err: unknown) {
      const apiMsg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setFixError(apiMsg ?? (err instanceof Error ? err.message : "Fix request failed"));
    } finally {
      setFixLoading(false);
    }
  };

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-gray-800/50 transition-colors"
      >
        <span className="text-gray-600 text-xs mt-0.5 shrink-0 w-3">
          {open ? "▼" : "▶"}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <SeverityBadge severity={violation.severity} />
            <span className="text-gray-500 font-mono text-xs">{violation.ruleId}</span>
            <span className="text-gray-500 text-xs">·</span>
            <span className="text-gray-500 text-xs">
              {CATEGORY_LABELS[violation.category] ?? violation.category}
            </span>
          </div>
          <p className={`text-sm font-medium ${cfg.textCls}`}>{violation.title}</p>
          {violation.node && (
            <p className="text-xs text-gray-500 mt-0.5">
              Node: <span className="text-gray-400">{violation.node.name}</span>
              <span className="text-gray-600"> ({violation.node.type})</span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {canSuggestFix && (
            <button
              onClick={handleSuggestFix}
              disabled={fixLoading}
              className="px-2.5 py-1 rounded text-xs font-medium bg-violet-600/20 text-violet-300 border border-violet-500/30 hover:bg-violet-600/40 disabled:opacity-50 transition-colors"
            >
              {fixLoading ? "Asking Gemini…" : fix ? "Refresh fix" : "Suggest fix"}
            </button>
          )}
          <span className="text-gray-700 text-xs">#{index + 1}</span>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-700 bg-gray-900/30 space-y-3">
          <p className="text-sm text-gray-300 leading-relaxed">{violation.description}</p>

          {violation.field && (
            <div>
              <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Field</span>
              <code className="block mt-1 text-xs text-gray-300 bg-gray-800 rounded px-2 py-1 font-mono">
                {violation.field}
              </code>
            </div>
          )}

          {violation.evidence && (
            <div>
              <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Evidence</span>
              <code className="block mt-1 text-xs text-yellow-300 bg-gray-800 rounded px-2 py-1 font-mono break-all">
                {violation.evidence}
              </code>
            </div>
          )}

          <div>
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Remediation</span>
            <p className="mt-1 text-sm text-green-400">{violation.remediation}</p>
          </div>

          {fixError && (
            <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-3 py-2 text-red-300 text-xs">
              {fixError}
            </div>
          )}

          {fix && (
            <div className="border border-violet-500/30 rounded-lg bg-violet-500/5 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-violet-300 uppercase tracking-wide">
                  AI Fix Suggestion
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded border font-medium ${
                    fix.verified
                      ? "text-green-400 bg-green-500/10 border-green-500/30"
                      : "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                  }`}
                >
                  {fix.verified ? "✓ Verified" : "⚠ Unverified"}
                </span>
              </div>

              <p className="text-sm text-gray-300 leading-relaxed">{fix.explanation}</p>

              <p className="text-xs text-gray-500 italic">{fix.verificationNote}</p>

              {fix.patchedParameters && (
                <div>
                  <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">
                    Suggested parameters patch
                  </span>
                  <pre className="mt-1 text-xs text-gray-300 bg-gray-900 rounded px-3 py-2 font-mono overflow-x-auto max-h-64">
                    {JSON.stringify(fix.patchedParameters, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AiPanel({ ai }: { ai: AiAnalysis }) {
  const confidenceColors = {
    high: "text-green-400 bg-green-500/10 border-green-500/30",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    low: "text-gray-400 bg-gray-500/10 border-gray-500/30",
  };

  return (
    <div className="border border-violet-500/30 rounded-xl bg-violet-500/5 p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-violet-300">AI Analysis</h2>
        <span className={`text-xs px-2 py-0.5 rounded border font-medium ${confidenceColors[ai.confidence]}`}>
          {ai.confidence} confidence
        </span>
      </div>

      <p className="text-sm text-gray-300 leading-relaxed">{ai.summary}</p>

      {ai.remediationPriority.length > 0 && (
        <AiSection title="Remediation priority" items={ai.remediationPriority} numbered />
      )}
      {ai.dataFlowRisks.length > 0 && (
        <AiSection title="Data flow risks" items={ai.dataFlowRisks} />
      )}
      {ai.falsePositiveNotes.length > 0 && (
        <AiSection title="Possible false positives" items={ai.falsePositiveNotes} />
      )}
      {ai.suggestedRedesigns.length > 0 && (
        <AiSection title="Suggested redesigns" items={ai.suggestedRedesigns} />
      )}
    </div>
  );
}

function AiSection({ title, items, numbered = false }: { title: string; items: string[]; numbered?: boolean }) {
  return (
    <div>
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">{title}</h3>
      <ul className="space-y-1.5">
        {items.map((item, i) => (
          <li key={i} className="flex gap-2 text-sm text-gray-300">
            <span className="text-gray-600 shrink-0 mt-0.5 font-mono text-xs">
              {numbered ? `${i + 1}.` : "–"}
            </span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Report({ report, workflow, onReset }: { report: AnalysisReport; workflow: N8nWorkflow; onReset: () => void }) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [showAll, setShowAll] = useState(false);

  const { summary, violations, passedRules, skippedRules, metadata, aiAnalysis, warnings } = report;

  const chartData = SEVERITIES.filter((s) => summary[s] > 0).map((s) => ({
    name: SEVERITY_CONFIG[s].label,
    value: summary[s],
    color: SEVERITY_CONFIG[s].color,
  }));

  const categories = [...new Set(violations.map((v) => v.category))].sort();

  // Sort by severity first, then stable within each severity level
  const sorted = [...violations].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  const filtered = sorted.filter(
    (v) =>
      (severityFilter === "all" || v.severity === severityFilter) &&
      (categoryFilter === "all" || v.category === categoryFilter)
  );

  // When more than MAX_VISIBLE, drop lowest-severity items unless showAll
  const visible = showAll || filtered.length <= MAX_VISIBLE
    ? filtered
    : filtered.slice(0, MAX_VISIBLE);

  const hiddenCount = filtered.length - visible.length;

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${report.workflowName?.replace(/\s+/g, "-") ?? "workflow"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <button
            onClick={onReset}
            className="text-gray-500 hover:text-gray-300 text-sm mb-2 flex items-center gap-1 transition-colors"
          >
            ← Analyze another workflow
          </button>
          <h1 className="text-2xl font-bold text-white">
            {report.workflowName ?? "Workflow Report"}
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            {summary.totalNodes} node{summary.totalNodes !== 1 ? "s" : ""} ·{" "}
            {metadata.nodeTypesFound?.join(", ")} · Analyzer v{metadata.analyzerVersion}
          </p>
        </div>
        <button
          onClick={handleExport}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm font-medium rounded-lg transition-colors shrink-0"
        >
          Export JSON
        </button>
      </div>

      {warnings && warnings.length > 0 && (
        <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg px-4 py-2.5 text-yellow-300 text-sm">
          {warnings.join(" · ")}
        </div>
      )}

      {/* Summary + chart */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-4">
            Violations by severity
          </h2>
          <div className="grid grid-cols-2 gap-3">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter((f) => (f === s ? "all" : s))}
                className={`rounded-lg p-3 text-left transition-colors border ${
                  severityFilter === s ? "border-gray-500 bg-gray-700" : "border-gray-700 hover:border-gray-600"
                }`}
              >
                <div className="text-2xl font-bold" style={{ color: SEVERITY_CONFIG[s].color }}>
                  {summary[s]}
                </div>
                <div className="text-xs text-gray-400 mt-0.5">{SEVERITY_CONFIG[s].label}</div>
              </button>
            ))}
          </div>
          <div className="mt-3 pt-3 border-t border-gray-700 flex items-center justify-between text-sm text-gray-400">
            <span>{summary.passed} rules passed</span>
            {skippedRules.length > 0 && <span>{skippedRules.length} skipped</span>}
          </div>
        </div>

        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 flex flex-col items-center justify-center">
          {summary.totalViolations === 0 ? (
            <div className="text-center">
              <div className="text-5xl mb-3">✓</div>
              <p className="text-green-400 font-semibold">No violations found</p>
              <p className="text-gray-500 text-sm mt-1">{summary.passed} rules passed</p>
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={chartData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} dataKey="value" stroke="none">
                    {chartData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#1f2937",
                      border: "1px solid #374151",
                      borderRadius: "8px",
                      fontSize: "12px",
                      color: "#e5e7eb",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap justify-center gap-3 mt-1">
                {chartData.map((d) => (
                  <div key={d.name} className="flex items-center gap-1.5 text-xs text-gray-400">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                    {d.name}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* AI analysis */}
      {aiAnalysis && <AiPanel ai={aiAnalysis} />}

      {/* Violations list */}
      {violations.length > 0 && (
        <div>
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <h2 className="text-base font-semibold text-white">
              Violations
              <span className="ml-2 text-gray-500 font-normal text-sm">
                {filtered.length} / {violations.length}
              </span>
            </h2>

            <div className="flex gap-1 ml-auto">
              <button
                onClick={() => { setSeverityFilter("all"); setShowAll(false); }}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  severityFilter === "all" ? "bg-gray-600 text-white" : "text-gray-400 hover:text-white"
                }`}
              >
                All
              </button>
              {SEVERITIES.filter((s) => summary[s] > 0).map((s) => (
                <button
                  key={s}
                  onClick={() => { setSeverityFilter((f) => (f === s ? "all" : s)); setShowAll(false); }}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                    severityFilter === s ? "bg-gray-600 text-white" : "text-gray-500 hover:text-gray-300"
                  }`}
                  style={severityFilter === s ? { color: SEVERITY_CONFIG[s].color } : {}}
                >
                  {SEVERITY_CONFIG[s].label}
                </button>
              ))}
            </div>

            {categories.length > 1 && (
              <select
                value={categoryFilter}
                onChange={(e) => { setCategoryFilter(e.target.value); setShowAll(false); }}
                className="bg-gray-800 text-gray-300 text-xs rounded px-2 py-1 border border-gray-700 focus:outline-none"
              >
                <option value="all">All categories</option>
                {categories.map((c) => (
                  <option key={c} value={c}>{CATEGORY_LABELS[c] ?? c}</option>
                ))}
              </select>
            )}
          </div>

          <div className="space-y-2">
            {filtered.length === 0 ? (
              <p className="text-gray-500 text-sm py-4 text-center">No violations match the current filters.</p>
            ) : (
              visible.map((v, i) => (
                <ViolationRow key={`${v.ruleId}-${i}`} violation={v} index={i} workflow={workflow} />
              ))
            )}
          </div>

          {hiddenCount > 0 && (
            <button
              onClick={() => setShowAll(true)}
              className="mt-3 w-full py-2 rounded-lg border border-gray-700 text-gray-400 text-sm hover:border-gray-500 hover:text-gray-200 transition-colors"
            >
              Show all — {hiddenCount} more {hiddenCount === 1 ? "violation" : "violations"} hidden
              <span className="ml-2 text-gray-600 text-xs">(lower severity)</span>
            </button>
          )}
          {showAll && filtered.length > MAX_VISIBLE && (
            <button
              onClick={() => setShowAll(false)}
              className="mt-3 w-full py-2 rounded-lg border border-gray-700 text-gray-500 text-sm hover:border-gray-600 hover:text-gray-300 transition-colors"
            >
              Show fewer
            </button>
          )}
        </div>
      )}

      {/* Passed rules */}
      {passedRules.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-2">
            Passed rules ({passedRules.length})
          </h2>
          <div className="flex flex-wrap gap-2">
            {passedRules.map((id) => (
              <span key={id} className="px-2 py-0.5 rounded text-xs font-mono bg-green-500/10 text-green-400 border border-green-500/20">
                {id}
              </span>
            ))}
          </div>
        </div>
      )}

      {skippedRules.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-2">
            Skipped rules ({skippedRules.length})
          </h2>
          <div className="flex flex-wrap gap-2">
            {skippedRules.map((id) => (
              <span key={id} className="px-2 py-0.5 rounded text-xs font-mono bg-gray-700 text-gray-500 border border-gray-600">
                {id}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Example workflow ─────────────────────────────────────────────────────────
// Intentionally contains several violations so the scan result is interesting:
//   SEC-001  hardcoded Stripe key in HTTP header
//   SEC-002  API key in URL query string
//   DP-001   webhook with no authentication
//   DP-004   console.log in Code node
//   EXP-001  webhook input flows into Code node without sanitisation

const EXAMPLE_WORKFLOW = JSON.stringify(
  {
    id: "example-001",
    name: "Payment Webhook Processor",
    active: true,
    nodes: [
      {
        id: "n1",
        name: "Payment Webhook",
        type: "n8n-nodes-base.webhook",
        position: [100, 200],
        parameters: {
          path: "payment",
          httpMethod: "POST",
          authentication: "none",
        },
      },
      {
        id: "n2",
        name: "Process Payment",
        type: "n8n-nodes-base.code",
        position: [350, 200],
        parameters: {
          jsCode: `// Process incoming payment data
const amount = $json.body.amount;
const user   = $json.body.userId;
console.log('Processing payment', amount, 'for user', user);
return [{ json: { amount, user, status: 'processed' } }];`,
        },
      },
      {
        id: "n3",
        name: "Call Stripe",
        type: "n8n-nodes-base.httpRequest",
        position: [600, 200],
        parameters: {
          url: "https://api.stripe.com/v1/charges",
          requestMethod: "POST",
          authentication: "none",
          headerParameters: {
            values: [
              { name: "Authorization", value: "Bearer sk_live_51ABCDEFabcdefghij1234567890" },
            ],
          },
        },
      },
      {
        id: "n4",
        name: "Log to Analytics",
        type: "n8n-nodes-base.httpRequest",
        position: [850, 200],
        parameters: {
          url: "https://analytics.example.com/track?api_key=supersecret_analytics_key_abc123",
          requestMethod: "POST",
        },
      },
    ],
    connections: {
      "Payment Webhook": {
        main: [[{ node: "Process Payment", type: "main", index: 0 }]],
      },
      "Process Payment": {
        main: [[{ node: "Call Stripe", type: "main", index: 0 }]],
      },
      "Call Stripe": {
        main: [[{ node: "Log to Analytics", type: "main", index: 0 }]],
      },
    },
  },
  null,
  2
);

// ─── Submit form ──────────────────────────────────────────────────────────────

export default function SubmitPage() {
  const [mode, setMode] = useState<Mode>("paste");
  const [json, setJson] = useState("");
  const [n8nConfig, setN8nConfig] = useState({ baseUrl: "", apiKey: "", workflowId: "" });
  const [ai, setAi] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [submittedWorkflow, setSubmittedWorkflow] = useState<N8nWorkflow | null>(null);

  const onDrop = useCallback((files: File[]) => {
    const file = files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => setJson((e.target?.result as string) ?? "");
    reader.readAsText(file);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "application/json": [".json"] },
    multiple: false,
    noClick: true,
  });

  const canSubmit =
    mode === "paste"
      ? json.trim().length > 0
      : !!(n8nConfig.baseUrl && n8nConfig.apiKey && n8nConfig.workflowId);

  const handleSubmit = async () => {
    setError(null);
    setLoading(true);
    try {
      let result: AnalysisReport;
      let parsedWorkflow: N8nWorkflow | null = null;
      if (mode === "paste") {
        try {
          parsedWorkflow = JSON.parse(json) as N8nWorkflow;
        } catch {
          throw new Error("Invalid JSON — check the pasted content.");
        }
        result = await apiClient.submitWorkflow({ workflow: parsedWorkflow, ai });
      } else {
        result = await apiClient.submitWorkflow({ n8n: n8nConfig, ai });
      }
      setSubmittedWorkflow(parsedWorkflow);
      setReport(result);
    } catch (err: unknown) {
      const apiMsg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(apiMsg ?? (err instanceof Error ? err.message : "Request failed"));
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setReport(null);
    setSubmittedWorkflow(null);
    setError(null);
  };

  if (report && submittedWorkflow) {
    return <Report report={report} workflow={submittedWorkflow} onReset={handleReset} />;
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold text-white mb-1">Analyze a Workflow</h1>
      <p className="text-gray-400 mb-6 text-sm">
        Paste exported workflow JSON or connect directly to a live n8n instance.
      </p>

      {/* Mode tabs + load example */}
      <div className="flex items-center gap-3 mb-4">
        <div className="flex gap-1 bg-gray-800 p-1 rounded-lg w-fit">
          {(["paste", "n8n"] as Mode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                mode === m ? "bg-gray-600 text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              {m === "paste" ? "Paste JSON" : "n8n API"}
            </button>
          ))}
        </div>
        {mode === "paste" && (
          <button
            onClick={() => setJson(EXAMPLE_WORKFLOW)}
            className="text-xs text-violet-400 hover:text-violet-300 transition-colors"
          >
            Load example
          </button>
        )}
      </div>

      {mode === "paste" ? (
        <div {...getRootProps()} className="relative">
          <input {...getInputProps()} />
          {isDragActive && (
            <div className="absolute inset-0 bg-violet-500/10 border-2 border-violet-500 border-dashed rounded-lg z-10 flex items-center justify-center pointer-events-none">
              <p className="text-violet-300 font-medium">Drop workflow JSON here</p>
            </div>
          )}
          <textarea
            className="w-full h-72 bg-gray-800 text-gray-200 font-mono text-xs rounded-lg p-3 border border-gray-700 focus:border-gray-500 focus:outline-none resize-none placeholder-gray-600"
            placeholder={`Paste n8n workflow JSON here, or drop a .json file anywhere on this area…\n\n{\n  "id": "abc123",\n  "name": "My Workflow",\n  "active": true,\n  "nodes": [...],\n  "connections": {}\n}`}
            value={json}
            onChange={(e) => setJson(e.target.value)}
            spellCheck={false}
          />
          <p className="text-gray-600 text-xs mt-1.5">
            Drag and drop a .json file anywhere on this area to load it.
          </p>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg p-5 space-y-4 border border-gray-700">
          {(
            [
              { key: "baseUrl", label: "n8n base URL", placeholder: "https://my-n8n.example.com", type: "text" },
              { key: "apiKey", label: "API key", placeholder: "n8n API key — Settings → API Keys", type: "password" },
              { key: "workflowId", label: "Workflow ID", placeholder: "abc123", type: "text" },
            ] as const
          ).map(({ key, label, placeholder, type }) => (
            <div key={key}>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">{label}</label>
              <input
                type={type}
                className="w-full bg-gray-900 text-gray-200 rounded-md px-3 py-2 text-sm border border-gray-700 focus:border-gray-500 focus:outline-none"
                placeholder={placeholder}
                value={n8nConfig[key]}
                onChange={(e) => setN8nConfig((c) => ({ ...c, [key]: e.target.value }))}
              />
            </div>
          ))}
          <p className="text-xs text-gray-500">
            Your API key is sent only to your own n8n instance and is not stored by this server.
          </p>
        </div>
      )}

      <label className="flex items-center gap-2.5 mt-5 cursor-pointer w-fit select-none">
        <input
          type="checkbox"
          className="w-4 h-4 accent-violet-500"
          checked={ai}
          onChange={(e) => setAi(e.target.checked)}
        />
        <span className="text-sm text-gray-300">Enable AI analysis</span>
        <span className="text-xs text-gray-500">(requires GEMINI_API_KEY on the server)</span>
      </label>

      {error && (
        <div className="mt-4 bg-red-900/30 border border-red-700/50 rounded-lg px-4 py-3 text-red-300 text-sm">
          {error}
        </div>
      )}

      <button
        onClick={handleSubmit}
        disabled={loading || !canSubmit}
        className="mt-5 px-6 py-2.5 bg-violet-600 hover:bg-violet-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-medium rounded-lg text-sm transition-colors"
      >
        {loading ? "Analyzing…" : "Analyze workflow"}
      </button>
    </div>
  );
}
