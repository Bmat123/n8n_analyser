import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import type { RuleDefinition, Severity, RuleCategory } from "@n8n-analyzer/types";

const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; badgeCls: string }
> = {
  critical: { label: "Critical", badgeCls: "bg-red-500/20 text-red-400 border border-red-500/30" },
  high: { label: "High", badgeCls: "bg-orange-500/20 text-orange-400 border border-orange-500/30" },
  medium: { label: "Medium", badgeCls: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30" },
  low: { label: "Low", badgeCls: "bg-blue-500/20 text-blue-400 border border-blue-500/30" },
};

const CATEGORY_LABELS: Record<RuleCategory, string> = {
  credentials: "Credentials",
  network: "Network",
  data_policy: "Data Policy",
  dangerous_nodes: "Dangerous Nodes",
  expression_injection: "Expression Injection",
  workflow_hygiene: "Workflow Hygiene",
};

const ALL_CATEGORIES = Object.keys(CATEGORY_LABELS) as RuleCategory[];
const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

function RuleCard({ rule }: { rule: RuleDefinition }) {
  const [open, setOpen] = useState(false);
  const sev = SEVERITY_CONFIG[rule.severity];

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden bg-gray-800/40">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-gray-800 transition-colors"
      >
        <span className="text-gray-600 text-xs mt-0.5 shrink-0 w-3">
          {open ? "▼" : "▶"}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className="font-mono text-sm font-semibold text-gray-200">
              {rule.id}
            </span>
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${sev.badgeCls}`}>
              {sev.label}
            </span>
            <span className="text-xs text-gray-500">
              {CATEGORY_LABELS[rule.category] ?? rule.category}
            </span>
          </div>
          <p className="text-sm text-gray-300">{rule.title}</p>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-2 border-t border-gray-700 bg-gray-900/30 space-y-3">
          <p className="text-sm text-gray-400 leading-relaxed">{rule.description}</p>
          <div>
            <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
              Remediation
            </span>
            <p className="mt-1 text-sm text-green-400">{rule.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default function RulesPage() {
  const [category, setCategory] = useState<RuleCategory | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [search, setSearch] = useState("");

  const { data: rules = [], isLoading, error } = useQuery({
    queryKey: ["rules", category, severity],
    queryFn: () =>
      apiClient.getRules({
        category: category || undefined,
        severity: severity || undefined,
      }),
  });

  const filtered = rules.filter((r) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      r.id.toLowerCase().includes(q) ||
      r.title.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q)
    );
  });

  // Group by category for display
  const grouped = filtered.reduce<Record<string, RuleDefinition[]>>((acc, r) => {
    const key = CATEGORY_LABELS[r.category] ?? r.category;
    if (!acc[key]) acc[key] = [];
    acc[key].push(r);
    return acc;
  }, {});

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-1">Rule Catalogue</h1>
        <p className="text-gray-400 text-sm">
          {rules.length} rules across {ALL_CATEGORIES.length} categories. Click a rule to see
          its description and remediation guidance.
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-6">
        <input
          type="text"
          placeholder="Search rules…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-gray-800 text-gray-200 text-sm rounded-lg px-3 py-2 border border-gray-700 focus:border-gray-500 focus:outline-none w-52"
        />
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value as RuleCategory | "")}
          className="bg-gray-800 text-gray-300 text-sm rounded-lg px-3 py-2 border border-gray-700 focus:outline-none"
        >
          <option value="">All categories</option>
          {ALL_CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {CATEGORY_LABELS[c]}
            </option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity | "")}
          className="bg-gray-800 text-gray-300 text-sm rounded-lg px-3 py-2 border border-gray-700 focus:outline-none"
        >
          <option value="">All severities</option>
          {ALL_SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_CONFIG[s].label}
            </option>
          ))}
        </select>
        {(category || severity || search) && (
          <button
            onClick={() => { setCategory(""); setSeverity(""); setSearch(""); }}
            className="text-gray-400 hover:text-white text-sm transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {isLoading && (
        <p className="text-gray-500 text-sm py-8 text-center">Loading rules…</p>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-4 py-3 text-red-300 text-sm">
          Could not load rules — is the API server running?
        </div>
      )}

      {!isLoading && !error && filtered.length === 0 && (
        <p className="text-gray-500 text-sm py-8 text-center">
          No rules match the current filters.
        </p>
      )}

      <div className="space-y-6">
        {Object.entries(grouped).map(([cat, catRules]) => (
          <div key={cat}>
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
              {cat} ({catRules.length})
            </h2>
            <div className="space-y-2">
              {catRules.map((r) => (
                <RuleCard key={r.id} rule={r} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
