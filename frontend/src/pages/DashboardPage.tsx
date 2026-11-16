import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { api } from "@/lib/api";
import type { DashboardSummary } from "@/types";
import { StatCard } from "@/components/StatCard";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
  info: "#64748b",
};

export function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<DashboardSummary>("/dashboard/summary")
      .then((res) => setSummary(res.data))
      .catch(() => setError("Failed to load dashboard data."))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="p-8 text-slate-500">Loading dashboard...</div>;
  if (error || !summary) return <div className="p-8 text-red-600">{error}</div>;

  const severityData = Object.entries(summary.vulnerabilities_by_severity)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => ({ severity: severity.charAt(0).toUpperCase() + severity.slice(1), count, key: severity }));

  return (
    <div className="p-8 space-y-8">
      <div>
        <h2 className="text-2xl font-bold text-slate-900">Risk Posture Overview</h2>
        <p className="text-sm text-slate-500">Live snapshot across your organization's tracked assets and findings.</p>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Open Vulnerabilities" value={summary.total_open_vulnerabilities} />
        <StatCard label="Assets Tracked" value={summary.total_assets} />
        <StatCard
          label="Actively Exploited (KEV)"
          value={summary.known_exploited_open_count}
          tone={summary.known_exploited_open_count > 0 ? "danger" : "success"}
        />
        <StatCard
          label="SLA Compliance"
          value={`${summary.sla_compliance.compliance_rate}%`}
          tone={summary.sla_compliance.compliance_rate < 80 ? "warning" : "success"}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <h3 className="text-sm font-semibold text-slate-900">Open Findings by Severity</h3>
          <div className="mt-4 h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="severity" fontSize={12} />
                <YAxis fontSize={12} allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry) => (
                    <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key] ?? "#64748b"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <h3 className="text-sm font-semibold text-slate-900">Highest-Risk Assets</h3>
          <table className="mt-4 w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500">
                <th className="pb-2 font-medium">Hostname</th>
                <th className="pb-2 font-medium">Criticality</th>
                <th className="pb-2 font-medium">Open</th>
                <th className="pb-2 font-medium">Top Score</th>
              </tr>
            </thead>
            <tbody>
              {summary.top_risky_assets.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-4 text-slate-400">No scored assets yet.</td>
                </tr>
              )}
              {summary.top_risky_assets.map((asset) => (
                <tr key={asset.hostname} className="border-t border-slate-100">
                  <td className="py-2 font-medium text-slate-900">{asset.hostname}</td>
                  <td className="py-2 capitalize text-slate-600">{asset.criticality}</td>
                  <td className="py-2 text-slate-600">{asset.open_vulnerability_count}</td>
                  <td className="py-2 font-semibold text-slate-900">{asset.highest_risk_score ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
