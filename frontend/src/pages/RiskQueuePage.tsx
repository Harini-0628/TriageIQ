import { Fragment, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { RankedVulnerability } from "@/types";

function scoreTone(score: number): string {
  if (score >= 70) return "bg-red-100 text-red-800";
  if (score >= 40) return "bg-amber-100 text-amber-800";
  return "bg-slate-100 text-slate-700";
}

export function RiskQueuePage() {
  const [queue, setQueue] = useState<RankedVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [recalculating, setRecalculating] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  function loadQueue() {
    setLoading(true);
    api
      .get<RankedVulnerability[]>("/risk/queue", { params: { limit: 50 } })
      .then((res) => setQueue(res.data))
      .finally(() => setLoading(false));
  }

  useEffect(loadQueue, []);

  async function handleRecalculate() {
    setRecalculating(true);
    try {
      await api.post("/risk/recalculate");
      loadQueue();
    } finally {
      setRecalculating(false);
    }
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-900">Risk Queue</h2>
          <p className="text-sm text-slate-500">Prioritized by composite risk score — highest risk first, not raw CVSS.</p>
        </div>
        <button
          onClick={handleRecalculate}
          disabled={recalculating}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
        >
          {recalculating ? "Recalculating..." : "Recalculate Risk"}
        </button>
      </div>

      <div className="mt-6 overflow-hidden rounded-lg border border-slate-200 bg-white">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading...</div>
        ) : queue.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            No open, scored vulnerabilities yet. Upload a scan and run a risk recalculation.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-500">
              <tr>
                <th className="px-5 py-3 font-medium">Finding</th>
                <th className="px-5 py-3 font-medium">Asset</th>
                <th className="px-5 py-3 font-medium">CVE</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {queue.map((v) => (
                <Fragment key={v.vulnerability_id}>
                  <tr
                    onClick={() => setExpandedId(expandedId === v.vulnerability_id ? null : v.vulnerability_id)}
                    className="cursor-pointer border-t border-slate-100 hover:bg-slate-50"
                  >
                    <td className="px-5 py-3 font-medium text-slate-900">{v.title}</td>
                    <td className="px-5 py-3 text-slate-600">{v.asset_hostname}</td>
                    <td className="px-5 py-3 text-slate-600">{v.cve_id ?? "—"}</td>
                    <td className="px-5 py-3 capitalize text-slate-600">{v.status.replace("_", " ")}</td>
                    <td className="px-5 py-3">
                      <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${scoreTone(v.composite_score)}`}>
                        {v.composite_score}
                      </span>
                    </td>
                  </tr>
                  {expandedId === v.vulnerability_id && (
                    <tr className="border-t border-slate-100 bg-slate-50">
                      <td colSpan={5} className="px-5 py-4">
                        <p className="mb-2 text-xs font-semibold uppercase text-slate-500">Score breakdown</p>
                        <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
                          <ScoreComponent label="CVSS" value={v.cvss_component} max={30} />
                          <ScoreComponent label="EPSS" value={v.epss_component} max={25} />
                          <ScoreComponent label="KEV" value={v.kev_component} max={20} />
                          <ScoreComponent label="Asset Crit." value={v.asset_criticality_component} max={15} />
                          <ScoreComponent label="Exposure" value={v.exposure_component} max={5} />
                          <ScoreComponent label="Age" value={v.age_component} max={5} />
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function ScoreComponent({ label, value, max }: { label: string; value: number; max: number }) {
  return (
    <div className="rounded-md border border-slate-200 bg-white p-3 text-center">
      <p className="text-xs text-slate-500">{label}</p>
      <p className="text-sm font-semibold text-slate-900">
        {value}<span className="text-slate-400">/{max}</span>
      </p>
    </div>
  );
}
