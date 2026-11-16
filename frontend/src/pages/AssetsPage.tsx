import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Asset } from "@/types";

const CRITICALITY_OPTIONS = ["critical", "high", "medium", "low"] as const;

export function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [criticalityFilter, setCriticalityFilter] = useState<string>("");
  const [search, setSearch] = useState("");

  function loadAssets() {
    setLoading(true);
    api
      .get<Asset[]>("/assets", { params: { criticality: criticalityFilter || undefined, search: search || undefined } })
      .then((res) => setAssets(res.data))
      .finally(() => setLoading(false));
  }

  useEffect(loadAssets, [criticalityFilter]);

  async function handleCriticalityChange(assetId: string, criticality: string) {
    await api.patch(`/assets/${assetId}`, { criticality });
    loadAssets();
  }

  return (
    <div className="p-8">
      <h2 className="text-2xl font-bold text-slate-900">Asset Inventory</h2>
      <p className="text-sm text-slate-500">
        Editing criticality or exposure here directly changes an asset's vulnerabilities' risk scores on the next recalculation.
      </p>

      <div className="mt-4 flex gap-3">
        <input
          placeholder="Search hostname..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && loadAssets()}
          className="w-64 rounded-md border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-500 focus:outline-none"
        />
        <select
          value={criticalityFilter}
          onChange={(e) => setCriticalityFilter(e.target.value)}
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-500 focus:outline-none"
        >
          <option value="">All criticalities</option>
          {CRITICALITY_OPTIONS.map((c) => (
            <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>
          ))}
        </select>
      </div>

      <div className="mt-4 overflow-hidden rounded-lg border border-slate-200 bg-white">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading...</div>
        ) : assets.length === 0 ? (
          <div className="p-8 text-center text-slate-500">No assets found.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-500">
              <tr>
                <th className="px-5 py-3 font-medium">Hostname</th>
                <th className="px-5 py-3 font-medium">IP Address</th>
                <th className="px-5 py-3 font-medium">Criticality</th>
                <th className="px-5 py-3 font-medium">Internet-Facing</th>
                <th className="px-5 py-3 font-medium">Open Findings</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => (
                <tr key={asset.id} className="border-t border-slate-100">
                  <td className="px-5 py-3 font-medium text-slate-900">{asset.hostname}</td>
                  <td className="px-5 py-3 text-slate-600">{asset.ip_address ?? "—"}</td>
                  <td className="px-5 py-3">
                    <select
                      value={asset.criticality}
                      onChange={(e) => handleCriticalityChange(asset.id, e.target.value)}
                      className="rounded-md border border-slate-300 px-2 py-1 text-xs focus:border-slate-500 focus:outline-none"
                    >
                      {CRITICALITY_OPTIONS.map((c) => (
                        <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-5 py-3">
                    {asset.internet_facing ? (
                      <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800">Yes</span>
                    ) : (
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">No</span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-slate-600">{asset.open_vulnerability_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
