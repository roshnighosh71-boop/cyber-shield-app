import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Trash2, Inbox } from "lucide-react";
import { toast } from "sonner";
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid,
} from "recharts";

export default function History() {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const [s, st] = await Promise.all([api.get("/scans"), api.get("/scans/stats")]);
      setScans(s.data);
      setStats(st.data);
      if (s.data.length && !selected) setSelected(s.data[0]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []); // eslint-disable-line

  const del = async (id) => {
    try {
      await api.delete(`/scans/${id}`);
      toast.success("Scan deleted");
      setSelected(null);
      load();
    } catch {
      toast.error("Delete failed");
    }
  };

  const badge = (cls) =>
    cls === "High Risk"
      ? "bg-rose-500/10 text-rose-300 border-rose-500/30"
      : cls === "Medium Risk"
      ? "bg-amber-400/10 text-amber-300 border-amber-400/30"
      : "bg-emerald-400/10 text-emerald-300 border-emerald-400/30";

  const trendData = (stats?.trend || []).map((t) => ({
    time: new Date(t.created_at).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    score: t.risk_score,
  }));

  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-6 py-8" data-testid="history-page">
        <div className="mb-6">
          <div className="text-[10px] uppercase tracking-[0.3em] text-cyan-400 mb-2">ARCHIVE</div>
          <h1 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">Scan history</h1>
          <p className="text-sm text-slate-400 mt-1">All prior threat assessments for your account.</p>
        </div>

        {stats && stats.total > 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-sm p-6 mb-6">
            <div className="flex items-center justify-between mb-3">
              <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                Score trend (last 10)
              </div>
              <div className="text-xs text-slate-400 font-mono-custom">
                avg: <span className="text-cyan-400">{stats.avg_score}</span>
              </div>
            </div>
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData} margin={{ left: -10, right: 10 }}>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} />
                  <YAxis stroke="#475569" fontSize={10} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", fontSize: 12 }}
                  />
                  <Line type="monotone" dataKey="score" stroke="#06b6d4" strokeWidth={2} dot={{ fill: "#06b6d4", r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {loading ? (
          <div className="text-sm text-slate-500">Loading…</div>
        ) : scans.length === 0 ? (
          <div className="bg-slate-900 border border-dashed border-slate-800 p-12 rounded-sm text-center">
            <Inbox className="h-8 w-8 text-slate-600 mx-auto mb-3" />
            <div className="text-sm text-slate-400">No scans yet — run your first analysis on the Scanner tab.</div>
          </div>
        ) : (
          <div className="grid lg:grid-cols-5 gap-4">
            <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-sm overflow-hidden">
              <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500 px-4 py-3 border-b border-slate-800">
                {scans.length} scans
              </div>
              <ul className="divide-y divide-slate-800 max-h-[70vh] overflow-y-auto" data-testid="scan-list">
                {scans.map((s) => (
                  <li key={s.id}>
                    <button
                      onClick={() => setSelected(s)}
                      className={`w-full text-left px-4 py-3 hover:bg-slate-800/60 transition-colors ${
                        selected?.id === s.id ? "bg-slate-800/80 border-l-2 border-cyan-400" : ""
                      }`}
                      data-testid={`scan-item-${s.id}`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="font-mono-custom text-sm text-white truncate">
                            @{s.username}
                          </div>
                          <div className="text-xs text-slate-500 truncate">
                            {s.platform} · {new Date(s.created_at).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="font-display font-bold text-lg text-white">
                            {s.risk_score}
                          </span>
                          <Badge className={`border rounded-sm text-[10px] ${badge(s.classification)}`}>
                            {s.classification}
                          </Badge>
                        </div>
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            </div>

            <div className="lg:col-span-3">
              {selected ? (
                <div className="bg-slate-900 border border-slate-800 rounded-sm p-6 space-y-5" data-testid="scan-detail">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.25em] text-cyan-400 mb-1">
                        Scan detail
                      </div>
                      <h2 className="font-display text-2xl font-bold">@{selected.username}</h2>
                      <div className="text-xs text-slate-500 font-mono-custom">
                        {selected.platform} ·{" "}
                        {new Date(selected.created_at).toLocaleString()}
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="border-rose-500/40 text-rose-300 hover:bg-rose-500/10 bg-transparent rounded-sm"
                      onClick={() => del(selected.id)}
                      data-testid="delete-scan-btn"
                    >
                      <Trash2 className="h-3.5 w-3.5 mr-2" /> Delete
                    </Button>
                  </div>

                  <div className="flex items-center gap-6 border-y border-slate-800 py-4">
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Score</div>
                      <div className="font-display text-4xl font-bold text-white">{selected.risk_score}</div>
                    </div>
                    <Badge className={`border rounded-sm ${badge(selected.classification)}`}>
                      {selected.classification}
                    </Badge>
                  </div>

                  {selected.alert && (
                    <div className={`text-sm p-3 rounded-sm border ${badge(selected.classification)} font-mono-custom`}>
                      {selected.alert}
                    </div>
                  )}

                  <div>
                    <div className="text-[10px] uppercase tracking-[0.2em] text-cyan-400 mb-2">AI insight</div>
                    <p className="text-sm text-slate-300 leading-relaxed">{selected.ai_insight}</p>
                  </div>

                  <div>
                    <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500 mb-2">Factors</div>
                    {selected.factors.length === 0 ? (
                      <div className="text-sm text-slate-500">None.</div>
                    ) : (
                      <ul className="space-y-1.5 text-sm">
                        {selected.factors.map((f, i) => (
                          <li key={i} className="flex items-center justify-between border-b border-slate-800 py-1.5">
                            <span className="text-slate-200">{f.label}</span>
                            <span className={`font-mono-custom ${f.score < 0 ? "text-emerald-400" : f.score >= 20 ? "text-rose-400" : "text-amber-400"}`}>
                              {f.score > 0 ? "+" : ""}
                              {f.score}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              ) : (
                <div className="bg-slate-900 border border-dashed border-slate-800 p-10 rounded-sm text-center text-sm text-slate-500">
                  Select a scan to view its full report.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
