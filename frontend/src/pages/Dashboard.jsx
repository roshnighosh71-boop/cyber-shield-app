import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Layout } from "../components/Layout";
import { RiskGauge } from "../components/RiskGauge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Textarea } from "../components/ui/textarea";
import { Switch } from "../components/ui/switch";
import { Badge } from "../components/ui/badge";
import { Alert, AlertDescription } from "../components/ui/alert";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "../components/ui/select";
import { AlertTriangle, CheckCircle2, ShieldAlert, Sparkles } from "lucide-react";
import { toast } from "sonner";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
} from "recharts";

const defaultForm = {
  username: "",
  platform: "instagram",
  profile_url: "",
  account_age_days: 365,
  followers: 100,
  following: 150,
  posts_count: 20,
  has_profile_picture: true,
  has_bio: true,
  is_verified: false,
  posting_frequency_per_day: 1,
  messages: "",
};

const SAMPLE_SUSPICIOUS = {
  username: "s3cretAdmirer_xx",
  platform: "instagram",
  profile_url: "https://instagram.com/s3cretAdmirer_xx",
  account_age_days: 7,
  followers: 2,
  following: 980,
  posts_count: 0,
  has_profile_picture: false,
  has_bio: false,
  is_verified: false,
  posting_frequency_per_day: 60,
  messages:
    "hey beautiful\nhey beautiful\nhey beautiful\ni know where you live\ndm me\ncheck my bio link\ni'll find you",
};

export default function Dashboard() {
  const [form, setForm] = useState(defaultForm);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);

  const loadStats = async () => {
    try {
      const r = await api.get("/scans/stats");
      setStats(r.data);
    } catch {}
  };

  useEffect(() => {
    loadStats();
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setScanning(true);
    setResult(null);
    try {
      const r = await api.post("/scan", form);
      setResult(r.data);
      toast.success(`Scan complete — ${r.data.classification}`);
      loadStats();
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const cls = result?.classification;
  const clsColor =
    cls === "High Risk"
      ? "text-rose-400 border-rose-500/40 bg-rose-500/10"
      : cls === "Medium Risk"
      ? "text-amber-400 border-amber-400/40 bg-amber-400/10"
      : "text-emerald-400 border-emerald-400/40 bg-emerald-400/10";

  const statsCards = [
    { label: "Total scans", value: stats?.total ?? 0, color: "text-cyan-400", testid: "stat-total" },
    { label: "Safe", value: stats?.safe ?? 0, color: "text-emerald-400", testid: "stat-safe" },
    { label: "Medium", value: stats?.medium ?? 0, color: "text-amber-400", testid: "stat-medium" },
    { label: "High risk", value: stats?.high ?? 0, color: "text-rose-400", testid: "stat-high" },
  ];

  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-6 py-8" data-testid="dashboard-page">
        {/* Header */}
        <div className="flex items-start justify-between mb-6 flex-wrap gap-4">
          <div>
            <div className="text-[10px] uppercase tracking-[0.3em] text-cyan-400 mb-2 flex items-center gap-2">
              <span className="relative inline-block h-1.5 w-1.5 rounded-full bg-cyan-400 pulse-dot" />
              THREAT SCANNER · LIVE
            </div>
            <h1 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
              Profile risk analysis
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Enter profile signals — hybrid rules + Claude Sonnet analysis produce a 0–100 score.
            </p>
          </div>
          <Button
            variant="outline"
            className="border-slate-700 bg-transparent hover:bg-slate-900 rounded-sm"
            onClick={() => setForm(SAMPLE_SUSPICIOUS)}
            data-testid="load-sample-btn"
          >
            <Sparkles className="h-3.5 w-3.5 mr-2" /> Load suspicious sample
          </Button>
        </div>

        {/* Stats strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          {statsCards.map((s) => (
            <div
              key={s.label}
              className="bg-slate-900 border border-slate-800 p-4 rounded-sm"
              data-testid={s.testid}
            >
              <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">{s.label}</div>
              <div className={`font-display text-3xl font-bold mt-1 ${s.color}`}>{s.value}</div>
            </div>
          ))}
        </div>

        <div className="grid lg:grid-cols-5 gap-4">
          {/* Form */}
          <form
            onSubmit={submit}
            className="lg:col-span-2 bg-slate-900 border border-slate-800 p-6 rounded-sm space-y-5"
            data-testid="scan-form"
          >
            <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500 border-b border-slate-800 pb-3">
              Profile signals
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label className="text-xs text-slate-400 uppercase tracking-widest">Username</Label>
                <Input
                  required
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  className="bg-slate-950 border-slate-800 focus:border-cyan-500 font-mono-custom rounded-sm"
                  placeholder="@handle"
                  data-testid="scan-username-input"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs text-slate-400 uppercase tracking-widest">Platform</Label>
                <Select
                  value={form.platform}
                  onValueChange={(v) => setForm({ ...form, platform: v })}
                >
                  <SelectTrigger className="bg-slate-950 border-slate-800 font-mono-custom rounded-sm" data-testid="scan-platform-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-800">
                    {["instagram", "twitter", "facebook", "tiktok", "linkedin", "generic"].map(
                      (p) => (
                        <SelectItem key={p} value={p} className="font-mono-custom">
                          {p}
                        </SelectItem>
                      )
                    )}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-xs text-slate-400 uppercase tracking-widest">Profile URL (optional)</Label>
              <Input
                value={form.profile_url}
                onChange={(e) => setForm({ ...form, profile_url: e.target.value })}
                className="bg-slate-950 border-slate-800 focus:border-cyan-500 font-mono-custom rounded-sm"
                placeholder="https://..."
                data-testid="scan-url-input"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              {[
                ["account_age_days", "Account age (days)"],
                ["followers", "Followers"],
                ["following", "Following"],
                ["posts_count", "Posts"],
                ["posting_frequency_per_day", "Posts / day"],
              ].map(([key, label]) => (
                <div className="space-y-2" key={key}>
                  <Label className="text-xs text-slate-400 uppercase tracking-widest">{label}</Label>
                  <Input
                    type="number"
                    step={key === "posting_frequency_per_day" ? "0.1" : "1"}
                    min="0"
                    required
                    value={form[key]}
                    onChange={(e) => setForm({ ...form, [key]: Number(e.target.value) })}
                    className="bg-slate-950 border-slate-800 focus:border-cyan-500 font-mono-custom rounded-sm"
                    data-testid={`scan-${key}-input`}
                  />
                </div>
              ))}
            </div>

            <div className="grid grid-cols-3 gap-3 pt-2">
              {[
                ["has_profile_picture", "Has picture"],
                ["has_bio", "Has bio"],
                ["is_verified", "Verified"],
              ].map(([key, label]) => (
                <div
                  key={key}
                  className="flex items-center justify-between bg-slate-950 border border-slate-800 px-3 py-2 rounded-sm"
                >
                  <span className="text-xs text-slate-400 uppercase tracking-wider">{label}</span>
                  <Switch
                    checked={form[key]}
                    onCheckedChange={(v) => setForm({ ...form, [key]: v })}
                    data-testid={`scan-${key}-switch`}
                  />
                </div>
              ))}
            </div>

            <div className="space-y-2">
              <Label className="text-xs text-slate-400 uppercase tracking-widest">
                Sample messages (one per line)
              </Label>
              <Textarea
                rows={5}
                value={form.messages}
                onChange={(e) => setForm({ ...form, messages: e.target.value })}
                placeholder={"hey beautiful\ndm me\ncheck my bio link"}
                className="bg-slate-950 border-slate-800 focus:border-cyan-500 font-mono-custom rounded-sm resize-none"
                data-testid="scan-messages-textarea"
              />
            </div>

            <Button
              type="submit"
              disabled={scanning}
              className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-sm"
              data-testid="scan-submit-btn"
            >
              {scanning ? "Analyzing…" : "Run threat scan"}
            </Button>
          </form>

          {/* Results */}
          <div className="lg:col-span-3 space-y-4">
            {!result ? (
              <div className="bg-slate-900 border border-dashed border-slate-800 p-10 rounded-sm text-center" data-testid="no-result-placeholder">
                <ShieldAlert className="h-8 w-8 text-slate-600 mx-auto mb-4" />
                <div className="text-sm text-slate-400">
                  Fill the form and run a scan to see the risk report here.
                </div>
              </div>
            ) : (
              <>
                {result.alert && (
                  <Alert
                    className={`border ${clsColor} rounded-sm`}
                    data-testid="result-alert"
                  >
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription className="font-mono-custom text-sm">
                      {result.alert}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="grid md:grid-cols-2 gap-4">
                  <div className="bg-slate-900 border border-slate-800 rounded-sm p-6">
                    <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500 mb-2">
                      Risk score
                    </div>
                    <RiskGauge score={result.risk_score} classification={result.classification} />
                    <div className="mt-4 text-xs text-slate-500 font-mono-custom">
                      Target: <span className="text-white">@{result.username}</span> ·{" "}
                      {result.platform}
                    </div>
                  </div>

                  <div className="bg-slate-900 border border-slate-800 rounded-sm p-6">
                    <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500 mb-4">
                      Contribution breakdown
                    </div>
                    {result.factors.length === 0 ? (
                      <div className="flex items-center gap-2 text-emerald-400 text-sm mt-8">
                        <CheckCircle2 className="h-4 w-4" />
                        No risk factors detected.
                      </div>
                    ) : (
                      <div className="h-56" data-testid="factors-chart">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart
                            data={result.factors.map((f) => ({
                              name: f.label,
                              score: f.score,
                            }))}
                            layout="vertical"
                            margin={{ left: 10, right: 20 }}
                          >
                            <XAxis type="number" stroke="#475569" fontSize={10} />
                            <YAxis
                              dataKey="name"
                              type="category"
                              stroke="#94a3b8"
                              fontSize={10}
                              width={130}
                            />
                            <Tooltip
                              contentStyle={{
                                background: "#0f172a",
                                border: "1px solid #1e293b",
                                fontSize: 12,
                              }}
                              cursor={{ fill: "rgba(6,182,212,0.08)" }}
                            />
                            <Bar dataKey="score" radius={0}>
                              {result.factors.map((f, i) => (
                                <Cell
                                  key={i}
                                  fill={f.score < 0 ? "#34d399" : f.score >= 20 ? "#f43f5e" : "#fbbf24"}
                                />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    )}
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-sm p-6">
                  <div className="text-[10px] uppercase tracking-[0.2em] text-cyan-400 mb-3 flex items-center gap-2">
                    <Sparkles className="h-3 w-3" /> AI INSIGHT — Claude Sonnet 4.5
                  </div>
                  <p className="text-sm text-slate-200 leading-relaxed" data-testid="ai-insight-text">
                    {result.ai_insight}
                  </p>
                </div>

                {(result.toxic_flags.length > 0 || result.repeated_messages.length > 0) && (
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="bg-slate-900 border border-slate-800 rounded-sm p-6">
                      <div className="text-[10px] uppercase tracking-[0.2em] text-rose-400 mb-3">
                        Toxic / threatening terms
                      </div>
                      {result.toxic_flags.length ? (
                        <div className="flex flex-wrap gap-2" data-testid="toxic-flags">
                          {result.toxic_flags.map((t) => (
                            <Badge
                              key={t}
                              className="bg-rose-500/10 text-rose-300 border border-rose-500/30 rounded-sm font-mono-custom"
                            >
                              {t}
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <div className="text-sm text-slate-500">None detected.</div>
                      )}
                    </div>
                    <div className="bg-slate-900 border border-slate-800 rounded-sm p-6">
                      <div className="text-[10px] uppercase tracking-[0.2em] text-amber-400 mb-3">
                        Repeated messages
                      </div>
                      {result.repeated_messages.length ? (
                        <ul className="space-y-1.5 font-mono-custom text-sm text-slate-300" data-testid="repeated-messages">
                          {result.repeated_messages.map((m, i) => (
                            <li key={i} className="truncate border-l-2 border-amber-400/50 pl-3">
                              {m}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <div className="text-sm text-slate-500">None detected.</div>
                      )}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
