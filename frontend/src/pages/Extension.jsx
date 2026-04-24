import { useState } from "react";
import { Layout } from "../components/Layout";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Shield, Radar, X } from "lucide-react";
import { api } from "../lib/api";
import { toast } from "sonner";

export default function Extension() {
  const [url, setUrl] = useState("https://instagram.com/");
  const [platform, setPlatform] = useState("instagram");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);

  const handleUrl = (v) => {
    setUrl(v);
    if (/twitter\.com|x\.com/i.test(v)) setPlatform("twitter");
    else if (/facebook\.com|fb\.com/i.test(v)) setPlatform("facebook");
    else if (/instagram\.com/i.test(v)) setPlatform("instagram");
  };

  const mockScan = async () => {
    if (!/^https?:\/\//i.test(url)) {
      toast.error("Enter a full URL starting with https://");
      return;
    }
    setScanning(true);
    setResult(null);
    try {
      const r = await api.post("/detect", { url, platform });
      setResult(r.data);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const classColor =
    result?.classification === "High Risk"
      ? "text-rose-400 bg-rose-500/10 border-rose-500/40"
      : result?.classification === "Medium Risk"
      ? "text-amber-400 bg-amber-400/10 border-amber-400/40"
      : "text-emerald-400 bg-emerald-400/10 border-emerald-400/40";

  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-6 py-8" data-testid="extension-page">
        <div className="mb-8">
          <div className="text-[10px] uppercase tracking-[0.3em] text-cyan-400 mb-2">
            MOCK · BROWSER EXTENSION
          </div>
          <h1 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            Real-time scanning preview
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Simulated browser extension that scans any profile URL as you browse.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-6 items-start">
          <div className="bg-slate-900 border border-slate-800 rounded-sm overflow-hidden">
            <div className="bg-slate-800 px-4 py-2.5 flex items-center gap-2 border-b border-slate-700">
              <div className="flex gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-500" />
                <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
              </div>
              <div className="flex-1 bg-slate-950 border border-slate-700 rounded-sm px-3 py-1 flex items-center gap-2 mx-4">
                <Shield className="h-3 w-3 text-cyan-400" />
                <Input
                  value={url}
                  onChange={(e) => handleUrl(e.target.value)}
                  className="bg-transparent border-0 h-6 p-0 text-xs font-mono-custom focus-visible:ring-0"
                  data-testid="extension-url-input"
                />
              </div>
              <Button
                size="sm"
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-sm h-7 text-xs"
                onClick={mockScan}
                disabled={scanning}
                data-testid="extension-scan-btn"
              >
                <Radar className="h-3 w-3 mr-1" /> {scanning ? "Scanning" : "Scan"}
              </Button>
            </div>
            <div className="p-6 min-h-[320px] bg-slate-950 relative cyber-grid">
              <div className="text-xs text-slate-500 mb-3 font-mono-custom">GET {url}</div>
              {!result && !scanning && (
                <div className="text-sm text-slate-500">
                  Click <span className="text-cyan-400">Scan</span> to simulate a real-time analysis as
                  this page loads.
                </div>
              )}
              {scanning && (
                <div className="text-sm text-cyan-400 font-mono-custom flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  Inspecting profile signals…
                </div>
              )}
            </div>
          </div>

          <div className="relative">
            <div className="absolute -top-3 -left-3 bg-slate-900 border border-cyan-500/30 text-[10px] uppercase tracking-[0.25em] text-cyan-400 px-2 py-1 rounded-sm">
              Extension popup
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-sm p-5 glow-border" data-testid="extension-popup">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-cyan-400" />
                  <span className="font-display font-bold text-sm">CyberShield</span>
                </div>
                <X className="h-4 w-4 text-slate-600" />
              </div>

              {!result ? (
                <div className="py-12 text-center text-sm text-slate-500">
                  No scan run yet. Trigger one from the browser mockup.
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-1">Target</div>
                    <div className="font-mono-custom text-sm text-white">@{result.username}</div>
                  </div>
                  <div className={`border ${classColor} rounded-sm p-4`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] uppercase tracking-[0.25em] opacity-80">Verdict</span>
                      <span className="font-display font-bold text-2xl">{result.risk_score}</span>
                    </div>
                    <div className="font-display font-bold text-lg" data-testid="extension-verdict">
                      {result.classification}
                    </div>
                    {result.alert && (
                      <div className="text-xs mt-2 opacity-90">{result.alert}</div>
                    )}
                  </div>

                  <div>
                    <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-2">Top red flags</div>
                    <ul className="space-y-1.5 text-xs font-mono-custom">
                      {result.factors.slice(0, 5).map((f, i) => (
                        <li key={i} className="flex justify-between border-b border-slate-800 py-1">
                          <span className="text-slate-300 truncate pr-2">{f.label}</span>
                          <span className={f.score >= 20 ? "text-rose-400" : f.score >= 10 ? "text-amber-400" : "text-cyan-400"}>
                            +{f.score}
                          </span>
                        </li>
                      ))}
                      {result.factors.length === 0 && (
                        <li className="text-emerald-400">Clean — no red flags.</li>
                      )}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
