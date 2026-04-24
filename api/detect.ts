// Vercel Edge Function: /api/detect
// Accepts { url, platform } → fetches via r.jina.ai → sends to OpenRouter → returns structured risk report.
// Env required in Vercel dashboard: OPENROUTER_API_KEY (required), OPENROUTER_MODEL (default: anthropic/claude-3.5-sonnet),
// JINA_READER_URL (default: https://r.jina.ai), APP_PUBLIC_URL, APP_NAME.

export const config = { runtime: "edge" };

const ANALYSIS_SYSTEM = `You are a senior cybersecurity analyst specializing in detecting fake profiles and cyberstalkers on social media. Given raw public content extracted from a profile page, return ONLY a valid JSON object (no markdown, no prose outside JSON) with this exact schema:
{
  "risk_score": <integer 0-100>,
  "classification": "Safe" | "Medium Risk" | "High Risk",
  "summary": "<2-4 sentence expert analysis ending with one actionable recommendation>",
  "red_flags": [{"label": "<short>", "score": <int 5-30>, "description": "<1 sentence>"}],
  "toxic_terms": ["<term1>"],
  "suspicious_snippets": ["<short excerpt>"]
}
Thresholds: <35=Safe, 35-64=Medium Risk, >=65=High Risk. Keep red_flags between 0 and 8. If content is thin or the page failed to load, assume unknown and score around 40 with a red_flag 'Insufficient data'.`;

const JSON_HEADERS = { "Content-Type": "application/json" };

function extractUsername(url) {
  try {
    const clean = url.trim().replace(/\/+$/, "");
    const parts = clean.split("/");
    let candidate = parts[parts.length - 1] || parts[parts.length - 2] || "profile";
    candidate = candidate.split("?")[0];
    candidate = candidate.replace(/[^a-zA-Z0-9._-]/g, "");
    return candidate.slice(0, 80) || "profile";
  } catch {
    return "profile";
  }
}

function classify(score) {
  if (score >= 65) return "High Risk";
  if (score >= 35) return "Medium Risk";
  return "Safe";
}

async function fetchJina(profileUrl) {
  const base = process.env.JINA_READER_URL || "https://r.jina.ai";
  const appName = process.env.APP_NAME || "CyberShield";
  const res = await fetch(`${base}/${profileUrl}`, {
    headers: { Accept: "text/plain", "User-Agent": `${appName}/1.0` },
  });
  if (!res.ok) throw new Error(`Jina reader failed (${res.status})`);
  const txt = await res.text();
  return txt.slice(0, 8000);
}

async function callOpenRouter(profileUrl, platform, content) {
  const key = process.env.OPENROUTER_API_KEY;
  if (!key) throw new Error("OPENROUTER_API_KEY not configured");
  const model = process.env.OPENROUTER_MODEL || "anthropic/claude-3.5-sonnet";
  const referer = process.env.APP_PUBLIC_URL || "http://localhost";
  const title = process.env.APP_NAME || "CyberShield";

  const body = {
    model,
    messages: [
      { role: "system", content: ANALYSIS_SYSTEM },
      {
        role: "user",
        content: `Profile URL: ${profileUrl}\nPlatform: ${platform}\n\nPublic content extracted via Jina Reader (may be partial):\n---\n${content}\n---\n\nReturn the JSON object now.`,
      },
    ],
    temperature: 0.2,
    max_tokens: 900,
    response_format: { type: "json_object" },
  };

  const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      "HTTP-Referer": referer,
      "X-Title": title,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errTxt = await res.text();
    throw new Error(`OpenRouter error (${res.status}): ${errTxt.slice(0, 200)}`);
  }
  const data = await res.json();
  const raw = data?.choices?.[0]?.message?.content ?? "{}";
  return JSON.parse(raw);
}

export default async function handler(req) {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ detail: "Method not allowed" }), {
      status: 405,
      headers: JSON_HEADERS,
    });
  }

  try {
    const { url, platform = "instagram" } = await req.json();
    if (!url || typeof url !== "string" || !/^https?:\/\//i.test(url)) {
      return new Response(JSON.stringify({ detail: "Valid http(s) URL required" }), {
        status: 400,
        headers: JSON_HEADERS,
      });
    }

    const content = await fetchJina(url);
    const ai = await callOpenRouter(url, platform, content);

    const score = Math.max(0, Math.min(100, Number(ai.risk_score ?? 40)));
    const cls = ai.classification || classify(score);
    const summary = String(ai.summary || "").trim() || "Analysis unavailable.";
    const factors = (Array.isArray(ai.red_flags) ? ai.red_flags : [])
      .slice(0, 8)
      .map((f) => ({
        label: String(f.label ?? "Signal").slice(0, 60),
        score: Number(f.score ?? 10),
        description: String(f.description ?? "").slice(0, 200),
      }));
    const toxic_flags = (Array.isArray(ai.toxic_terms) ? ai.toxic_terms : [])
      .slice(0, 10)
      .map((t) => String(t).slice(0, 40));
    const repeated_messages = (Array.isArray(ai.suspicious_snippets) ? ai.suspicious_snippets : [])
      .slice(0, 10)
      .map((s) => String(s).slice(0, 120));

    let alert = null;
    if (cls === "High Risk") {
      alert = "High risk — this profile may be fake or a cyberstalker. Block and report.";
    } else if (cls === "Medium Risk") {
      alert = "Caution — suspicious patterns detected. Review interactions carefully.";
    }

    const body = {
      id: crypto.randomUUID(),
      user_id: "edge",
      username: extractUsername(url),
      platform,
      profile_url: url,
      risk_score: score,
      classification: cls,
      factors,
      toxic_flags,
      repeated_messages,
      ai_insight: summary,
      alert,
      created_at: new Date().toISOString(),
    };

    return new Response(JSON.stringify(body), { status: 200, headers: JSON_HEADERS });
  } catch (err) {
    return new Response(JSON.stringify({ detail: err?.message || "Internal error" }), {
      status: 500,
      headers: JSON_HEADERS,
    });
  }
}
