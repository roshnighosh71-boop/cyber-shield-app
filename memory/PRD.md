# CyberShield — AI Fake Profile & Cyberstalker Detection

## Problem
Build a working prototype detecting fake profiles and cyberstalkers via hybrid rule-based + AI analysis. Dashboard, risk score 0-100, classification (Safe / Medium / High), toxic-language & repeated-message NLP, real-time alerts, history, mock browser extension.

## Architecture
- **Backend**: FastAPI + MongoDB (Motor async). JWT auth (bcrypt). Emergentintegrations → Claude Sonnet 4.5 for NLP insights.
- **Frontend**: React + React Router + Tailwind + Shadcn UI + Recharts + Sonner toasts. Dark slate-950 + cyan cybersecurity aesthetic.
- **Routes**: `/`, `/login`, `/register`, `/dashboard` (scanner + live results), `/history` (archive + trend chart), `/extension` (mock browser extension popup).

## Core Requirements (static)
- Manual profile entry form (username, platform, URL, age, followers, following, posts, posts/day, picture/bio/verified flags, sample messages)
- Hybrid scoring: 12+ rule heuristics + Claude Sonnet 4.5 insight
- Threat banner / alert simulation for Medium+High
- Persisted scan history per user
- Data-viz: gauge, contribution bar chart, trend line chart
- Mock browser extension UI preview

## Implemented (2026-02)
- JWT auth: register/login/me
- `POST /api/scan`: rule engine + Claude Sonnet 4.5 AI insight
- `GET /api/scans`, `GET /api/scans/stats`, `DELETE /api/scans/{id}`
- Full dashboard UI with risk gauge, factor chart, toxic-flag & repeated-message panels, AI insight card
- History page with list + detail + trend chart + delete
- Browser-extension mock popup with simulated real-time scan
- Landing page with hero, features, CTAs

## Testing
- Backend: 100% pass (14 pytest cases) — iteration_1.json
- Credentials: `/app/memory/test_credentials.md`

## Backlog (P1)
- Unique index on `users.email` (race-condition safety)
- Store `created_at` as BSON datetime for stats consistency
- Rate limit on `/api/scan` (LLM cost)
- Per-platform heuristic weights (IG vs Twitter vs LinkedIn)

## Backlog (P2)
- Bulk scan via CSV upload
- Shareable scan report (read-only link)
- Chrome extension bundled build (manifest v3)
- Email/webhook alert for High Risk scans
- PDF export of report
