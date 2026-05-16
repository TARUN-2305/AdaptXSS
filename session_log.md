# AdaptXSS Session Log

This file tracks the progress, decisions, and current state of the AdaptXSS project for all agents to collaborate and any agent continuing the project can pick up from where work was left off.

---

## Project Goal
Implement the Adaptive DOM-Based XSS Detection (AdaptXSS) system per `AdaptXSS_Action_Plan.md`.

**Tech Stack:** Vanilla JS (core) · React 18 + Vite (dashboard) · Node.js + Express (backend) · PHP 8 (fallback) · Python 3 + Django (admin) · scikit-learn (evaluation)

---

## Completed Phases

### ✅ Repository Structure
- Git initialized at project root.
- All folders created: `core/`, `backend/`, `dashboard/`, `php-receiver/`, `evaluation/`, `paper/`.

### ✅ Phase 0 — Research Baseline
- Mock datasets created: `evaluation/datasets/xss_payloads.txt`, `benign_strings.txt`, `xss_payloads.csv`.
- `evaluation/datasets/README.md` documents data sources.

### ✅ Phase 1 — Core JS Library (`core/`)
- `core/src/extractor.js` — 8-feature extractor (tag risk, attr delta, script flag, handler flag, URL anomaly, data URI, depth, entropy).
- `core/src/classifier.js` — Online Bernoulli Naive Bayes with Laplace smoothing + localStorage persistence + seed model fallback.
- `core/src/observer.js` — MutationObserver wrapper, attaches to DOM, runs extractor→classifier, fires onAlert callback.
- `core/src/reporter.js` — fetch-based Ajax reporter with exponential backoff retry.
- `core/src/index.js` — public re-exports.
- `core/package.json` — esbuild bundler, Jest tests.
- **All 10 tests pass** (`npm test` in `core/`).
- Build: `dist/adaptxss.min.js` = **4.69 KB** ✅ (under 10 KB limit).

### ✅ Phase 2 — Seed Training Data
- `core/scripts/pretrain.js` — reads xss_payloads.txt + benign_strings.txt, simulates mutations via jsdom, trains OnlineNBClassifier.
- `core/scripts/build.js` — esbuild script that reads `dist/seed_model.json` and injects it as base64 into the bundle via `--define`.
- Seed model written to `core/dist/seed_model.json`.

### ✅ Phase 3 — Node.js Backend (`backend/`)
- `backend/src/server.js` — Express server, helmet, CORS, rate-limit (200 req/min), dotenv.
- `backend/src/middleware/validate.js` — express-validator schema for all event fields.
- `backend/src/store/memory.js` — circular in-memory buffer (max 10000 events), per-session index.
- `backend/src/routes/report.js` — `POST /api/report`, `GET /api/events`, `GET /api/stats`, `GET /api/export`, `GET /api/model-xml` (XML rule export).
- **All 6 backend tests pass** (`npm test` in `backend/`).

### ✅ Phase 3b — PHP Fallback Receiver
- `php-receiver/receiver.php` — validates JSON payload (sessionId, probability, label), appends to `store/events.json` as JSON-lines.

### ✅ Phase 4 — React Dashboard (`dashboard/`)
- Bootstrapped with Vite + React 18.
- `src/hooks/useEvents.js` — polls `/api/events` and `/api/stats` every 2s.
- `src/components/ThreatFeed.jsx` — scrollable table of latest 50 events, red highlights for malicious.
- `src/components/ScoreGauge.jsx` — Recharts RadialBarChart showing malicious/benign ratio.
- `src/components/SessionTable.jsx` — grouped by sessionId, sorted by alert count.
- `src/components/ModelStats.jsx` — global stats + **"Export Rules as XML"** button (triggers `/api/model-xml`).
- Run: `npm run dev` in `dashboard/` → `http://localhost:5173`.

### ✅ Phase 5 — XML Rule Export
- `core/src/xmlExporter.js` — serializes classifier state to IEEE-compatible XML with log-odds per feature.
- Backend `/api/model-xml` route reconstructs classifier state from stored events and returns XML.

---

### ✅ Phase 6 — Django Admin Panel (`adaptxss_admin/`)
- `adaptxss_admin/` — Django 6 project, `monitor` app.
- `monitor/models.py` — `XSSEvent` model (session_id, timestamp, label, probability, features JSON, latency_ms).
- `monitor/admin.py` — `@admin.register` with list_display, list_filter, search, readonly_fields.
- `monitor/views.py` — `POST /api/ingest/` (DRF), `GET /api/events/`.
- `monitor/urls.py` — wired into project urls.py.
- `adaptxss_admin/settings.py` — corsheaders, rest_framework, monitor all in INSTALLED_APPS.
- Migrations applied cleanly (`0001_initial`), system check: 0 issues.
- Superuser: `admin` / `admin1234` (dev only).
- Run: `python manage.py runserver` → `http://localhost:8000/admin`.

### ✅ Phase 7 — Evaluation & Benchmarking (`evaluation/`)
- `evaluation/benchmark.ipynb` — full notebook with: stratified 80/20 split, Offline BNB baseline, AdaptXSS cold/warm simulation, latency measurements (mean + P99), results table, model drift experiment (5 sessions) with matplotlib plot saved to `paper/figures/model_drift.png`.
- `evaluation/baselines/zap_runner.py` — OWASP ZAP runner (falls back to heuristic mock if ZAP not running).

### ✅ Phase 8 — Research Paper (`paper/`)
- `paper/main.tex` — Full IEEE two-column draft: Abstract, Introduction, Related Work, System Design (with feature table + 4 equations), Implementation, Evaluation (results table + drift figure), Discussion, Conclusion.
- `paper/refs.bib` — 7 required citations: Heiderich 2012, Fang 2019, Bates 2010, OWASP ZAP, payloadbox, McCallum & Nigam 1998, MDN MutationObserver.

### ✅ Phase 9 — Integration Demo Page (`core/demo/`)
- `core/demo/index.html` — standalone HTML demo: inject/benign buttons, quick-payload shortcuts, configurable threshold slider, DOM target zone monitored by AdaptXSS, live event log with color-coded entries (red=alert, green=benign), session stats (total, alerts, avg/P99 latency).
- Open in browser after `npm run build` in `core/`.

---

## Key Decisions & Notes
- `adaptxss.min.js` must stay under 10 KB. Current: ~4.7 KB ✅
- Backend runs on port **4000**, Dashboard on **5173**.
- Tests use `--experimental-vm-modules` for ESM Jest support.
- The `outerHTML` fallback in extractor.js was added so script tags (which have no innerHTML in jsdom) are still detected via f2.
- Session IDs use format `sess_[a-z0-9]+_[epoch]` — validated by backend regex.

---

## How to Run the Full Stack

```bash
# 1. Core library (build once)
cd core && npm install && node scripts/pretrain.js && npm run build

# 2. Backend (port 4000)
cd backend && npm install && node src/server.js

# 3. Dashboard (port 5173)
cd dashboard && npm install && npm run dev

# 4. (Optional) PHP receiver
cd php-receiver && php -S localhost:8080

# 5. (Optional) Django admin
cd adaptxss_admin && python manage.py migrate && python manage.py runserver
```
