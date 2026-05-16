# AdaptXSS — Complete Project Action Plan
### Adaptive DOM-Based XSS Detection via Incremental Pattern Learning

> **For any freelancer:** Follow this document section by section, in order. Every task has exact file names, code skeletons, commands, acceptance criteria, and definitions of done. Do not skip steps. Each phase builds directly on the previous one.

---

## Project Overview

| Field | Detail |
|---|---|
| Full Name | AdaptXSS — Adaptive DOM-Based XSS Detection |
| Tech Stack | Vanilla JS (core library) · React 18 (dashboard) · Node.js + Express (aggregation server) · PHP 8 (fallback receiver) · Python 3.11 (evaluation notebook) |
| Repository Structure | Monorepo with 5 subfolders |
| Total Estimated Duration | 8 weeks (solo freelancer), 5 weeks (2-person team) |
| Target Publication | IEEE ICWS / ACM WWW Security Track |
| Key Novelty | MutationObserver + online incremental Naive Bayes in-browser — no prior published combination |

---

## Repository Structure (Create This First)

```
adaptxss/
├── core/                  # Phase 1 — vanilla JS library
│   ├── src/
│   │   ├── observer.js
│   │   ├── extractor.js
│   │   ├── classifier.js
│   │   └── reporter.js
│   ├── dist/              # built output: adaptxss.min.js
│   ├── test/
│   │   ├── payloads/      # XSS payload fixtures
│   │   └── extractor.test.js
│   └── package.json
├── backend/               # Phase 3 — Node.js + Express
│   ├── src/
│   │   ├── server.js
│   │   ├── routes/
│   │   │   └── report.js
│   │   ├── store/
│   │   │   └── memory.js
│   │   └── middleware/
│   │       └── validate.js
│   ├── .env.example
│   └── package.json
├── dashboard/             # Phase 4 — React 18
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── ThreatFeed.jsx
│   │   │   ├── ScoreGauge.jsx
│   │   │   ├── SessionTable.jsx
│   │   │   └── ModelStats.jsx
│   │   └── hooks/
│   │       └── useEvents.js
│   └── package.json
├── php-receiver/          # Phase 3b — PHP fallback
│   ├── receiver.php
│   └── store/
│       └── events.json    # append-only log
├── evaluation/            # Phase 7 — benchmarks
│   ├── benchmark.ipynb
│   ├── datasets/
│   │   └── README.md      # instructions for downloading datasets
│   └── baselines/
│       └── zap_runner.py
└── paper/                 # Phase 8 — IEEE paper
    ├── main.tex
    ├── refs.bib
    └── figures/
```

**Setup command (run once at repo root):**
```bash
git init adaptxss && cd adaptxss
mkdir -p core/src core/test/payloads core/dist
mkdir -p backend/src/routes backend/src/store backend/src/middleware
mkdir -p dashboard/src/components dashboard/src/hooks
mkdir -p php-receiver/store
mkdir -p evaluation/datasets evaluation/baselines
mkdir -p paper/figures
```

---

## Phase 0 — Research Baseline (Days 1–2)

**Goal:** Understand exactly what the existing systems achieve so you know what numbers to beat.

### Task 0.1 — Collect datasets

Download the following (free, research-use):

| Dataset | Source | Size | Use |
|---|---|---|---|
| payloadbox/xss-payload-list | github.com/payloadbox/xss-payload-list | ~20k entries | Training + test payloads |
| XSSShield dataset | IEEE DataPort (DOI: 10.21227/...) | 1.8M entries | Evaluation benchmark |
| Benign URL corpus | Common Crawl (100k sample) | variable | URL anomaly baseline |

Place downloaded files inside `evaluation/datasets/`. Create `evaluation/datasets/README.md` documenting where each file came from and its license.

### Task 0.2 — Reproduce baseline F1 scores

Open `evaluation/benchmark.ipynb`. Before writing any of your own code, add a cell that loads the payloadbox dataset, runs scikit-learn's `BernoulliNB` on character n-gram features (this is the offline equivalent of what you'll build), and records F1, Precision, Recall as your offline ceiling. This number is your reference. Your browser-based system should not be expected to exceed this offline number — but it should stay within 10–15% of it while running in real-time.

**Acceptance criteria for Phase 0:**
- Offline BernoulliNB F1 on payloadbox dataset recorded in notebook cell output.
- Datasets present in `evaluation/datasets/`.

---

## Phase 1 — Core JS Library: `adaptxss.js` (Days 3–9)

This is the heart of the project. Build it in four separate modules and compose them in `index.js`.

---

### Module 1A — `core/src/extractor.js` (Feature Extraction)

**Purpose:** Given a single `MutationRecord` (from MutationObserver), produce a normalized 8-dimensional feature vector as a plain JS array.

**Feature vector definition (fixed — do not change this spec):**

```
f = [
  f0: tag_risk_score,         // Float 0–1
  f1: attr_delta_score,       // Float 0–1
  f2: script_injection_flag,  // Binary 0 or 1
  f3: inline_handler_flag,    // Binary 0 or 1
  f4: url_anomaly_score,      // Float 0–1
  f5: data_uri_flag,          // Binary 0 or 1
  f6: dom_depth_score,        // Float 0–1 (normalized)
  f7: text_content_entropy    // Float 0–1 (Shannon entropy)
]
```

**Exact implementation spec:**

```javascript
// core/src/extractor.js

// High-risk tags. Presence = f0 of 1.0, medium-risk = 0.5, absent = 0.0
const HIGH_RISK_TAGS = new Set(['script','iframe','object','embed','link','meta','base','svg','math']);
const MED_RISK_TAGS  = new Set(['img','video','audio','source','track','input','form','button','a']);

// Dangerous attributes. Any present = f1 increment of 0.25 each, capped at 1.0
const DANGEROUS_ATTRS = ['href','src','action','formaction','xlink:href','data','poster'];

// Inline event handler prefixes
const EVENT_PREFIXES = ['on']; // matches any attribute starting with "on"

export function extractFeatures(mutation) {
  const features = new Float32Array(8);
  const node = mutation.addedNodes.length > 0
    ? mutation.addedNodes[0]
    : mutation.target;

  // f0 — tag risk
  if (node.nodeName) {
    const tag = node.nodeName.toLowerCase();
    if (HIGH_RISK_TAGS.has(tag)) features[0] = 1.0;
    else if (MED_RISK_TAGS.has(tag)) features[0] = 0.5;
  }

  // f1 — dangerous attribute presence
  if (node.attributes) {
    let attrScore = 0;
    for (const attr of node.attributes) {
      if (DANGEROUS_ATTRS.includes(attr.name.toLowerCase())) attrScore += 0.25;
    }
    features[1] = Math.min(attrScore, 1.0);
  }

  // f2 — script injection (innerHTML or text content contains <script)
  const content = node.innerHTML || node.textContent || '';
  features[2] = /(<script[\s>]|javascript\s*:)/i.test(content) ? 1 : 0;

  // f3 — inline event handler (any attribute starting with "on")
  if (node.attributes) {
    for (const attr of node.attributes) {
      if (attr.name.toLowerCase().startsWith('on')) { features[3] = 1; break; }
    }
  }

  // f4 — URL anomaly (href/src contains non-http schemes or suspicious keywords)
  const urlAttrs = ['href', 'src', 'action', 'formaction'];
  if (node.attributes) {
    for (const attr of node.attributes) {
      if (urlAttrs.includes(attr.name.toLowerCase())) {
        const val = attr.value.toLowerCase().trim();
        if (/^(javascript|vbscript|data|blob):/.test(val)) features[4] = 1.0;
        else if (/[<>"']/.test(val)) features[4] = 0.7;
      }
    }
  }

  // f5 — data URI flag (img/a with data: URI is high-risk vector)
  if (node.attributes) {
    const src = node.getAttribute && node.getAttribute('src');
    const href = node.getAttribute && node.getAttribute('href');
    if ((src && src.startsWith('data:')) || (href && href.startsWith('data:'))) features[5] = 1;
  }

  // f6 — DOM depth (normalized, max assumed = 20)
  let depth = 0, el = node;
  while (el.parentNode) { depth++; el = el.parentNode; }
  features[6] = Math.min(depth / 20, 1.0);

  // f7 — Shannon entropy of text content
  if (content.length > 0) {
    const freq = {};
    for (const ch of content) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    const len = content.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    features[7] = Math.min(entropy / 8, 1.0); // normalize: max natural entropy ~8 bits
  }

  return features;
}
```

**Unit tests for `core/test/extractor.test.js`:**

Write tests using Jest. Cover these exact cases:

| Test | Input | Expected |
|---|---|---|
| Clean div | `<div>Hello</div>` mutation | All features 0.0 |
| Script tag injection | `<script>alert(1)</script>` added | f0=1.0, f2=1 |
| XSS via onerror | `<img onerror="alert(1)">` | f0=0.5, f3=1 |
| javascript: href | `<a href="javascript:alert(1)">` | f4=1.0 |
| data: URI | `<img src="data:image/png;base64,...">` | f5=1 |
| High entropy payload | obfuscated string like `%3Cscript%3E` | f7 > 0.7 |

---

### Module 1B — `core/src/classifier.js` (Online Incremental Naive Bayes)

**Purpose:** A self-contained online Bernoulli Naive Bayes classifier that updates its weights per prediction (when feedback is available) and per session using localStorage for model persistence.

**Full implementation spec:**

```javascript
// core/src/classifier.js

// Model state — serializable to JSON
const DEFAULT_STATE = {
  classCounts:   { malicious: 1, benign: 1 },   // Laplace init
  featureCounts: {
    malicious: new Array(8).fill(1),
    benign:    new Array(8).fill(1),
  },
  totalSamples: 2,
  version: 1
};

export class OnlineNBClassifier {
  constructor() {
    this.state = this._load() || structuredClone(DEFAULT_STATE);
  }

  // Classify: returns { label: 'malicious'|'benign', probability: Float }
  predict(features) {
    const classes = ['malicious', 'benign'];
    const logProbs = {};

    for (const cls of classes) {
      const total = this.state.classCounts[cls];
      const prior = Math.log(total / this.state.totalSamples);
      let likelihood = 0;

      for (let i = 0; i < features.length; i++) {
        // Bernoulli: treat feature as present if > 0.5 threshold
        const present = features[i] > 0.5 ? 1 : 0;
        const count = this.state.featureCounts[cls][i];
        const total_cls = total + 8; // Laplace denominator
        const p = (count + 1) / (total_cls + 2);
        likelihood += present ? Math.log(p) : Math.log(1 - p);
      }
      logProbs[cls] = prior + likelihood;
    }

    // Normalize to probability via log-sum-exp
    const maxLogP = Math.max(...Object.values(logProbs));
    const expSum = Object.values(logProbs).reduce((s, lp) => s + Math.exp(lp - maxLogP), 0);
    const maliciousProb = Math.exp(logProbs.malicious - maxLogP) / expSum;

    return {
      label: maliciousProb > 0.5 ? 'malicious' : 'benign',
      probability: maliciousProb
    };
  }

  // Update model with ground truth label (used when analyst confirms/rejects alert)
  update(features, trueLabel) {
    this.state.classCounts[trueLabel]++;
    this.state.totalSamples++;
    for (let i = 0; i < features.length; i++) {
      if (features[i] > 0.5) this.state.featureCounts[trueLabel][i]++;
    }
    this._save();
  }

  // Serialize model as JSON string (for export / server sync)
  serialize() {
    return JSON.stringify(this.state);
  }

  // Load from serialized JSON
  static fromJSON(json) {
    const c = new OnlineNBClassifier();
    c.state = JSON.parse(json);
    return c;
  }

  _save() {
    try { localStorage.setItem('adaptxss_model', this.serialize()); } catch(_) {}
  }

  _load() {
    try {
      const raw = localStorage.getItem('adaptxss_model');
      return raw ? JSON.parse(raw) : null;
    } catch(_) { return null; }
  }
}
```

**Unit tests for classifier:**

| Test | Scenario | Expected |
|---|---|---|
| Fresh model | predict on all-zero features | label='benign', probability < 0.6 |
| After training 50 XSS samples | predict on `[1,1,1,1,1,1,0,0]` | label='malicious', probability > 0.85 |
| Persistence round-trip | serialize → fromJSON → predict | Same prediction as before serialization |
| Laplace smoothing | No division-by-zero on fresh model | No NaN or Infinity in output |

---

### Module 1C — `core/src/observer.js` (MutationObserver Hook)

**Purpose:** Attach a `MutationObserver` to a given DOM root, pipe each mutation through extractor → classifier, and emit events.

```javascript
// core/src/observer.js
import { extractFeatures } from './extractor.js';
import { OnlineNBClassifier } from './classifier.js';
import { report } from './reporter.js';

export class AdaptXSSObserver {
  constructor(options = {}) {
    this.classifier = new OnlineNBClassifier();
    this.threshold = options.threshold || 0.65;      // configurable alert threshold
    this.endpoint  = options.endpoint  || null;      // Node.js or PHP endpoint
    this.onAlert   = options.onAlert   || null;      // callback(event)
    this.sessionId = this._genSession();
    this._observer = null;
    this._stats = { total: 0, alerts: 0, latencies: [] };
  }

  attach(root = document.body) {
    this._observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        const t0 = performance.now();
        const features = extractFeatures(mutation);
        const { label, probability } = this.classifier.predict(features);
        const latency = performance.now() - t0;

        this._stats.total++;
        this._stats.latencies.push(latency);

        if (probability >= this.threshold) {
          this._stats.alerts++;
          const evt = {
            timestamp: Date.now(),
            sessionId: this.sessionId,
            label, probability,
            features: Array.from(features),
            mutation: {
              type: mutation.type,
              targetTag: mutation.target.nodeName,
              addedCount: mutation.addedNodes.length
            },
            latencyMs: latency
          };
          if (this.onAlert) this.onAlert(evt);
          if (this.endpoint) report(this.endpoint, evt);
        }
      }
    });

    this._observer.observe(root, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['href','src','onerror','onclick','onload','onmouseover',
                        'onfocus','action','formaction','xlink:href']
    });

    console.log(`[AdaptXSS] Observer attached. Session: ${this.sessionId}`);
  }

  detach() { this._observer && this._observer.disconnect(); }

  getStats() {
    const lats = this._stats.latencies;
    return {
      ...this._stats,
      avgLatencyMs: lats.length ? lats.reduce((a,b) => a+b, 0) / lats.length : 0,
      p99LatencyMs: lats.length ? lats.sort((a,b)=>a-b)[Math.floor(lats.length*0.99)] : 0
    };
  }

  _genSession() {
    return 'sess_' + Math.random().toString(36).slice(2, 11) + '_' + Date.now();
  }
}
```

---

### Module 1D — `core/src/reporter.js` (Ajax Reporting)

```javascript
// core/src/reporter.js

// Sends event to backend with exponential backoff retry
export async function report(endpoint, event, retries = 3) {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
        keepalive: true  // important: survives page unload
      });
      if (res.ok) return;
    } catch (_) {
      await new Promise(r => setTimeout(r, 200 * Math.pow(2, attempt)));
    }
  }
  // Silent failure — security monitor must not crash the host app
}
```

---

### Module 1E — `core/src/index.js` (Public API)

```javascript
// core/src/index.js — public entry point
export { AdaptXSSObserver } from './observer.js';
export { OnlineNBClassifier } from './classifier.js';
export { extractFeatures } from './extractor.js';

// Usage example (in any web page):
//
// import { AdaptXSSObserver } from 'adaptxss';
// const monitor = new AdaptXSSObserver({
//   threshold: 0.7,
//   endpoint: 'https://yourserver.com/api/report',
//   onAlert: (evt) => console.warn('[XSS ALERT]', evt)
// });
// monitor.attach(document.body);
```

---

### Build configuration for `core/`

**`core/package.json`:**
```json
{
  "name": "adaptxss",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/adaptxss.min.js",
  "scripts": {
    "build": "npx esbuild src/index.js --bundle --minify --format=iife --global-name=AdaptXSS --outfile=dist/adaptxss.min.js",
    "test": "npx jest --experimental-vm-modules",
    "size": "du -sh dist/adaptxss.min.js"
  },
  "devDependencies": {
    "esbuild": "^0.20.0",
    "jest": "^29.0.0"
  }
}
```

**Build and size check:**
```bash
cd core && npm install && npm run build && npm run size
```

The output `dist/adaptxss.min.js` must be under 10 KB. If it exceeds this, audit with `npx esbuild src/index.js --bundle --analyze`.

**Phase 1 definition of done:**
- `npm test` in `core/` passes all tests with 0 failures.
- `dist/adaptxss.min.js` exists and is < 10 KB.
- All 8 features extracted correctly for each test payload.
- Classifier produces no NaN outputs on any input.

---

## Phase 2 — Seed Training Data (Days 8–9)

**Goal:** Pre-train the classifier on a curated subset of the payloadbox dataset so that it starts with reasonable priors before any live session.

### Task 2.1 — Payload preprocessing script

Create `core/scripts/pretrain.js`:

```javascript
// core/scripts/pretrain.js
// Reads XSS payloads from a text file (one per line), simulates DOM mutations,
// runs extractor, and outputs a seed model JSON.

import { JSDOM } from 'jsdom';
import { extractFeatures } from '../src/extractor.js';
import { OnlineNBClassifier } from '../src/classifier.js';
import { readFileSync, writeFileSync } from 'fs';

const payloads = readFileSync('./datasets/xss_payloads.txt', 'utf-8')
  .split('\n').filter(Boolean).slice(0, 5000); // use first 5000

const benignStrings = readFileSync('./datasets/benign_strings.txt', 'utf-8')
  .split('\n').filter(Boolean).slice(0, 5000);

const clf = new OnlineNBClassifier();

// Simulate: inject each payload into a JSDOM, observe first mutation
for (const payload of payloads) {
  const dom = new JSDOM('<div id="root"></div>');
  const root = dom.window.document.getElementById('root');
  const mutation = simulateMutation(dom, root, payload);
  if (mutation) {
    const features = extractFeatures(mutation);
    clf.update(features, 'malicious');
  }
}

for (const benign of benignStrings) {
  const dom = new JSDOM('<div id="root"></div>');
  const root = dom.window.document.getElementById('root');
  const mutation = simulateMutation(dom, root, benign);
  if (mutation) {
    const features = extractFeatures(mutation);
    clf.update(features, 'benign');
  }
}

writeFileSync('./dist/seed_model.json', clf.serialize());
console.log('Seed model written. Size:', clf.serialize().length, 'bytes');
```

**Important:** `simulateMutation` is a helper that uses `jsdom`'s `MutationObserver` polyfill. Add `jsdom` as a dev dependency: `npm install --save-dev jsdom`.

### Task 2.2 — Embed seed model in build

Add the seed model JSON as a base64-encoded string inside `adaptxss.min.js` so that the browser-based classifier starts pre-trained, not cold. Modify `core/src/classifier.js` to import `seed_model.json` at build time using esbuild's `--define` flag:

```bash
npx esbuild src/index.js --bundle --minify --format=iife \
  --global-name=AdaptXSS \
  --define:SEED_MODEL_JSON="'$(cat dist/seed_model.json | base64)'" \
  --outfile=dist/adaptxss.min.js
```

In `classifier.js`, add:

```javascript
_load() {
  try {
    const stored = localStorage.getItem('adaptxss_model');
    if (stored) return JSON.parse(stored);
    // Fallback to compile-time seed
    if (typeof SEED_MODEL_JSON !== 'undefined') {
      return JSON.parse(atob(SEED_MODEL_JSON));
    }
  } catch(_) {}
  return null;
}
```

**Phase 2 definition of done:**
- `dist/seed_model.json` exists with > 2000 training samples recorded.
- Pre-trained classifier on clean XSS payloads achieves F1 > 0.70 in offline test (run `npm test`).
- Final `dist/adaptxss.min.js` still < 10 KB after embedding seed.

---

## Phase 3 — Node.js Aggregation Backend (Days 10–12)

### Task 3.1 — Setup

```bash
cd backend
npm init -y
npm install express cors helmet express-validator dotenv
npm install --save-dev nodemon jest supertest
```

**`backend/.env.example`:**
```
PORT=4000
ALLOWED_ORIGIN=http://localhost:3000
MAX_EVENTS_STORED=10000
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=200
```

Copy to `.env` and fill in values before running.

### Task 3.2 — Event schema

Every event sent from the browser (by `reporter.js`) must match this exact shape. Enforce it on the backend:

```javascript
// backend/src/middleware/validate.js
import { body, validationResult } from 'express-validator';

export const validateEvent = [
  body('timestamp').isInt({ min: 0 }),
  body('sessionId').isString().matches(/^sess_[a-z0-9_]+$/),
  body('label').isIn(['malicious', 'benign']),
  body('probability').isFloat({ min: 0, max: 1 }),
  body('features').isArray({ min: 8, max: 8 }),
  body('features.*').isFloat({ min: 0, max: 1 }),
  body('latencyMs').isFloat({ min: 0 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    next();
  }
];
```

### Task 3.3 — In-memory event store

```javascript
// backend/src/store/memory.js
// Circular buffer — keeps last N events per session, no database needed

const MAX = parseInt(process.env.MAX_EVENTS_STORED || '10000');
const store = { events: [], sessions: {} };

export function addEvent(event) {
  store.events.push(event);
  if (store.events.length > MAX) store.events.shift();
  if (!store.sessions[event.sessionId]) store.sessions[event.sessionId] = [];
  store.sessions[event.sessionId].push(event);
}

export function getAll() { return store.events; }

export function getBySession(sessionId) {
  return store.sessions[sessionId] || [];
}

export function getStats() {
  const total = store.events.length;
  const malicious = store.events.filter(e => e.label === 'malicious').length;
  return {
    total,
    malicious,
    benign: total - malicious,
    sessions: Object.keys(store.sessions).length,
    avgProbability: total ? store.events.reduce((s,e) => s + e.probability, 0) / total : 0
  };
}
```

### Task 3.4 — Routes

```javascript
// backend/src/routes/report.js
import { Router } from 'express';
import { validateEvent } from '../middleware/validate.js';
import { addEvent, getAll, getBySession, getStats } from '../store/memory.js';

const router = Router();

// POST /api/report — receive event from browser
router.post('/report', validateEvent, (req, res) => {
  addEvent(req.body);
  res.status(201).json({ ok: true });
});

// GET /api/events — return all events (used by React dashboard)
router.get('/events', (req, res) => {
  const { session, limit = 100 } = req.query;
  const events = session ? getBySession(session) : getAll();
  res.json(events.slice(-parseInt(limit)));
});

// GET /api/stats — aggregate statistics
router.get('/stats', (req, res) => res.json(getStats()));

// GET /api/export — download all events as JSON (for paper evaluation)
router.get('/export', (req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="adaptxss_events.json"');
  res.json(getAll());
});

export default router;
```

### Task 3.5 — Server entry point

```javascript
// backend/src/server.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import reportRouter from './routes/report.js';

dotenv.config();

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN }));
app.use(rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000'),
  max: parseInt(process.env.RATE_LIMIT_MAX || '200')
}));

app.use('/api', reportRouter);
app.get('/health', (_, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`[AdaptXSS Backend] Listening on port ${PORT}`));
export default app;
```

**Run dev server:**
```bash
cd backend && node --env-file=.env src/server.js
```

### Task 3.6 — Backend tests

Write integration tests in `backend/test/report.test.js` using `supertest`. Cover:

- `POST /api/report` with valid payload → 201 response.
- `POST /api/report` with missing fields → 400 with error list.
- `POST /api/report` with probability > 1 → 400.
- `GET /api/events` returns array.
- `GET /api/stats` returns object with `total`, `malicious`, `benign`.
- Rate limiting: 201 identical posts → last ones return 429.

**Phase 3 definition of done:**
- `npm test` in `backend/` passes all 6 test cases.
- Server starts without errors on `npm start`.
- `GET /health` returns `{"status":"ok"}`.

---

## Phase 3b — PHP Fallback Receiver (Day 12)

Used when deploying in environments without Node.js (shared hosting, legacy servers).

### `php-receiver/receiver.php`

```php
<?php
// AdaptXSS PHP Fallback Receiver
// Requirement: PHP 8.0+, write permission on store/ directory

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!$data || !isset($data['sessionId'], $data['probability'], $data['label'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid payload']);
    exit;
}

// Validate probability range
if ($data['probability'] < 0 || $data['probability'] > 1) {
    http_response_code(400);
    echo json_encode(['error' => 'probability out of range']);
    exit;
}

$data['received_at'] = time();
$store_file = __DIR__ . '/store/events.json';

// Append to JSON lines file (one JSON object per line)
$line = json_encode($data) . PHP_EOL;
$fp = fopen($store_file, 'a');
if (!$fp) {
    http_response_code(500);
    echo json_encode(['error' => 'Cannot write to store']);
    exit;
}
fwrite($fp, $line);
fclose($fp);

http_response_code(201);
echo json_encode(['ok' => true]);
```

**Test it:**
```bash
cd php-receiver
php -S localhost:8080
curl -X POST http://localhost:8080/receiver.php \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"sess_test","label":"malicious","probability":0.92,"features":[1,1,1,1,0,0,0.5,0.7],"timestamp":1234567890,"latencyMs":3.2}'
```

Expect `{"ok":true}` and a new line in `store/events.json`.

---

## Phase 4 — React Dashboard (Days 13–16)

### Task 4.1 — Bootstrap

```bash
cd dashboard
npm create vite@latest . -- --template react
npm install recharts axios date-fns
npm install --save-dev @testing-library/react @testing-library/jest-dom vitest
```

**`dashboard/src/App.jsx` skeleton:**

```jsx
import { useState, useEffect } from 'react';
import ThreatFeed from './components/ThreatFeed';
import ScoreGauge from './components/ScoreGauge';
import SessionTable from './components/SessionTable';
import ModelStats from './components/ModelStats';
import { useEvents } from './hooks/useEvents';

export default function App() {
  const { events, stats, loading } = useEvents('http://localhost:4000');

  return (
    <div style={{ fontFamily: 'monospace', padding: '1rem', background: '#0d0d0d', minHeight: '100vh', color: '#e2e8f0' }}>
      <h1 style={{ fontSize: '1.4rem', marginBottom: '1rem', color: '#f97316' }}>
        AdaptXSS — Live Threat Monitor
      </h1>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <ScoreGauge stats={stats} />
        <ModelStats stats={stats} />
      </div>
      <ThreatFeed events={events} />
      <SessionTable events={events} />
    </div>
  );
}
```

### Task 4.2 — `useEvents` hook

```javascript
// dashboard/src/hooks/useEvents.js
import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

export function useEvents(baseUrl, pollIntervalMs = 2000) {
  const [events, setEvents] = useState([]);
  const [stats, setStats]   = useState({ total: 0, malicious: 0, benign: 0, sessions: 0 });
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [evtsRes, statsRes] = await Promise.all([
        axios.get(`${baseUrl}/api/events?limit=200`),
        axios.get(`${baseUrl}/api/stats`)
      ]);
      setEvents(evtsRes.data);
      setStats(statsRes.data);
    } catch (err) {
      console.error('[AdaptXSS Dashboard] Fetch error:', err.message);
    } finally {
      setLoading(false);
    }
  }, [baseUrl]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, pollIntervalMs);
    return () => clearInterval(interval);
  }, [fetchData, pollIntervalMs]);

  return { events, stats, loading };
}
```

### Task 4.3 — Component specs

**`ThreatFeed.jsx`** — A scrollable list of the 50 most recent events. Each row shows: timestamp (formatted with `date-fns`), sessionId (truncated to 8 chars), label (red badge for malicious / green for benign), probability (e.g., 0.94), latencyMs. Color the row background `rgba(239,68,68,0.1)` when label = malicious.

**`ScoreGauge.jsx`** — A `recharts` `RadialBarChart` showing the current ratio of malicious to total events as a percentage. Update in real time from the `stats` prop.

**`SessionTable.jsx`** — Group `events` by `sessionId`. For each session show: session ID, event count, alert count, first seen, last seen. Sortable by alert count descending.

**`ModelStats.jsx`** — Show: total events processed, current malicious %, average latency (ms), P99 latency (ms). Pull latency stats from the events array directly (compute client-side from `latencyMs` field).

### Task 4.4 — Dashboard start

```bash
cd dashboard && npm run dev
```

Navigate to `http://localhost:5173`. The dashboard should show live-updating data within 2 seconds of events being posted to the backend.

**Phase 4 definition of done:**
- Dashboard renders without console errors.
- Gauge updates within 2 seconds of a new event being sent to the backend.
- ThreatFeed correctly colors malicious events red.
- `npm run build` produces a `dist/` folder with no TypeScript / Vite errors.

---

## Phase 5 — XML Rule Export Module (Day 15)

This satisfies Unit III (XML) of the syllabus and provides an extra feature for the paper: the model can export its learned rules as an XML document that other systems (e.g., WAF rule engines) can import.

### `core/src/xmlExporter.js`

```javascript
// core/src/xmlExporter.js
// Exports the current classifier state as an XML rule set

export function exportModelAsXML(classifierState) {
  const { classCounts, featureCounts, totalSamples } = classifierState;
  const featureNames = [
    'tag_risk', 'attr_delta', 'script_injection', 'inline_handler',
    'url_anomaly', 'data_uri', 'dom_depth', 'text_entropy'
  ];

  const rules = featureNames.map((name, i) => {
    const pMalicious = (featureCounts.malicious[i] + 1) / (classCounts.malicious + 2);
    const pBenign    = (featureCounts.benign[i]    + 1) / (classCounts.benign    + 2);
    return `    <feature name="${name}" index="${i}">
      <p_malicious>${pMalicious.toFixed(6)}</p_malicious>
      <p_benign>${pBenign.toFixed(6)}</p_benign>
      <log_odds>${(Math.log(pMalicious) - Math.log(pBenign)).toFixed(6)}</log_odds>
    </feature>`;
  }).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<adaptxss_model version="${classifierState.version}" totalSamples="${totalSamples}">
  <prior_malicious>${(classCounts.malicious / totalSamples).toFixed(6)}</prior_malicious>
  <prior_benign>${(classCounts.benign / totalSamples).toFixed(6)}</prior_benign>
  <features>
${rules}
  </features>
</adaptxss_model>`;
}
```

Add a button to the React dashboard: "Export Rules as XML". When clicked, call `GET /api/model-xml` on the backend, which returns the XML string, and trigger a browser download.

---

## Phase 6 — Django Admin Panel (Days 16–17)

This satisfies Unit V (Django) of the syllabus and provides a web-based management interface for reviewing stored events.

### Setup

```bash
pip install django djangorestframework django-cors-headers
django-admin startproject adaptxss_admin
cd adaptxss_admin
python manage.py startapp monitor
```

### Task 6.1 — Model

```python
# monitor/models.py
from django.db import models

class XSSEvent(models.Model):
    session_id   = models.CharField(max_length=64, db_index=True)
    timestamp    = models.BigIntegerField()
    label        = models.CharField(max_length=16)  # 'malicious' or 'benign'
    probability  = models.FloatField()
    features     = models.JSONField()
    latency_ms   = models.FloatField()
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'XSS Event'
```

### Task 6.2 — Admin registration

```python
# monitor/admin.py
from django.contrib import admin
from .models import XSSEvent

@admin.register(XSSEvent)
class XSSEventAdmin(admin.ModelAdmin):
    list_display  = ('session_id', 'label', 'probability', 'latency_ms', 'created_at')
    list_filter   = ('label',)
    search_fields = ('session_id',)
    readonly_fields = ('features',)
```

### Task 6.3 — Ingest endpoint

Add a REST endpoint at `POST /api/ingest/` that accepts the same event schema as the Node.js backend and saves to Django's SQLite database. This provides persistence across server restarts.

**Phase 6 definition of done:**
- `python manage.py runserver` starts without errors.
- Navigate to `http://localhost:8000/admin`, log in, and see the XSS Events table.
- `POST /api/ingest/` with a valid event returns 201.

---

## Phase 7 — Evaluation & Benchmarking (Days 18–20)

This phase produces the numbers that go into the research paper.

### Task 7.1 — Dataset split

In `evaluation/benchmark.ipynb`:

```python
import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_csv('datasets/xss_payloads.csv')  # columns: payload, label (1=xss, 0=benign)
train_df, test_df = train_test_split(df, test_size=0.2, stratify=df['label'], random_state=42)
print(f"Train: {len(train_df)}, Test: {len(test_df)}")
```

Use 80/20 split. Stratify by label to maintain class balance.

### Task 7.2 — Baseline measurements

Measure these three systems on the same test set:

**Baseline A: OWASP ZAP (static rules)**

Use ZAP's Python API or subprocess to scan a local test page injected with each payload. Record TP, FP, FN, TN manually. Refer to `evaluation/baselines/zap_runner.py`.

**Baseline B: Offline Bernoulli NB (bag-of-chars)**

```python
from sklearn.naive_bayes import BernoulliNB
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import classification_report
import time

vec = CountVectorizer(analyzer='char', ngram_range=(2,3), max_features=5000)
X_train = vec.fit_transform(train_df['payload'])
X_test  = vec.transform(test_df['payload'])

clf = BernoulliNB()
t0 = time.time()
clf.fit(X_train, train_df['label'])
t1 = time.time()

preds = clf.predict(X_test)
print(classification_report(test_df['label'], preds))
print(f"Training time: {t1-t0:.2f}s")
```

**Baseline C: AdaptXSS (your system)**

Simulate browser mutations using `jsdom` + the `core/` module from Phase 1. For each test payload, inject into a JSDOM document, observe the mutation, run `predict()`, record prediction + latency. Aggregate Precision, Recall, F1.

```python
import subprocess
import json

# Call Node.js evaluation harness
result = subprocess.run(
    ['node', '../core/scripts/evaluate.js', 'datasets/test_payloads.txt'],
    capture_output=True, text=True
)
metrics = json.loads(result.stdout)
print(metrics)
```

### Task 7.3 — Latency measurement

For AdaptXSS, record `latencyMs` from each prediction. Compute:
- Mean latency
- Median latency
- P99 latency (99th percentile)

Compare with server-side systems by measuring their round-trip time.

### Task 7.4 — Results table

Fill in this table in the notebook and in the paper:

| System | Precision | Recall | F1 | Mean Latency | Model Size |
|---|---|---|---|---|---|
| OWASP ZAP | measured | measured | measured | measured | N/A |
| Offline BNB | measured | measured | measured | train-only | ~1 MB |
| AdaptXSS (cold) | measured | measured | measured | measured | < 10 KB |
| AdaptXSS (warm) | measured | measured | measured | measured | < 10 KB |

"Cold" = fresh model before any session-specific updates. "Warm" = after 200 training samples seen.

### Task 7.5 — Model drift experiment

Run 5 simulated sessions of 100 mutations each (mixed benign + XSS). After each session, record F1. Plot F1 vs session number to show that the online model improves (or at worst stabilizes) over time. This is the **key novelty plot** for the paper.

**Phase 7 definition of done:**
- All four rows of the results table are filled with real measured numbers.
- Model drift plot shows upward or stable F1 trend.
- Notebook runs end-to-end with `Run All` without errors.

---

## Phase 8 — Research Paper (Days 20–24)

Write in IEEE two-column format using LaTeX.

### File: `paper/main.tex` — Section outline

```
\documentclass[conference]{IEEEtran}
\begin{document}

1. Introduction          (~500 words)
   - XSS prevalence and cost
   - Gap: no in-browser, adaptive, lightweight detector
   - Contribution: AdaptXSS

2. Related Work          (~600 words)
   - Static approaches (OWASP ZAP, CSP)
   - ML offline approaches (Fang 2019, XGBoost-XSS, BernoulliNB)
   - Mutation XSS attacks (Heiderich 2012, PortSwigger 2020)
   - Why existing work does not address the gap

3. System Design         (~800 words)
   - Architecture diagram (Figure 1)
   - Feature vector definition (Table 1)
   - Online NB derivation (Equations 1–4)
   - MutationObserver integration

4. Implementation        (~400 words)
   - Module breakdown
   - Build size analysis
   - API surface

5. Evaluation            (~800 words)
   - Dataset description
   - Experimental setup
   - Results table (Table 2)
   - Model drift plot (Figure 2)
   - Latency analysis

6. Discussion            (~300 words)
   - Limitations: adversarial robustness, class imbalance
   - Future work: federated learning across sessions

7. Conclusion            (~200 words)

References
```

### Key equations to include in the paper

**Equation 1 — Posterior:**
```
P(c | f) ∝ P(c) · ∏_{i=1}^{8} P(f_i | c)
```

**Equation 2 — Bernoulli likelihood:**
```
P(f_i | c) = p_{ic}^{f_i} · (1 - p_{ic})^{1-f_i}
```

**Equation 3 — Laplace-smoothed parameter:**
```
p_{ic} = (N_{ic} + 1) / (N_c + 2)
```

**Equation 4 — Online update:**
```
N_{ic}(t+1) = N_{ic}(t) + 1   if y_t = c and f_i(t) > 0.5
N_c(t+1)   = N_c(t) + 1       if y_t = c
```

### `paper/refs.bib` — Required citations

Include at minimum:
- Heiderich et al. (2012) — DOM clobbering
- Fang et al. (2018/2019) — Deep learning XSS detection
- OWASP ZAP documentation
- payloadbox/xss-payload-list
- McCallum & Nigam (1998) — Bernoulli Naive Bayes original paper
- MutationObserver MDN specification

---

## Phase 9 — Integration Demo Page (Day 21)

Create `core/demo/index.html` — a single HTML file that a professor can open in a browser to see the whole system working:

```html
<!DOCTYPE html>
<html>
<head>
  <title>AdaptXSS — Live Demo</title>
  <script src="../dist/adaptxss.min.js"></script>
</head>
<body>
  <h2>AdaptXSS Demo — Inject XSS below</h2>
  <input id="payload" type="text" placeholder="Paste payload here" style="width:400px">
  <button onclick="inject()">Inject</button>
  <div id="target"></div>
  <div id="log" style="margin-top:1rem;font-family:monospace;font-size:12px"></div>

  <script>
    const monitor = new AdaptXSS.AdaptXSSObserver({
      threshold: 0.6,
      onAlert: (evt) => {
        const log = document.getElementById('log');
        log.innerHTML = `<div style="color:red">⚠ ALERT [${new Date(evt.timestamp).toLocaleTimeString()}]
          label=${evt.label} prob=${evt.probability.toFixed(3)} latency=${evt.latencyMs.toFixed(2)}ms</div>` + log.innerHTML;
      }
    });
    monitor.attach(document.getElementById('target'));

    function inject() {
      const p = document.getElementById('payload').value;
      document.getElementById('target').innerHTML = p;  // deliberate — this is the attack surface
    }
  </script>
</body>
</html>
```

Test with: `<script>alert(1)</script>`, `<img onerror="alert(1)" src=x>`, `<a href="javascript:alert(1)">click</a>`.

---

## Final Checklist Before Submission

| Item | Done? |
|---|---|
| `core/dist/adaptxss.min.js` < 10 KB | |
| All unit tests passing (`npm test` in `core/`) | |
| All backend tests passing (`npm test` in `backend/`) | |
| React dashboard runs and polls in real time | |
| PHP receiver accepts POST and writes to `events.json` | |
| Django admin panel shows stored events | |
| XML export produces valid XML | |
| Evaluation notebook runs end-to-end | |
| Results table fully populated with measured numbers | |
| Model drift plot shows stable or improving F1 | |
| Demo page triggers alerts on known payloads | |
| Paper draft written, equations included, references cited | |

---

## Dependency Summary

| Folder | Key Packages |
|---|---|
| `core/` | esbuild, jest, jsdom (dev) |
| `backend/` | express, cors, helmet, express-validator, dotenv |
| `dashboard/` | react, vite, recharts, axios, date-fns |
| `php-receiver/` | PHP 8.0+ (no composer dependencies) |
| `evaluation/` | scikit-learn, pandas, matplotlib, jupyterlab, numpy |
| `paper/` | LaTeX (IEEEtran class), BibTeX |

---

## Mathematical Reference Card

**Feature vector:** `f ∈ [0,1]^8`

**Predict:**
```
label = argmax_c [ log P(c) + Σ_i log P(f_i | c) ]
```

**Update (per confirmed label):**
```
N_ic += 1[f_i > 0.5]
N_c  += 1
```

**Metrics:**
```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 · Precision · Recall / (Precision + Recall)
```

**Latency target:** mean < 5ms, P99 < 20ms (browser main thread)

**Size target:** `adaptxss.min.js` < 10 KB (minified + gzipped < 4 KB)
