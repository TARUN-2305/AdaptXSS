// core/scripts/evaluate.js
// Evaluates the AdaptXSS classifier on a payload file (one payload per line).
// Outputs JSON to stdout — consumed by evaluation/benchmark.ipynb Cell 6.
//
// Usage:
//   node scripts/evaluate.js <path-to-payloads.txt> [--label <malicious|benign>]
//
// The script simulates browser MutationObserver events using jsdom,
// runs the pre-trained seed model (cold) and a warm model (pre-trained on 80%
// of the file), and outputs precision/recall/F1/latency for both.
//
// Example:
//   node scripts/evaluate.js ../evaluation/datasets/xss_payloads.txt --label malicious
//   node scripts/evaluate.js ../evaluation/datasets/benign_strings.txt --label benign

// Polyfill localStorage (not available in Node.js)
if (typeof localStorage === 'undefined') {
  global.localStorage = {
    _store: {},
    getItem(k)    { return this._store[k] ?? null; },
    setItem(k, v) { this._store[k] = String(v); },
    removeItem(k) { delete this._store[k]; },
    clear()       { this._store = {}; }
  };
}

import { JSDOM }              from 'jsdom';
import { readFileSync }       from 'fs';
import { fileURLToPath }      from 'url';
import { dirname, resolve }   from 'path';
import { extractFeatures }    from '../src/extractor.js';
import { OnlineNBClassifier } from '../src/classifier.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI args ──────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: node evaluate.js <payloads.txt> [--label malicious|benign]');
  process.exit(1);
}
const payloadFile = resolve(args[0]);
const labelIdx    = args.indexOf('--label');
const trueLabel   = labelIdx !== -1 ? args[labelIdx + 1] : 'malicious';

if (!['malicious', 'benign'].includes(trueLabel)) {
  console.error('--label must be "malicious" or "benign"');
  process.exit(1);
}

// ── Load payloads ─────────────────────────────────────────────────────────────
const payloads = readFileSync(payloadFile, 'utf-8')
  .split('\n')
  .map(l => l.trim())
  .filter(Boolean);

// ── Simulate MutationRecord from HTML string ──────────────────────────────────
function simulateMutation(html) {
  try {
    const dom = new JSDOM('<!DOCTYPE html><html><body><div id="root"></div></body></html>');
    const root = dom.window.document.getElementById('root');
    const wrapper = dom.window.document.createElement('div');
    wrapper.innerHTML = html;
    const node = wrapper.firstChild;
    if (!node) return null;
    return { addedNodes: [node], target: root };
  } catch (_) {
    return null;
  }
}

// ── Build feature vectors ─────────────────────────────────────────────────────
const samples = [];
for (const payload of payloads) {
  const mut = simulateMutation(payload);
  if (!mut) continue;
  samples.push({ features: extractFeatures(mut), payload });
}

// ── Cold evaluation (fresh model, seed priors only) ───────────────────────────
global.localStorage.clear();
const coldClf = new OnlineNBClassifier();

const coldResults = samples.map(({ features }) => {
  const t0 = performance.now();
  const { label, probability } = coldClf.predict(features);
  return { label, probability, latencyMs: performance.now() - t0 };
});

// ── Warm evaluation (train on 80%, test on 20%) ───────────────────────────────
global.localStorage.clear();
const warmClf   = new OnlineNBClassifier();
const splitIdx  = Math.floor(samples.length * 0.8);
const trainSamples = samples.slice(0, splitIdx);
const testSamples  = samples.slice(splitIdx);

for (const { features } of trainSamples) {
  warmClf.update(features, trueLabel);
}

const warmResults = testSamples.map(({ features }) => {
  const t0 = performance.now();
  const { label, probability } = warmClf.predict(features);
  return { label, probability, latencyMs: performance.now() - t0 };
});

// ── Metrics calculation ───────────────────────────────────────────────────────
function metrics(results, expectedLabel, totalSamples) {
  const tp = results.filter(r => r.label === expectedLabel).length;
  const fn = results.filter(r => r.label !== expectedLabel).length;
  // FP/TN can't be computed from single-class file alone — noted in output
  const recall    = totalSamples > 0 ? tp / totalSamples : 0;
  const lats      = results.map(r => r.latencyMs).sort((a, b) => a - b);
  const avgLat    = lats.reduce((s, l) => s + l, 0) / (lats.length || 1);
  const p99Lat    = lats[Math.floor(lats.length * 0.99)] || lats[lats.length - 1] || 0;
  return {
    truePositives:  tp,
    falseNegatives: fn,
    recall:         parseFloat(recall.toFixed(4)),
    avgLatencyMs:   parseFloat(avgLat.toFixed(4)),
    p99LatencyMs:   parseFloat(p99Lat.toFixed(4)),
    totalEvaluated: results.length
  };
}

const output = {
  file:       payloadFile,
  trueLabel,
  totalLoaded: payloads.length,
  totalParsed: samples.length,
  cold: metrics(coldResults, trueLabel, samples.length),
  warm: metrics(warmResults, trueLabel, testSamples.length),
  note: 'Precision/F1 require mixed-class evaluation — use benchmark.ipynb for full metrics'
};

// Output clean JSON for notebook subprocess call
process.stdout.write(JSON.stringify(output, null, 2) + '\n');
