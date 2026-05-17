// core/scripts/pretrain.js
// Pre-trains the classifier on the evaluation dataset and writes dist/seed_model.json
// Usage: node scripts/pretrain.js

// Polyfill localStorage for Node.js (classifier._save() uses it)
if (typeof localStorage === 'undefined') {
  global.localStorage = {
    _store: {},
    getItem(k)    { return this._store[k] ?? null; },
    setItem(k, v) { this._store[k] = String(v); },
    removeItem(k) { delete this._store[k]; },
    clear()       { this._store = {}; }
  };
}

import { JSDOM }             from 'jsdom';
import { extractFeatures }   from '../src/extractor.js';
import { OnlineNBClassifier } from '../src/classifier.js';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join }  from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const datasetsDir = join(__dirname, '../../evaluation/datasets');

const payloads = readFileSync(join(datasetsDir, 'xss_payloads.txt'), 'utf-8')
  .split('\n').map(s => s.trim()).filter(Boolean);

const benignStrings = readFileSync(join(datasetsDir, 'benign_strings.txt'), 'utf-8')
  .split('\n').map(s => s.trim()).filter(Boolean);

function simulateMutation(htmlString) {
  try {
    const dom = new JSDOM('<!DOCTYPE html><html><body><div id="root"></div></body></html>');
    const root = dom.window.document.getElementById('root');
    const wrapper = dom.window.document.createElement('div');
    wrapper.innerHTML = htmlString;
    const node = wrapper.firstChild;
    if (!node) return null;
    return { addedNodes: [node], target: root };
  } catch (_) {
    return null;
  }
}

const clf = new OnlineNBClassifier();

let malCount = 0, benCount = 0, skipCount = 0;

console.log(`[pretrain] Training on ${payloads.length} XSS payloads...`);
for (const payload of payloads) {
  const mutation = simulateMutation(payload);
  if (!mutation) { skipCount++; continue; }
  const features = extractFeatures(mutation);
  clf.update(features, 'malicious');
  malCount++;
}

console.log(`[pretrain] Training on ${benignStrings.length} benign strings...`);
for (const benign of benignStrings) {
  const mutation = simulateMutation(benign);
  if (!mutation) { skipCount++; continue; }
  const features = extractFeatures(mutation);
  clf.update(features, 'benign');
  benCount++;
}

mkdirSync(join(__dirname, '../dist'), { recursive: true });
const outPath = join(__dirname, '../dist/seed_model.json');
writeFileSync(outPath, clf.serialize());

const sizeBytes = clf.serialize().length;
console.log(`\n✅ Seed model written to dist/seed_model.json`);
console.log(`   Malicious samples: ${malCount}`);
console.log(`   Benign samples:    ${benCount}`);
console.log(`   Skipped:           ${skipCount}`);
console.log(`   Model JSON size:   ${sizeBytes} bytes`);
