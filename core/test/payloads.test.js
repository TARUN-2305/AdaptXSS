// core/test/payloads.test.js
// Fixture-driven integration tests — reads from test/payloads/*.html
// XSS files must score >= threshold; benign files must score < threshold

import { JSDOM }             from 'jsdom';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname }     from 'path';
import { fileURLToPath }     from 'url';
import { extractFeatures }   from '../src/extractor.js';
import { OnlineNBClassifier } from '../src/classifier.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PAYLOADS_DIR = join(__dirname, 'payloads');

// Polyfill localStorage
global.localStorage = {
  _store: {},
  getItem(k)    { return this._store[k] ?? null; },
  setItem(k, v) { this._store[k] = String(v); },
  removeItem(k) { delete this._store[k]; },
  clear()       { this._store = {}; }
};

function makeMutation(html) {
  const dom = new JSDOM('<!DOCTYPE html><html><body><div id="root"></div></body></html>');
  const root = dom.window.document.getElementById('root');
  const wrapper = dom.window.document.createElement('div');
  wrapper.innerHTML = html.trim();
  const node = wrapper.firstChild || wrapper;
  return { addedNodes: [node], target: root };
}

// Pre-train classifier on the dataset for reliable fixture-level results
function buildWarmClassifier() {
  global.localStorage.clear();
  const clf = new OnlineNBClassifier();
  const xssPayloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<a href="javascript:alert(1)">x</a>',
    '<iframe src="javascript:void(0)">',
    '<img src="data:text/html,<h1>x</h1>">',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<math><script>alert(1)</script></math>',
  ];
  const benignSamples = [
    '<div>Hello</div>',
    '<p>Normal paragraph</p>',
    '<img src="logo.png" alt="Logo">',
    '<a href="https://example.com">Link</a>',
    '<form action="/submit" method="POST">',
    '<button type="button">Click me</button>',
  ];
  for (let i = 0; i < 30; i++) {
    for (const p of xssPayloads)   clf.update(extractFeatures(makeMutation(p)), 'malicious');
    for (const b of benignSamples) clf.update(extractFeatures(makeMutation(b)), 'benign');
  }
  return clf;
}

describe('Fixture-driven payload tests', () => {
  let clf;

  beforeAll(() => { clf = buildWarmClassifier(); });

  const files = readdirSync(PAYLOADS_DIR).filter(f => f.endsWith('.html'));

  for (const file of files) {
    const isXSS    = file.startsWith('xss_');
    const isBenign = file.startsWith('benign_');
    if (!isXSS && !isBenign) return;

    test(`${file} → ${isXSS ? 'MALICIOUS' : 'BENIGN'}`, () => {
      const html = readFileSync(join(PAYLOADS_DIR, file), 'utf-8').trim();
      const features = extractFeatures(makeMutation(html));
      const { label, probability } = clf.predict(features);

      if (isXSS) {
        expect(label).toBe('malicious');
        expect(probability).toBeGreaterThan(0.5);
      } else {
        expect(label).toBe('benign');
        expect(probability).toBeLessThan(0.5);
      }
    });
  }
});
