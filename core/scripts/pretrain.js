import { JSDOM } from 'jsdom';
import { extractFeatures } from '../src/extractor.js';
import { OnlineNBClassifier } from '../src/classifier.js';
import { readFileSync, writeFileSync } from 'fs';

const payloads = readFileSync('../evaluation/datasets/xss_payloads.txt', 'utf-8')
  .split('\n').filter(Boolean).slice(0, 5000);

const benignStrings = readFileSync('../evaluation/datasets/benign_strings.txt', 'utf-8')
  .split('\n').filter(Boolean).slice(0, 5000);

const clf = new OnlineNBClassifier();

function simulateMutation(dom, root, html) {
  const div = dom.window.document.createElement('div');
  div.innerHTML = html;
  const node = div.firstChild;
  if (!node) return null;
  return { addedNodes: [node], target: root };
}

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
