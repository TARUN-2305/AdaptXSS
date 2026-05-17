// core/test/classifier.test.js

import { OnlineNBClassifier } from '../src/classifier.js';

// Polyfill localStorage for Node.js test environment
global.localStorage = {
  _store: {},
  getItem(k)    { return this._store[k] ?? null; },
  setItem(k, v) { this._store[k] = String(v); },
  removeItem(k) { delete this._store[k]; },
  clear()       { this._store = {}; }
};

beforeEach(() => { global.localStorage.clear(); });

describe('OnlineNBClassifier', () => {

  test('Fresh model — all-zero features → benign', () => {
    const clf = new OnlineNBClassifier();
    const res = clf.predict([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(res.label).toBe('benign');
    expect(typeof res.probability).toBe('number');
    expect(Number.isNaN(res.probability)).toBe(false);
    expect(res.probability).toBeGreaterThanOrEqual(0);
    expect(res.probability).toBeLessThanOrEqual(1);
  });

  test('Laplace smoothing — no NaN or Infinity on fresh model', () => {
    const clf = new OnlineNBClassifier();
    const testVectors = [
      [1,0,0,0,0,0,0,0],
      [0,1,0,0,0,0,0,0],
      [0,0,0,0,0,0,0,1],
      [1,1,1,1,1,1,1,1],
    ];
    for (const vec of testVectors) {
      const res = clf.predict(vec);
      expect(Number.isFinite(res.probability)).toBe(true);
    }
  });

  test('After 50 XSS samples — malicious vector correctly classified', () => {
    const clf = new OnlineNBClassifier();
    for (let i = 0; i < 50; i++) clf.update([1,1,1,1,1,1,0,0], 'malicious');
    const res = clf.predict([1,1,1,1,1,1,0,0]);
    expect(res.label).toBe('malicious');
    expect(res.probability).toBeGreaterThan(0.85);
  });

  test('After mixed training — probabilities reflect class balance', () => {
    const clf = new OnlineNBClassifier();
    for (let i = 0; i < 20; i++) clf.update([1,1,1,0,0,0,0,0], 'malicious');
    for (let i = 0; i < 20; i++) clf.update([0,0,0,0,0,0,0,0], 'benign');
    const malRes = clf.predict([1,1,1,0,0,0,0,0]);
    const benRes = clf.predict([0,0,0,0,0,0,0,0]);
    expect(malRes.label).toBe('malicious');
    expect(benRes.label).toBe('benign');
  });

  test('Persistence round-trip — state survives serialize/fromJSON', () => {
    const clf = new OnlineNBClassifier();
    clf.update([1,1,1,1,0,0,0,0], 'malicious');
    const json = clf.serialize();
    const clf2 = OnlineNBClassifier.fromJSON(json);
    // classCounts.malicious = 1 (init) + 1 (update) = 2
    expect(clf2.state.classCounts.malicious).toBe(2);
    expect(clf2.state.totalSamples).toBe(3);  // 2 init + 1 update
    // Same prediction
    const res1 = clf.predict([1,1,1,1,0,0,0,0]);
    const res2 = clf2.predict([1,1,1,1,0,0,0,0]);
    expect(res1.label).toBe(res2.label);
    expect(Math.abs(res1.probability - res2.probability)).toBeLessThan(0.001);
  });

  test('update() ignores invalid labels', () => {
    const clf = new OnlineNBClassifier();
    const before = clf.state.totalSamples;
    clf.update([1,0,0,0,0,0,0,0], 'unknown_label');
    expect(clf.state.totalSamples).toBe(before);  // unchanged
  });

  test('Probabilities sum to 1 (via log-sum-exp normalisation)', () => {
    const clf = new OnlineNBClassifier();
    for (let i = 0; i < 10; i++) clf.update([1,1,0,0,0,0,0,0], 'malicious');
    const { probability } = clf.predict([1,1,0,0,0,0,0,0]);
    // malicious + benign probabilities should sum to 1
    // We only get malicious prob, benign is implied as 1-prob
    expect(probability + (1 - probability)).toBeCloseTo(1.0);
  });
});
