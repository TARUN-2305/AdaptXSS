import { OnlineNBClassifier } from '../src/classifier.js';

// Polyfill localStorage for Node.js test env
global.localStorage = {
  store: {},
  getItem(key) { return this.store[key] || null; },
  setItem(key, value) { this.store[key] = value.toString(); },
  clear() { this.store = {}; }
};

describe('classifier', () => {
  beforeEach(() => {
    global.localStorage.clear();
  });

  test('Fresh model predicts benign', () => {
    const clf = new OnlineNBClassifier();
    const res = clf.predict([0,0,0,0,0,0,0,0]);
    expect(res.label).toBe('benign');
    expect(res.probability).toBeLessThan(0.6);
  });

  test('After training 50 XSS samples', () => {
    const clf = new OnlineNBClassifier();
    for(let i=0; i<50; i++) clf.update([1,1,1,1,1,1,0,0], 'malicious');
    const res = clf.predict([1,1,1,1,1,1,0,0]);
    expect(res.label).toBe('malicious');
    expect(res.probability).toBeGreaterThan(0.85);
  });

  test('Persistence round-trip', () => {
    const clf = new OnlineNBClassifier();
    clf.update([1,1,1,1,0,0,0,0], 'malicious');
    const json = clf.serialize();
    const clf2 = OnlineNBClassifier.fromJSON(json);
    expect(clf2.state.classCounts.malicious).toBe(2); // 1 init + 1 update
  });

  test('Laplace smoothing', () => {
    const clf = new OnlineNBClassifier();
    const res = clf.predict([1,0,0,0,0,0,0,0]);
    expect(Number.isNaN(res.probability)).toBe(false);
  });
});
