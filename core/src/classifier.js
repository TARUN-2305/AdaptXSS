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
      const stored = localStorage.getItem('adaptxss_model');
      if (stored) return JSON.parse(stored);
      // Fallback to compile-time seed
      if (typeof SEED_MODEL_JSON !== 'undefined') {
        return JSON.parse(atob(SEED_MODEL_JSON));
      }
    } catch(_) {}
    return null;
  }
}
