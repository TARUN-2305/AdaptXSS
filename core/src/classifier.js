// core/src/classifier.js
// Online incremental Bernoulli Naive Bayes classifier
// Persists model state to localStorage between page loads

// Initial state with Laplace prior (1 pseudo-count per class)
const DEFAULT_STATE = {
  classCounts:   { malicious: 1, benign: 1 },
  featureCounts: {
    malicious: new Array(8).fill(1),
    benign:    new Array(8).fill(1),
  },
  totalSamples: 2,
  version: 1
};

export class OnlineNBClassifier {
  constructor() {
    this.state = this._load() || this._defaultState();
  }

  /**
   * Classify a feature vector.
   * @param {Float32Array|number[]} features — 8-dimensional vector in [0,1]
   * @returns {{ label: 'malicious'|'benign', probability: number }}
   */
  predict(features) {
    const classes = ['malicious', 'benign'];
    const logProbs = {};

    for (const cls of classes) {
      const N_c   = this.state.classCounts[cls];   // total samples of this class
      const prior = Math.log(N_c / this.state.totalSamples);
      let likelihood = 0;

      for (let i = 0; i < 8; i++) {
        const present = features[i] > 0.5 ? 1 : 0;
        const N_ic = this.state.featureCounts[cls][i];
        // Bernoulli NB Laplace smoothing: p = (N_ic + 1) / (N_c + 2)
        const p = (N_ic + 1) / (N_c + 2);
        likelihood += present ? Math.log(p) : Math.log(1 - p);
      }
      logProbs[cls] = prior + likelihood;
    }

    // Log-sum-exp for numerical stability
    const maxLogP = Math.max(...Object.values(logProbs));
    const expSum  = Object.values(logProbs).reduce((s, lp) => s + Math.exp(lp - maxLogP), 0);
    const maliciousProb = Math.exp(logProbs.malicious - maxLogP) / expSum;

    return {
      label: maliciousProb > 0.5 ? 'malicious' : 'benign',
      probability: maliciousProb
    };
  }

  /**
   * Online update — call after a confirmed label is known.
   * @param {Float32Array|number[]} features
   * @param {'malicious'|'benign'} trueLabel
   */
  update(features, trueLabel) {
    if (!['malicious', 'benign'].includes(trueLabel)) return;
    this.state.classCounts[trueLabel]++;
    this.state.totalSamples++;
    for (let i = 0; i < 8; i++) {
      if (features[i] > 0.5) this.state.featureCounts[trueLabel][i]++;
    }
    this._save();
  }

  /** Serialize model state as JSON string */
  serialize() {
    return JSON.stringify(this.state);
  }

  /** Restore from serialized JSON string */
  static fromJSON(json) {
    const c = new OnlineNBClassifier();
    c.state = JSON.parse(json);
    return c;
  }

  _save() {
    try { localStorage.setItem('adaptxss_model', this.serialize()); } catch (_) {}
  }

  _load() {
    try {
      const stored = localStorage.getItem('adaptxss_model');
      if (stored) return JSON.parse(stored);
      // Fallback to compile-time seed (injected by build.js via esbuild --define)
      if (typeof SEED_MODEL_JSON !== 'undefined' && SEED_MODEL_JSON) {
        return JSON.parse(atob(SEED_MODEL_JSON));
      }
    } catch (_) {}
    return null;
  }

  _defaultState() {
    return {
      classCounts:   { malicious: 1, benign: 1 },
      featureCounts: {
        malicious: new Array(8).fill(1),
        benign:    new Array(8).fill(1),
      },
      totalSamples: 2,
      version: 1
    };
  }
}
