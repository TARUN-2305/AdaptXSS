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
              targetTag: mutation.target ? mutation.target.nodeName : 'unknown',
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
