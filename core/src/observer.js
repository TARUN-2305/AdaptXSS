// core/src/observer.js
import { extractFeatures } from './extractor.js';
import { OnlineNBClassifier } from './classifier.js';
import { report } from './reporter.js';

export class AdaptXSSObserver {
  /**
   * @param {object} options
   * @param {number}   [options.threshold=0.65]  — Probability above which onAlert fires
   * @param {string}   [options.reportUrl=null]  — Backend POST endpoint (null = no reporting)
   * @param {string}   [options.endpoint=null]   — Alias for reportUrl (backward compat)
   * @param {function} [options.onAlert=null]    — Callback(event) on malicious classification
   * @param {number}   [options.debounceMs=0]    — Min ms between consecutive mutation processes
   * @param {number}   [options.maxRetries=3]    — Retry count for failed fetch calls
   */
  constructor(options = {}) {
    this.classifier  = new OnlineNBClassifier();
    this.threshold   = options.threshold  ?? 0.65;
    // Accept both 'reportUrl' (documented) and 'endpoint' (legacy)
    this.reportUrl   = options.reportUrl  || options.endpoint || null;
    this.onAlert     = options.onAlert    || null;
    this.debounceMs  = options.debounceMs ?? 0;
    this.maxRetries  = options.maxRetries ?? 3;
    this.sessionId   = this._genSession();
    this._observer   = null;
    this._lastMutTs  = 0;
    this._stats      = { total: 0, alerts: 0, latencies: [] };
  }

  /**
   * Attach the MutationObserver to a DOM element.
   * @param {Element} [root=document.body]
   */
  attach(root) {
    if (!root && typeof document !== 'undefined') root = document.body;
    if (!root) { console.warn('[AdaptXSS] No root element — observer not attached.'); return; }

    this._observer = new MutationObserver((mutations) => {
      // Debounce: skip if within debounceMs of last processed mutation batch
      const now = Date.now();
      if (this.debounceMs > 0 && (now - this._lastMutTs) < this.debounceMs) return;
      this._lastMutTs = now;

      for (const mutation of mutations) {
        const t0 = performance.now();
        const features = extractFeatures(mutation);
        const { label, probability } = this.classifier.predict(features);
        const latency = performance.now() - t0;

        this._stats.total++;
        this._stats.latencies.push(latency);
        // Keep latencies array bounded to last 1000 for memory safety
        if (this._stats.latencies.length > 1000) this._stats.latencies.shift();

        if (probability >= this.threshold) {
          this._stats.alerts++;
          const evt = {
            timestamp:  Date.now(),
            sessionId:  this.sessionId,
            label,
            probability,
            features:   Array.from(features),
            mutation: {
              type:       mutation.type,
              targetTag:  mutation.target ? mutation.target.nodeName : 'UNKNOWN',
              addedCount: mutation.addedNodes.length
            },
            latencyMs: latency
          };
          if (this.onAlert)   this.onAlert(evt);
          if (this.reportUrl) report(this.reportUrl, evt, this.maxRetries);
        }
      }
    });

    this._observer.observe(root, {
      childList:       true,
      subtree:         true,
      attributes:      true,
      attributeFilter: [
        'href','src','onerror','onclick','onload','onmouseover',
        'onfocus','action','formaction','xlink:href','onkeyup',
        'onmouseenter','onsubmit','oninput','onchange'
      ]
    });

    console.log(`[AdaptXSS] Observer attached to <${root.nodeName}>. Session: ${this.sessionId}`);
  }

  /** Disconnect the observer */
  detach() {
    if (this._observer) { this._observer.disconnect(); this._observer = null; }
  }

  /** Returns performance statistics for this session */
  getStats() {
    const lats = this._stats.latencies;
    const sorted = lats.length ? [...lats].sort((a, b) => a - b) : [];
    return {
      total:         this._stats.total,
      alerts:        this._stats.alerts,
      avgLatencyMs:  sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : 0,
      p99LatencyMs:  sorted.length ? sorted[Math.floor(sorted.length * 0.99)] || sorted[sorted.length - 1] : 0,
      sessionId:     this.sessionId
    };
  }

  _genSession() {
    return 'sess_' + Math.random().toString(36).slice(2, 11) + '_' + Date.now();
  }
}
