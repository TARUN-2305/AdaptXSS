// core/src/extractor.js
// Feature extraction from MutationObserver MutationRecord events

// f0 — tag risk scoring
const HIGH_RISK_TAGS = new Set(['script','iframe','object','embed','link','meta','base','svg','math']);
const MED_RISK_TAGS  = new Set(['img','video','audio','source','track','input','form','button','a']);

// f1 — dangerous attribute presence (use Set for O(1) lookup)
const DANGEROUS_ATTRS_SET = new Set(['href','src','action','formaction','xlink:href','data','poster']);

// f4 — URL-bearing attributes to check for anomalous schemes
const URL_ATTRS_SET = new Set(['href', 'src', 'action', 'formaction']);

/**
 * Extract an 8-dimensional feature vector from a MutationRecord.
 * Returns Float32Array(8) with all values in [0, 1].
 *
 * Features:
 *   f[0] tag_risk         — 1.0 for high-risk tags, 0.5 for medium-risk
 *   f[1] attr_delta       — normalised count of dangerous attributes (cap 1.0)
 *   f[2] script_injection — binary: outerHTML contains <script or javascript:
 *   f[3] inline_handler   — binary: any on* attribute present
 *   f[4] url_anomaly      — score for dangerous URL scheme in href/src/action
 *   f[5] data_uri         — binary: src or href starts with data:
 *   f[6] dom_depth        — normalised DOM depth (max assumed 20)
 *   f[7] text_entropy     — Shannon entropy of outerHTML (normalised)
 */
export function extractFeatures(mutation) {
  const features = new Float32Array(8);

  // Prefer the first added node; fall back to the mutation target
  const node = (mutation.addedNodes && mutation.addedNodes.length > 0)
    ? mutation.addedNodes[0]
    : mutation.target;

  if (!node) return features;

  // ── f0: tag risk ──────────────────────────────────────────────────────────
  if (node.nodeName) {
    const tag = node.nodeName.toLowerCase();
    if (HIGH_RISK_TAGS.has(tag))      features[0] = 1.0;
    else if (MED_RISK_TAGS.has(tag))  features[0] = 0.5;
  }

  // ── f1: dangerous attribute count ─────────────────────────────────────────
  if (node.attributes) {
    let attrScore = 0;
    for (const attr of node.attributes) {
      if (DANGEROUS_ATTRS_SET.has(attr.name.toLowerCase())) attrScore += 0.25;
    }
    features[1] = Math.min(attrScore, 1.0);
  }

  // ── f2 + f7: use outerHTML for full content context ───────────────────────
  const content = node.outerHTML || node.innerHTML || node.textContent || '';

  // f2: script injection signal
  features[2] = /(<script[\s>]|javascript\s*:)/i.test(content) ? 1 : 0;

  // ── f3: inline event handler ───────────────────────────────────────────────
  if (node.attributes) {
    for (const attr of node.attributes) {
      if (attr.name.toLowerCase().startsWith('on')) { features[3] = 1; break; }
    }
  }

  // ── f4: URL anomaly ────────────────────────────────────────────────────────
  if (node.attributes) {
    for (const attr of node.attributes) {
      if (URL_ATTRS_SET.has(attr.name.toLowerCase())) {
        const val = attr.value.toLowerCase().trim();
        if (/^(javascript|vbscript|data|blob):/.test(val)) {
          features[4] = 1.0;
          break;
        } else if (/[<>"']/.test(val)) {
          features[4] = Math.max(features[4], 0.7);
        }
      }
    }
  }

  // ── f5: data URI in src or href ────────────────────────────────────────────
  if (node.getAttribute) {
    const src  = node.getAttribute('src');
    const href = node.getAttribute('href');
    if ((src && src.startsWith('data:')) || (href && href.startsWith('data:'))) {
      features[5] = 1;
    }
  }

  // ── f6: DOM depth (normalised, max=20) ─────────────────────────────────────
  let depth = 0, el = node;
  while (el.parentNode) { depth++; el = el.parentNode; }
  features[6] = Math.min(depth / 20, 1.0);

  // ── f7: Shannon entropy of content ────────────────────────────────────────
  if (content.length > 0) {
    const freq = {};
    for (const ch of content) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    const len = content.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    features[7] = Math.min(entropy / 8, 1.0);
  }

  return features;
}
