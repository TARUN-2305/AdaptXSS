// core/src/extractor.js

// High-risk tags. Presence = f0 of 1.0, medium-risk = 0.5, absent = 0.0
const HIGH_RISK_TAGS = new Set(['script','iframe','object','embed','link','meta','base','svg','math']);
const MED_RISK_TAGS  = new Set(['img','video','audio','source','track','input','form','button','a']);

// Dangerous attributes. Any present = f1 increment of 0.25 each, capped at 1.0
const DANGEROUS_ATTRS = ['href','src','action','formaction','xlink:href','data','poster'];

// Inline event handler prefixes
const EVENT_PREFIXES = ['on']; // matches any attribute starting with "on"

export function extractFeatures(mutation) {
  const features = new Float32Array(8);
  const node = mutation.addedNodes.length > 0
    ? mutation.addedNodes[0]
    : mutation.target;

  // f0 — tag risk
  if (node.nodeName) {
    const tag = node.nodeName.toLowerCase();
    if (HIGH_RISK_TAGS.has(tag)) features[0] = 1.0;
    else if (MED_RISK_TAGS.has(tag)) features[0] = 0.5;
  }

  // f1 — dangerous attribute presence
  if (node.attributes) {
    let attrScore = 0;
    for (const attr of node.attributes) {
      if (DANGEROUS_ATTRS.includes(attr.name.toLowerCase())) attrScore += 0.25;
    }
    features[1] = Math.min(attrScore, 1.0);
  }

  // f2 — script injection (innerHTML or text content contains <script)
  const content = node.outerHTML || node.innerHTML || node.textContent || '';
  features[2] = /(<script[\s>]|javascript\s*:)/i.test(content) ? 1 : 0;

  // f3 — inline event handler (any attribute starting with "on")
  if (node.attributes) {
    for (const attr of node.attributes) {
      if (attr.name.toLowerCase().startsWith('on')) { features[3] = 1; break; }
    }
  }

  // f4 — URL anomaly (href/src contains non-http schemes or suspicious keywords)
  const urlAttrs = ['href', 'src', 'action', 'formaction'];
  if (node.attributes) {
    for (const attr of node.attributes) {
      if (urlAttrs.includes(attr.name.toLowerCase())) {
        const val = attr.value.toLowerCase().trim();
        if (/^(javascript|vbscript|data|blob):/.test(val)) features[4] = 1.0;
        else if (/[<>"']/.test(val)) features[4] = 0.7;
      }
    }
  }

  // f5 — data URI flag (img/a with data: URI is high-risk vector)
  if (node.attributes) {
    const src = node.getAttribute && node.getAttribute('src');
    const href = node.getAttribute && node.getAttribute('href');
    if ((src && src.startsWith('data:')) || (href && href.startsWith('data:'))) features[5] = 1;
  }

  // f6 — DOM depth (normalized, max assumed = 20)
  let depth = 0, el = node;
  while (el.parentNode) { depth++; el = el.parentNode; }
  features[6] = Math.min(depth / 20, 1.0);

  // f7 — Shannon entropy of text content
  if (content.length > 0) {
    const freq = {};
    for (const ch of content) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    const len = content.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    features[7] = Math.min(entropy / 8, 1.0); // normalize: max natural entropy ~8 bits
  }

  return features;
}
