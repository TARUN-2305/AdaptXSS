// core/src/reporter.js
// Sends a classified event to the backend with exponential backoff retry.
// Silent on all failures — the security monitor must never crash the host application.

/**
 * @param {string} endpoint — Full URL to POST to
 * @param {object} event    — Classified event payload
 * @param {number} [retries=3] — Max retry attempts
 */
export async function report(endpoint, event, retries = 3) {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const res = await fetch(endpoint, {
        method:    'POST',
        headers:   { 'Content-Type': 'application/json' },
        body:      JSON.stringify(event),
        keepalive: true   // survives page unload / navigation
      });
      if (res.ok) return; // success — stop retrying
      // Non-2xx response (e.g. 400 validation error) — don't retry
      if (res.status >= 400 && res.status < 500) return;
    } catch (_) {
      // Network error — wait then retry with exponential backoff
      if (attempt < retries - 1) {
        await new Promise(r => setTimeout(r, 150 * Math.pow(2, attempt)));
      }
    }
  }
}
