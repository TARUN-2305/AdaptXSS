// core/src/reporter.js

// Sends event to backend with exponential backoff retry
export async function report(endpoint, event, retries = 3) {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
        keepalive: true  // important: survives page unload
      });
      if (res.ok) return;
    } catch (_) {
      await new Promise(r => setTimeout(r, 200 * Math.pow(2, attempt)));
    }
  }
  // Silent failure — security monitor must not crash the host app
}
