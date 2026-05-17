const MAX = parseInt(process.env.MAX_EVENTS_STORED || '10000');
const store = { events: [], sessions: {} };

export function addEvent(event) {
  store.events.push(event);
  // Circular buffer: remove oldest event AND remove from its session bucket
  if (store.events.length > MAX) {
    const oldest = store.events.shift();
    if (oldest && store.sessions[oldest.sessionId]) {
      const bucket = store.sessions[oldest.sessionId];
      const idx = bucket.indexOf(oldest);
      if (idx !== -1) bucket.splice(idx, 1);
      if (bucket.length === 0) delete store.sessions[oldest.sessionId];
    }
  }
  if (!store.sessions[event.sessionId]) store.sessions[event.sessionId] = [];
  store.sessions[event.sessionId].push(event);
}

export function getAll() { return store.events; }

export function getBySession(sessionId) {
  return store.sessions[sessionId] || [];
}

export function getStats() {
  const total = store.events.length;
  const malicious = store.events.filter(e => e.label === 'malicious').length;
  const latencies = store.events.map(e => e.latencyMs).filter(l => typeof l === 'number' && !isNaN(l));
  const avgLatencyMs = latencies.length
    ? latencies.reduce((a, b) => a + b, 0) / latencies.length
    : 0;
  const p99LatencyMs = latencies.length
    ? [...latencies].sort((a, b) => a - b)[Math.floor(latencies.length * 0.99)] || 0
    : 0;

  return {
    total,
    malicious,
    benign: total - malicious,
    sessions: Object.keys(store.sessions).length,
    avgProbability: total
      ? store.events.reduce((s, e) => s + (e.probability || 0), 0) / total
      : 0,
    avgLatencyMs: parseFloat(avgLatencyMs.toFixed(3)),
    p99LatencyMs: parseFloat(p99LatencyMs.toFixed(3))
  };
}

// For testing: reset store between test runs
export function _resetStore() {
  store.events.length = 0;
  Object.keys(store.sessions).forEach(k => delete store.sessions[k]);
}
