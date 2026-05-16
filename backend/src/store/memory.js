const MAX = parseInt(process.env.MAX_EVENTS_STORED || '10000');
const store = { events: [], sessions: {} };

export function addEvent(event) {
  store.events.push(event);
  if (store.events.length > MAX) store.events.shift();
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
  return {
    total,
    malicious,
    benign: total - malicious,
    sessions: Object.keys(store.sessions).length,
    avgProbability: total ? store.events.reduce((s,e) => s + e.probability, 0) / total : 0
  };
}
