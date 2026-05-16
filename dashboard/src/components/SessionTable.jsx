import React, { useMemo } from 'react';
import { format } from 'date-fns';

export default function SessionTable({ events }) {
  const sessions = useMemo(() => {
    const map = {};
    for (const evt of events) {
      if (!map[evt.sessionId]) {
        map[evt.sessionId] = { id: evt.sessionId, count: 0, alerts: 0, first: evt.timestamp, last: evt.timestamp };
      }
      map[evt.sessionId].count++;
      if (evt.label === 'malicious') map[evt.sessionId].alerts++;
      map[evt.sessionId].first = Math.min(map[evt.sessionId].first, evt.timestamp);
      map[evt.sessionId].last = Math.max(map[evt.sessionId].last, evt.timestamp);
    }
    return Object.values(map).sort((a, b) => b.alerts - a.alerts);
  }, [events]);

  return (
    <div style={{ marginTop: '2rem', background: '#1a1a1a', padding: '1rem', borderRadius: '8px' }}>
      <h2 style={{ fontSize: '1.2rem', marginBottom: '1rem' }}>Active Sessions</h2>
      <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #333' }}>
            <th style={{ padding: '0.5rem' }}>Session ID</th>
            <th>Events</th>
            <th>Alerts</th>
            <th>First Seen</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.id} style={{ borderBottom: '1px solid #2a2a2a' }}>
              <td style={{ padding: '0.5rem' }}>{s.id}</td>
              <td>{s.count}</td>
              <td style={{ color: s.alerts > 0 ? '#ef4444' : 'inherit' }}>{s.alerts}</td>
              <td>{format(new Date(s.first), 'HH:mm:ss')}</td>
              <td>{format(new Date(s.last), 'HH:mm:ss')}</td>
            </tr>
          ))}
          {sessions.length === 0 && (
            <tr><td colSpan="5" style={{ padding: '1rem', textAlign: 'center' }}>No sessions active.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
