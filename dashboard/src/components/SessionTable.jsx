import React, { useMemo } from 'react';
import { format, formatDistanceToNow } from 'date-fns';

export default function SessionTable({ events }) {
  const sessions = useMemo(() => {
    const map = {};
    for (const evt of events) {
      const sid = evt.sessionId;
      if (!map[sid]) {
        map[sid] = { id: sid, count: 0, alerts: 0, first: evt.timestamp, last: evt.timestamp };
      }
      map[sid].count++;
      if (evt.label === 'malicious') map[sid].alerts++;
      if (evt.timestamp < map[sid].first) map[sid].first = evt.timestamp;
      if (evt.timestamp > map[sid].last)  map[sid].last  = evt.timestamp;
    }
    return Object.values(map).sort((a, b) => b.last - a.last);
  }, [events]);

  return (
    <div style={{
      marginTop: '1rem', background: '#1a1a1a', padding: '1rem',
      borderRadius: '8px', border: '1px solid #2a2a2a'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.8rem' }}>
        <h2 style={{ fontSize: '0.85rem', color: '#666', textTransform: 'uppercase', letterSpacing: '0.1em', margin: 0 }}>
          Active Sessions
        </h2>
        <span style={{ fontSize: '0.75rem', color: '#444' }}>{sessions.length} session(s)</span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #2a2a2a' }}>
              <Th>Session ID</Th>
              <Th>Events</Th>
              <Th>Alerts</Th>
              <Th>Alert Rate</Th>
              <Th>First Seen</Th>
              <Th>Last Active</Th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => {
              const alertRate = s.count > 0 ? ((s.alerts / s.count) * 100).toFixed(0) : 0;
              const isActive = Date.now() - s.last < 10_000; // active in last 10s
              return (
                <tr key={s.id} style={{ borderBottom: '1px solid #1e1e1e' }}>
                  <td style={{ padding: '0.4rem 0.5rem' }}>
                    <span style={{
                      display: 'inline-block', width: '6px', height: '6px',
                      borderRadius: '50%', background: isActive ? '#22c55e' : '#444',
                      marginRight: '0.4rem', verticalAlign: 'middle'
                    }} />
                    <code style={{ fontSize: '0.75rem', color: '#888' }}>
                      {s.id.slice(0, 20)}…
                    </code>
                  </td>
                  <td style={{ color: '#aaa' }}>{s.count}</td>
                  <td style={{ color: s.alerts > 0 ? '#ef4444' : '#666', fontWeight: s.alerts > 0 ? 'bold' : 'normal' }}>
                    {s.alerts}
                  </td>
                  <td>
                    <span style={{
                      background: alertRate > 50 ? 'rgba(239,68,68,0.15)' : alertRate > 0 ? 'rgba(249,115,22,0.12)' : 'rgba(34,197,94,0.1)',
                      color: alertRate > 50 ? '#ef4444' : alertRate > 0 ? '#f97316' : '#22c55e',
                      padding: '0.1rem 0.4rem', borderRadius: '3px', fontSize: '0.75rem'
                    }}>
                      {alertRate}%
                    </span>
                  </td>
                  <td style={{ color: '#555', fontSize: '0.75rem' }}>
                    {format(new Date(s.first), 'HH:mm:ss')}
                  </td>
                  <td style={{ color: '#555', fontSize: '0.75rem' }}>
                    {formatDistanceToNow(new Date(s.last), { addSuffix: true })}
                  </td>
                </tr>
              );
            })}
            {sessions.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: '1.5rem', textAlign: 'center', color: '#444' }}>
                  No sessions active — open the demo page to start monitoring.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Th({ children }) {
  return (
    <th style={{ padding: '0.4rem 0.5rem', fontSize: '0.72rem', color: '#555',
                 textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
      {children}
    </th>
  );
}
