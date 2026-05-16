import React from 'react';
import { format } from 'date-fns';

export default function ThreatFeed({ events }) {
  // latest 50
  const recentEvents = [...events].reverse().slice(0, 50);

  return (
    <div style={{ marginTop: '2rem', background: '#1a1a1a', padding: '1rem', borderRadius: '8px' }}>
      <h2 style={{ fontSize: '1.2rem', marginBottom: '1rem' }}>Live Threat Feed</h2>
      <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
        <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #333' }}>
              <th style={{ padding: '0.5rem' }}>Timestamp</th>
              <th>Session ID</th>
              <th>Label</th>
              <th>Probability</th>
              <th>Latency (ms)</th>
            </tr>
          </thead>
          <tbody>
            {recentEvents.map((evt, idx) => {
              const isMalicious = evt.label === 'malicious';
              return (
                <tr key={idx} style={{ 
                  background: isMalicious ? 'rgba(239,68,68,0.1)' : 'transparent',
                  borderBottom: '1px solid #2a2a2a'
                }}>
                  <td style={{ padding: '0.5rem' }}>{format(new Date(evt.timestamp), 'HH:mm:ss.SSS')}</td>
                  <td>{evt.sessionId.substring(0, 8)}...</td>
                  <td>
                    <span style={{ 
                      color: isMalicious ? '#ef4444' : '#22c55e',
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      background: isMalicious ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)'
                    }}>
                      {evt.label.toUpperCase()}
                    </span>
                  </td>
                  <td>{evt.probability.toFixed(4)}</td>
                  <td>{evt.latencyMs.toFixed(2)}</td>
                </tr>
              );
            })}
            {recentEvents.length === 0 && (
              <tr><td colSpan="5" style={{ padding: '1rem', textAlign: 'center' }}>No events recorded yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
