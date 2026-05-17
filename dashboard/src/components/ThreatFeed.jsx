import React from 'react';
import { format } from 'date-fns';

export default function ThreatFeed({ events }) {
  const recentEvents = [...events].reverse().slice(0, 50);

  return (
    <div style={{
      marginTop: '1rem', background: '#1a1a1a', padding: '1rem',
      borderRadius: '8px', border: '1px solid #2a2a2a'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.8rem' }}>
        <h2 style={{ fontSize: '0.85rem', color: '#666', textTransform: 'uppercase', letterSpacing: '0.1em', margin: 0 }}>
          Live Threat Feed
        </h2>
        <span style={{ fontSize: '0.75rem', color: '#444' }}>
          {recentEvents.length} / {events.length} events shown
        </span>
      </div>

      <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
        <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #2a2a2a', position: 'sticky', top: 0, background: '#1a1a1a' }}>
              <Th>Time</Th>
              <Th>Session</Th>
              <Th>Label</Th>
              <Th>Prob</Th>
              <Th>Lat (ms)</Th>
              <Th>Top Feature</Th>
            </tr>
          </thead>
          <tbody>
            {recentEvents.map((evt, idx) => {
              const isMalicious = evt.label === 'malicious';
              // Identify the highest-valued feature for visual insight
              const features = Array.isArray(evt.features) ? evt.features : [];
              const featureNames = ['tag_risk','attr_delta','script_inj','handler','url_anom','data_uri','depth','entropy'];
              const maxIdx = features.reduce((best, v, i) => v > (features[best] || 0) ? i : best, 0);
              const topFeat = features.length ? `${featureNames[maxIdx]}=${features[maxIdx].toFixed(2)}` : '—';

              return (
                <tr key={`${evt.timestamp}-${idx}`} style={{
                  background: isMalicious ? 'rgba(239,68,68,0.08)' : 'transparent',
                  borderBottom: '1px solid #222',
                  transition: 'background 0.2s'
                }}>
                  <td style={{ padding: '0.4rem 0.5rem', color: '#666', fontVariantNumeric: 'tabular-nums' }}>
                    {format(new Date(evt.timestamp), 'HH:mm:ss.SSS')}
                  </td>
                  <td style={{ color: '#888', maxWidth: '90px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {evt.sessionId.slice(5, 13)}…
                  </td>
                  <td>
                    <span style={{
                      display: 'inline-block',
                      color:      isMalicious ? '#ef4444' : '#22c55e',
                      background: isMalicious ? 'rgba(239,68,68,0.18)' : 'rgba(34,197,94,0.15)',
                      padding: '0.1rem 0.45rem', borderRadius: '3px',
                      fontWeight: 'bold', fontSize: '0.72rem', letterSpacing: '0.05em'
                    }}>
                      {isMalicious ? '⚠ XSS' : '✓ OK'}
                    </span>
                  </td>
                  <td style={{ fontVariantNumeric: 'tabular-nums', color: isMalicious ? '#ef4444' : '#888' }}>
                    {evt.probability.toFixed(3)}
                  </td>
                  <td style={{ color: '#888', fontVariantNumeric: 'tabular-nums' }}>
                    {typeof evt.latencyMs === 'number' ? evt.latencyMs.toFixed(2) : '—'}
                  </td>
                  <td style={{ color: '#555', fontSize: '0.75rem' }}>
                    {topFeat}
                  </td>
                </tr>
              );
            })}
            {recentEvents.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: '1.5rem', textAlign: 'center', color: '#444' }}>
                  No events recorded yet — open the demo page and inject a payload.
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
