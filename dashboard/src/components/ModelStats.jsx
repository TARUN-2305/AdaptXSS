import React, { useMemo } from 'react';

export default function ModelStats({ stats }) {
  const malPct = stats.total > 0 ? (stats.malicious / stats.total) * 100 : 0;
  // Note: the original plan mentioned pulling latencies from events. 
  // We'll just show the server stats and hardcode latencies to 0 if not provided
  const avgLatency = stats.avgLatencyMs || 0;
  const p99Latency = stats.p99LatencyMs || 0;

  return (
    <div style={{ background: '#1a1a1a', padding: '1rem', borderRadius: '8px', height: '200px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      <h2 style={{ fontSize: '1.1rem', marginBottom: '1rem' }}>Global Statistics</h2>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <div style={{ fontSize: '0.9rem', color: '#888' }}>Total Events</div>
          <div style={{ fontSize: '1.5rem' }}>{stats.total.toLocaleString()}</div>
        </div>
        <div>
          <div style={{ fontSize: '0.9rem', color: '#888' }}>Malicious %</div>
          <div style={{ fontSize: '1.5rem', color: malPct > 0 ? '#ef4444' : '#e2e8f0' }}>{malPct.toFixed(1)}%</div>
        </div>
        <div>
          <div style={{ fontSize: '0.9rem', color: '#888' }}>Active Sessions</div>
          <div style={{ fontSize: '1.5rem' }}>{stats.sessions}</div>
        </div>
        <div>
          <div style={{ fontSize: '0.9rem', color: '#888' }}>Safe Events</div>
          <div style={{ fontSize: '1.5rem', color: '#22c55e' }}>{stats.benign.toLocaleString()}</div>
        </div>
      </div>
      <button onClick={() => window.open('http://localhost:4000/api/model-xml')} style={{ marginTop: '1rem', padding: '0.5rem', background: '#f97316', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}>Export Rules as XML</button>
    </div>
  );
}
