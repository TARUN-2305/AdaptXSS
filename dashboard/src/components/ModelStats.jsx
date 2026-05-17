import React from 'react';

export default function ModelStats({ stats, backendUrl }) {
  const malPct = stats.total > 0 ? (stats.malicious / stats.total) * 100 : 0;
  const avgLat = typeof stats.avgLatencyMs === 'number' ? stats.avgLatencyMs.toFixed(2) : '—';
  const p99Lat = typeof stats.p99LatencyMs === 'number' ? stats.p99LatencyMs.toFixed(2) : '—';

  function downloadXML() {
    window.open(`${backendUrl}/api/model-xml`, '_blank');
  }

  function downloadJSON() {
    window.open(`${backendUrl}/api/export`, '_blank');
  }

  return (
    <div style={{
      background: '#1a1a1a', padding: '1rem', borderRadius: '8px',
      border: '1px solid #2a2a2a', display: 'flex', flexDirection: 'column'
    }}>
      <h2 style={{ fontSize: '0.85rem', color: '#666', textTransform: 'uppercase',
                   letterSpacing: '0.1em', marginBottom: '0.8rem', margin: '0 0 0.8rem' }}>
        Global Statistics
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.8rem', flex: 1 }}>
        <Stat label="Total Events"   value={stats.total.toLocaleString()} />
        <Stat label="Malicious %"    value={`${malPct.toFixed(1)}%`}
              valueColor={malPct > 0 ? '#ef4444' : '#e2e8f0'} />
        <Stat label="Active Sessions" value={stats.sessions} />
        <Stat label="Safe Events"    value={stats.benign.toLocaleString()} valueColor="#22c55e" />
        <Stat label="Avg Latency"    value={`${avgLat} ms`} valueColor="#f97316" />
        <Stat label="P99 Latency"    value={`${p99Lat} ms`} valueColor="#f97316" />
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.8rem', flexWrap: 'wrap' }}>
        <button onClick={downloadXML} style={btnStyle('#f97316')}>
          ↓ Export Rules (XML)
        </button>
        <button onClick={downloadJSON} style={btnStyle('#3b82f6')}>
          ↓ Export Events (JSON)
        </button>
      </div>
    </div>
  );
}

function Stat({ label, value, valueColor }) {
  return (
    <div>
      <div style={{ fontSize: '0.75rem', color: '#666', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {label}
      </div>
      <div style={{ fontSize: '1.4rem', fontWeight: 'bold', color: valueColor || '#e2e8f0', lineHeight: 1.2 }}>
        {value}
      </div>
    </div>
  );
}

function btnStyle(bg) {
  return {
    padding: '0.4rem 0.8rem', background: bg, color: '#fff',
    border: 'none', borderRadius: '4px', cursor: 'pointer',
    fontFamily: 'monospace', fontWeight: 'bold', fontSize: '0.78rem'
  };
}
