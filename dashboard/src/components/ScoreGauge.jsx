import React from 'react';
import { RadialBarChart, RadialBar, Tooltip, ResponsiveContainer, PolarAngleAxis } from 'recharts';

export default function ScoreGauge({ stats }) {
  const malPct = stats.total > 0 ? parseFloat(((stats.malicious / stats.total) * 100).toFixed(1)) : 0;
  const benPct = 100 - malPct;

  const data = [
    { name: 'Benign',    value: benPct,  fill: '#22c55e' },
    { name: 'Malicious', value: malPct,  fill: '#ef4444' },
  ];

  const threatLevel = malPct === 0 ? 'CLEAR' : malPct < 20 ? 'LOW' : malPct < 50 ? 'MEDIUM' : 'HIGH';
  const levelColor  = malPct === 0 ? '#22c55e' : malPct < 20 ? '#f97316' : malPct < 50 ? '#eab308' : '#ef4444';

  return (
    <div style={{
      background: '#1a1a1a', padding: '1rem', borderRadius: '8px',
      border: '1px solid #2a2a2a', position: 'relative'
    }}>
      <h2 style={{ fontSize: '0.85rem', color: '#666', textTransform: 'uppercase',
                   letterSpacing: '0.1em', margin: '0 0 0.5rem' }}>
        Threat Ratio
      </h2>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {/* Gauge */}
        <div style={{ height: '140px', flex: 1 }}>
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              cx="50%" cy="100%" innerRadius="60%" outerRadius="100%"
              barSize={14} data={data}
              startAngle={180} endAngle={0}
            >
              <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
              <RadialBar minAngle={2} background={{ fill: '#111' }} clockWise dataKey="value" />
              <Tooltip
                contentStyle={{ background: '#222', border: '1px solid #333', borderRadius: '6px', fontSize: '0.8rem' }}
                itemStyle={{ color: '#e2e8f0' }}
                formatter={(v, n) => [`${v.toFixed(1)}%`, n]}
              />
            </RadialBarChart>
          </ResponsiveContainer>
        </div>

        {/* Threat level */}
        <div style={{ textAlign: 'center', minWidth: '80px' }}>
          <div style={{ fontSize: '0.72rem', color: '#555', textTransform: 'uppercase', marginBottom: '0.3rem' }}>
            Threat Level
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 'bold', color: levelColor }}>{threatLevel}</div>
          <div style={{ fontSize: '1.1rem', color: '#ef4444', marginTop: '0.3rem' }}>{malPct.toFixed(1)}%</div>
          <div style={{ fontSize: '0.72rem', color: '#555' }}>malicious</div>
          <div style={{ marginTop: '0.6rem', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <div style={{ fontSize: '0.72rem' }}>
              <span style={{ color: '#ef4444' }}>■</span>
              <span style={{ color: '#666' }}> {stats.malicious} XSS</span>
            </div>
            <div style={{ fontSize: '0.72rem' }}>
              <span style={{ color: '#22c55e' }}>■</span>
              <span style={{ color: '#666' }}> {stats.benign} safe</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
