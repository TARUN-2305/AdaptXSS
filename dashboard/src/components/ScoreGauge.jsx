import React from 'react';
import { RadialBarChart, RadialBar, Legend, Tooltip, ResponsiveContainer } from 'recharts';

export default function ScoreGauge({ stats }) {
  const malPct = stats.total > 0 ? (stats.malicious / stats.total) * 100 : 0;
  
  const data = [
    { name: 'Benign', uv: 100 - malPct, fill: '#22c55e' },
    { name: 'Malicious', uv: malPct, fill: '#ef4444' }
  ];

  return (
    <div style={{ background: '#1a1a1a', padding: '1rem', borderRadius: '8px', height: '200px' }}>
      <h2 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Threat Ratio</h2>
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart cx="50%" cy="50%" innerRadius="30%" outerRadius="100%" barSize={10} data={data}>
          <RadialBar minAngle={15} background clockWise dataKey="uv" />
          <Legend iconSize={10} layout="vertical" verticalAlign="middle" wrapperStyle={{ right: 0 }} />
          <Tooltip contentStyle={{ background: '#333', border: 'none' }} itemStyle={{ color: '#fff' }} />
        </RadialBarChart>
      </ResponsiveContainer>
    </div>
  );
}
