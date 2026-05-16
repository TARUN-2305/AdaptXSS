import { useState, useEffect } from 'react';
import ThreatFeed from './components/ThreatFeed';
import ScoreGauge from './components/ScoreGauge';
import SessionTable from './components/SessionTable';
import ModelStats from './components/ModelStats';
import { useEvents } from './hooks/useEvents';

export default function App() {
  const { events, stats, loading } = useEvents('http://localhost:4000');

  return (
    <div style={{ fontFamily: 'monospace', padding: '1rem', background: '#0d0d0d', minHeight: '100vh', color: '#e2e8f0' }}>
      <h1 style={{ fontSize: '1.4rem', marginBottom: '1rem', color: '#f97316' }}>
        AdaptXSS — Live Threat Monitor
      </h1>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <ScoreGauge stats={stats} />
        <ModelStats stats={stats} />
      </div>
      <ThreatFeed events={events} />
      <SessionTable events={events} />
    </div>
  );
}
