import { useState } from 'react';
import ThreatFeed from './components/ThreatFeed';
import ScoreGauge from './components/ScoreGauge';
import SessionTable from './components/SessionTable';
import ModelStats from './components/ModelStats';
import { useEvents } from './hooks/useEvents';

// Backend URL — change this if your backend runs on a different port/host
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000';

export default function App() {
  const { events, stats, loading, error } = useEvents(BACKEND_URL);

  return (
    <div style={{
      fontFamily: "'Courier New', monospace",
      padding: '1.2rem',
      background: '#0d0d0d',
      minHeight: '100vh',
      color: '#e2e8f0'
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '1rem', marginBottom: '0.25rem' }}>
        <h1 style={{ fontSize: '1.5rem', color: '#f97316', margin: 0 }}>
          ⚡ AdaptXSS
        </h1>
        <span style={{ fontSize: '0.85rem', color: '#666' }}>
          Live Threat Monitor · polling {BACKEND_URL}
        </span>
      </div>
      <p style={{ fontSize: '0.78rem', color: '#555', margin: '0 0 1.2rem' }}>
        Adaptive DOM-Based XSS Detection · MutationObserver + Online Naive Bayes · &lt;10 KB
      </p>

      {/* Connection status banner */}
      {error && (
        <div style={{
          background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: '6px', padding: '0.6rem 1rem', marginBottom: '1rem',
          fontSize: '0.82rem', color: '#ef4444'
        }}>
          ⚠ Backend unreachable at {BACKEND_URL} — start the Node.js server with{' '}
          <code style={{ background: '#111', padding: '0 4px', borderRadius: '3px' }}>
            cd backend &amp;&amp; node src/server.js
          </code>
        </div>
      )}

      {/* Loading indicator */}
      {loading && !error && (
        <div style={{ color: '#666', fontSize: '0.82rem', marginBottom: '1rem' }}>
          Connecting to backend…
        </div>
      )}

      {/* Top stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
        <ScoreGauge stats={stats} />
        <ModelStats stats={stats} backendUrl={BACKEND_URL} />
      </div>

      {/* Tables */}
      <ThreatFeed events={events} />
      <SessionTable events={events} />

      {/* Footer */}
      <div style={{ marginTop: '2rem', borderTop: '1px solid #1e1e1e', paddingTop: '0.8rem',
                    fontSize: '0.72rem', color: '#444', textAlign: 'center' }}>
        AdaptXSS · CS365TDC Web Frameworks · Sem VI · Built with MutationObserver + Online Naive Bayes
      </div>
    </div>
  );
}
