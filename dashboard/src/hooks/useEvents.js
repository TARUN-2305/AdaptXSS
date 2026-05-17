import { useState, useEffect, useCallback, useRef } from 'react';

export function useEvents(baseUrl, pollIntervalMs = 2000) {
  const [events, setEvents]   = useState([]);
  const [stats, setStats]     = useState({ total: 0, malicious: 0, benign: 0, sessions: 0, avgLatencyMs: 0, p99LatencyMs: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const controllerRef         = useRef(null);

  const fetchData = useCallback(async () => {
    // Abort any in-flight request before starting a new one
    if (controllerRef.current) controllerRef.current.abort();
    controllerRef.current = new AbortController();
    const signal = controllerRef.current.signal;

    try {
      const [evtsRes, statsRes] = await Promise.all([
        fetch(`${baseUrl}/api/events?limit=200`, { signal }),
        fetch(`${baseUrl}/api/stats`,            { signal })
      ]);

      if (!evtsRes.ok || !statsRes.ok) throw new Error('Server error');

      const [evtsData, statsData] = await Promise.all([
        evtsRes.json(),
        statsRes.json()
      ]);

      setEvents(evtsData);
      setStats(statsData);
      setError(null);
    } catch (err) {
      if (err.name === 'AbortError') return;  // Ignore aborted requests
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [baseUrl]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, pollIntervalMs);
    return () => {
      clearInterval(interval);
      if (controllerRef.current) controllerRef.current.abort();
    };
  }, [fetchData, pollIntervalMs]);

  return { events, stats, loading, error };
}
