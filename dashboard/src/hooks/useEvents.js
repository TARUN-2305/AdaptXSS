import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

export function useEvents(baseUrl, pollIntervalMs = 2000) {
  const [events, setEvents] = useState([]);
  const [stats, setStats]   = useState({ total: 0, malicious: 0, benign: 0, sessions: 0 });
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [evtsRes, statsRes] = await Promise.all([
        axios.get(`${baseUrl}/api/events?limit=200`),
        axios.get(`${baseUrl}/api/stats`)
      ]);
      setEvents(evtsRes.data);
      setStats(statsRes.data);
    } catch (err) {
      console.error('[AdaptXSS Dashboard] Fetch error:', err.message);
    } finally {
      setLoading(false);
    }
  }, [baseUrl]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, pollIntervalMs);
    return () => clearInterval(interval);
  }, [fetchData, pollIntervalMs]);

  return { events, stats, loading };
}
