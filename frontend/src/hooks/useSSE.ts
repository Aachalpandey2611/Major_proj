import { useEffect, useState } from 'react';

export interface SSEEvent {
  event_type: string;
  data: any;
}

export function useSSE(scanId: string | null) {
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const [status, setStatus] = useState<string>('disconnected');
  const [completedAttacks, setCompletedAttacks] = useState<number>(0);
  const [totalAttacks, setTotalAttacks] = useState<number>(15);
  const [findingsDiscovered, setFindingsDiscovered] = useState<any[]>([]);

  useEffect(() => {
    if (!scanId) {
      setStatus('disconnected');
      setEvents([]);
      setCompletedAttacks(0);
      setFindingsDiscovered([]);
      return;
    }

    // Get auth token from localStorage for SSE (EventSource doesn't support headers)
    const token = localStorage.getItem('sentinelloop_auth_token');
    if (!token) {
      setStatus('error');
      console.error('Authentication token not found');
      return;
    }

    setStatus('connecting');
    const url = `http://localhost:8001/api/v1/scans/${scanId}/stream?token=${token}`;
    const eventSource = new EventSource(url);

    eventSource.onopen = () => {
      setStatus('connected');
    };

    eventSource.onmessage = (event) => {
      try {
        const payload: SSEEvent = JSON.parse(event.data);
        setEvents((prev) => [...prev, payload]);

        switch (payload.event_type) {
          case 'scan_started':
            setStatus('running');
            if (payload.data.total_attacks) {
              setTotalAttacks(payload.data.total_attacks);
            }
            break;

          case 'attack_complete':
            setCompletedAttacks(payload.data.completed_attacks);
            break;

          case 'finding_discovered':
            setFindingsDiscovered((prev) => [...prev, payload.data]);
            break;

          case 'scan_done':
            setStatus('done');
            eventSource.close();
            break;

          case 'scan_failed':
            setStatus('failed');
            eventSource.close();
            break;

          case 'fully_secure':
            setStatus('fully_secure');
            eventSource.close();
            break;

          default:
            break;
        }
      } catch (err) {
        console.error('Failed to parse SSE payload:', err);
      }
    };

    eventSource.onerror = (err) => {
      console.error('SSE connection error:', err);
      setStatus('error');
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [scanId]);

  return {
    events,
    status,
    completedAttacks,
    totalAttacks,
    findingsDiscovered,
  };
}
