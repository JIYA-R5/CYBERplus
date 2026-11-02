import { useState, useEffect, useRef, useCallback } from 'react';
import { NetworkEvent, SecurityAlert } from '../types';
import { normalizeAlert } from '../services/api';

export type WSConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error';

interface UseWebSocketOptions {
  maxEvents?: number;
  onEvent?: (event: NetworkEvent) => void;
  onAlert?: (alert: SecurityAlert) => void;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { maxEvents = 150, onEvent, onAlert } = options;

  const [status, setStatus] = useState<WSConnectionStatus>('disconnected');
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [lastEventTime, setLastEventTime] = useState<Date | null>(null);

  const eventsSocketRef = useRef<WebSocket | null>(null);
  const alertsSocketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isPausedRef = useRef<boolean>(false);
  const pendingEventsRef = useRef<NetworkEvent[]>([]);
  const batchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  isPausedRef.current = isPaused;

  const connect = useCallback(() => {
    // Determine ws host
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host; // Vite proxy handles /ws or direct backend
    const eventsUrl = `${protocol}//${host}/ws/events`;
    const alertsUrl = `${protocol}//${host}/ws/alerts`;

    setStatus('connecting');

    try {
      // 1. Events WebSocket
      const wsEvents = new WebSocket(eventsUrl);
      eventsSocketRef.current = wsEvents;

      wsEvents.onopen = () => {
        setStatus('connected');
      };

      wsEvents.onmessage = (msg) => {
        if (isPausedRef.current) return;
        try {
          const data = JSON.parse(msg.data);
          // Handle single event or batch of events
          const newEvents: NetworkEvent[] = Array.isArray(data) ? data : [data];
          if (newEvents.length > 0 && newEvents[0].timestamp) {
            // Buffer events to decouple high-frequency network packets from React DOM diffing
            pendingEventsRef.current.unshift(...newEvents);
            if (pendingEventsRef.current.length > maxEvents) {
              pendingEventsRef.current = pendingEventsRef.current.slice(0, maxEvents);
            }

            if (!batchTimerRef.current) {
              batchTimerRef.current = setTimeout(() => {
                batchTimerRef.current = null;
                const batch = pendingEventsRef.current;
                pendingEventsRef.current = [];
                if (batch.length > 0) {
                  setLastEventTime(new Date());
                  setEvents((prev) => {
                    const combined = [...batch, ...prev];
                    return combined.slice(0, maxEvents);
                  });
                  if (onEvent) {
                    batch.forEach((evt) => onEvent(evt));
                  }
                }
              }, 200);
            }
          }
        } catch (err) {
          console.debug('Failed to parse WebSocket event frame:', err);
        }
      };

      wsEvents.onclose = () => {
        setStatus('disconnected');
        scheduleReconnect();
      };

      wsEvents.onerror = () => {
        setStatus('error');
      };

      // 2. Alerts WebSocket
      const wsAlerts = new WebSocket(alertsUrl);
      alertsSocketRef.current = wsAlerts;

      wsAlerts.onmessage = (msg) => {
        try {
          const raw = JSON.parse(msg.data);
          const alertData: SecurityAlert = normalizeAlert(raw);
          if (alertData && alertData.alert_id) {
            setAlerts((prev) => {
              const existingIndex = prev.findIndex((a) => a.alert_id === alertData.alert_id);
              if (existingIndex >= 0) {
                const updated = [...prev];
                updated[existingIndex] = alertData;
                return updated;
              }
              return [alertData, ...prev.slice(0, 49)];
            });
            if (onAlert) {
              onAlert(alertData);
            }
          }
        } catch (err) {
          console.debug('Failed to parse WebSocket alert frame:', err);
        }
      };

      wsAlerts.onclose = () => {
        // Will be reconnected by the main reconnect cycle
      };
    } catch (e) {
      console.warn('WebSocket connection error:', e);
      setStatus('error');
      scheduleReconnect();
    }
  }, [maxEvents, onEvent, onAlert]);

  const scheduleReconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) return;
    reconnectTimeoutRef.current = setTimeout(() => {
      reconnectTimeoutRef.current = null;
      connect();
    }, 4000);
  }, [connect]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (batchTimerRef.current) clearTimeout(batchTimerRef.current);
      if (eventsSocketRef.current) {
        eventsSocketRef.current.close();
      }
      if (alertsSocketRef.current) {
        alertsSocketRef.current.close();
      }
    };
  }, [connect]);

  const togglePause = () => {
    setIsPaused((prev) => !prev);
  };

  const clearEvents = () => {
    setEvents([]);
  };

  return {
    status,
    events,
    alerts,
    isPaused,
    togglePause,
    clearEvents,
    lastEventTime,
  };
}
