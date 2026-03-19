import { useEffect, useState, useCallback, useRef } from 'react';

// Use current page host for WebSocket — works with both Vite proxy and production
const WS_BASE = import.meta.env.VITE_WS_URL || `ws://${window.location.host}`;

interface WSMessage {
  type: string;
  data?: unknown;
}

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const subscriptionsRef = useRef<Set<string>>(new Set());

  const connect = useCallback(() => {
    const token = localStorage.getItem('token');
    if (!token) return;

    const ws = new WebSocket(`${WS_BASE}/ws?token=${token}`);

    ws.onopen = () => {
      setConnected(true);
      console.log('Connected to PhantomStrike realtime feed');

      // Re-subscribe to any active subscriptions
      subscriptionsRef.current.forEach((topic) => {
        ws.send(JSON.stringify({ type: 'subscribe', data: { topic } }));
      });
    };

    ws.onclose = () => {
      setConnected(false);
      console.log('Disconnected from realtime feed');
      wsRef.current = null;

      // Auto-reconnect after 3 seconds
      reconnectTimer.current = setTimeout(() => {
        connect();
      }, 3000);
    };

    ws.onerror = () => {
      // onclose will fire after this, triggering reconnect
    };

    wsRef.current = ws;
  }, []);

  useEffect(() => {
    connect();

    return () => {
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  const send = useCallback((message: WSMessage) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  }, []);

  const subscribe = useCallback((topic: string, handler: (msg: WSMessage) => void) => {
    subscriptionsRef.current.add(topic);

    // Send subscribe message if already connected
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'subscribe', data: { topic } }));
    }

    const listener = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data) as WSMessage;
        handler(msg);
      } catch {
        // ignore invalid messages
      }
    };

    wsRef.current?.addEventListener('message', listener);

    // Return unsubscribe function
    return () => {
      subscriptionsRef.current.delete(topic);
      wsRef.current?.removeEventListener('message', listener);
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'unsubscribe', data: { topic } }));
      }
    };
  }, []);

  return {
    connected,
    send,
    subscribe,
  };
}
