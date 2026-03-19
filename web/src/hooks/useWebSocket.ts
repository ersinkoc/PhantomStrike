import { useEffect, useState, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';

interface RealtimeMessage {
  type: 'scan' | 'vuln' | 'agent' | 'tool' | 'system';
  data: any;
  timestamp: string;
}

export function useWebSocket() {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<RealtimeMessage[]>([]);

  useEffect(() => {
    const newSocket = io('ws://localhost:8080', {
      transports: ['websocket'],
      autoConnect: true,
    });

    newSocket.on('connect', () => {
      setConnected(true);
      console.log('Connected to PhantomStrike realtime feed');
    });

    newSocket.on('disconnect', () => {
      setConnected(false);
      console.log('Disconnected from realtime feed');
    });

    newSocket.on('scan.update', (data) => {
      setMessages(prev => [...prev, { type: 'scan', data, timestamp: new Date().toISOString() }]);
    });

    newSocket.on('vuln.found', (data) => {
      setMessages(prev => [...prev, { type: 'vuln', data, timestamp: new Date().toISOString() }]);
    });

    newSocket.on('agent.status', (data) => {
      setMessages(prev => [...prev, { type: 'agent', data, timestamp: new Date().toISOString() }]);
    });

    newSocket.on('tool.output', (data) => {
      setMessages(prev => [...prev, { type: 'tool', data, timestamp: new Date().toISOString() }]);
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, []);

  const sendCommand = useCallback((command: string, payload?: any) => {
    if (socket?.connected) {
      socket.emit('command', { command, payload });
    }
  }, [socket]);

  const subscribeToMission = useCallback((missionId: string) => {
    if (socket?.connected) {
      socket.emit('mission.subscribe', { missionId });
    }
  }, [socket]);

  return {
    socket,
    connected,
    messages,
    sendCommand,
    subscribeToMission,
  };
}
