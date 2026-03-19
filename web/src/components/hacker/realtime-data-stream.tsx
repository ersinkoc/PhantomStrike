import { useEffect, useState } from 'react';
import { Activity, Shield, AlertTriangle, CheckCircle, Terminal } from 'lucide-react';

interface DataStream {
  id: string;
  type: 'scan' | 'vuln' | 'tool' | 'system';
  message: string;
  timestamp: Date;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export function RealtimeDataStream() {
  const [streams, setStreams] = useState<DataStream[]>([]);
  const [stats, setStats] = useState({
    scans: 0,
    vulns: 0,
    tools: 0,
    agents: 0,
  });

  useEffect(() => {
    // Simulate incoming data
    const messages = [
      { type: 'scan', message: 'nmap scan started on 192.168.1.1', severity: 'info' },
      { type: 'tool', message: 'nuclei found XSS vulnerability', severity: 'high' },
      { type: 'scan', message: 'Port 80 open - HTTP service', severity: 'info' },
      { type: 'vuln', message: 'Critical: SQL Injection detected', severity: 'critical' },
      { type: 'tool', message: 'sqlmap extracted database names', severity: 'high' },
      { type: 'system', message: 'Agent-1 connected', severity: 'info' },
      { type: 'scan', message: 'subfinder discovered 45 subdomains', severity: 'info' },
      { type: 'vuln', message: 'Medium: Information disclosure', severity: 'medium' },
      { type: 'tool', message: 'metasploit session opened', severity: 'high' },
      { type: 'system', message: 'Workflow execution completed', severity: 'info' },
    ];

    let index = 0;
    const interval = setInterval(() => {
      const msg = messages[index % messages.length];
      const newStream: DataStream = {
        id: Math.random().toString(36).substr(2, 9),
        type: msg.type as any,
        message: msg.message,
        timestamp: new Date(),
        severity: msg.severity as any,
      };

      setStreams(prev => [newStream, ...prev].slice(0, 50));

      // Update stats
      setStats(prev => ({
        scans: msg.type === 'scan' ? prev.scans + 1 : prev.scans,
        vulns: msg.type === 'vuln' ? prev.vulns + 1 : prev.vulns,
        tools: msg.type === 'tool' ? prev.tools + 1 : prev.tools,
        agents: msg.type === 'system' && msg.message.includes('Agent') ? prev.agents + 1 : prev.agents,
      }));

      index++;
    }, 1500);

    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-blue-500';
      default: return 'text-green-400';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'scan': return <Activity className="w-4 h-4 text-blue-400" />;
      case 'vuln': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'tool': return <Terminal className="w-4 h-4 text-green-400" />;
      case 'system': return <Shield className="w-4 h-4 text-purple-400" />;
      default: return <CheckCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  return (
    <div className="bg-black/80 border border-green-500/30 rounded-lg overflow-hidden">
      {/* Stats Bar */}
      <div className="bg-green-900/20 border-b border-green-500/30 px-4 py-2 overflow-x-auto">
        <div className="flex items-center gap-6 text-sm whitespace-nowrap">
          <span className="text-green-400">ACTIVE SCANS: {stats.scans}</span>
          <span className="text-red-400">VULNERABILITIES: {stats.vulns}</span>
          <span className="text-blue-400">TOOLS RUNNING: {stats.tools}</span>
          <span className="text-purple-400">AGENTS ONLINE: {stats.agents}</span>
          <span className="text-cyan-400">STATUS: ACTIVE</span>
        </div>
      </div>

      {/* Live Data Feed */}
      <div className="h-64 overflow-hidden">
        <div className="p-2 space-y-1">
          {streams.slice(0, 15).map((stream, idx) => (
            <div
              key={stream.id}
              className="flex items-center gap-2 px-2 py-1 rounded hover:bg-green-500/10 transition-colors animate-fadeIn"
              style={{ animationDelay: `${idx * 50}ms` }}
            >
              {getTypeIcon(stream.type)}
              <span className="text-xs text-gray-500 font-mono">
                {stream.timestamp.toLocaleTimeString()}
              </span>
              <span className={`text-xs font-mono truncate flex-1 ${getSeverityColor(stream.severity)}`}>
                [{stream.type.toUpperCase()}] {stream.message}
              </span>
              {stream.severity && (
                <span className={`text-xs px-1.5 py-0.5 rounded ${getSeverityColor(stream.severity)} bg-current/20`}>
                  {stream.severity}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Status */}
      <div className="bg-green-900/10 border-t border-green-500/30 px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-xs text-green-400 font-mono">LIVE FEED ACTIVE</span>
        </div>
        <div className="text-xs text-gray-500 font-mono">
          {streams.length} events | Last update: {new Date().toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
}
