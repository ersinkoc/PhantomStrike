import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  Shield,
  AlertTriangle,
  Target,
  Zap,
  Cpu,
  Globe,
  Lock,
  Search,
  Play,
  Pause,
  RotateCw,
  MessageSquare,
  Minimize2,
  Maximize2,
} from 'lucide-react';
import { MatrixBackground } from './matrix-background';
import { TerminalChat } from './terminal-chat';
import { AttackChainFlow } from './attack-chain-flow';
import { RealtimeDataStream } from './realtime-data-stream';
import { useWebSocket } from '../../hooks/useWebSocket';

export function HackerDashboard() {
  const [activeTab, setActiveTab] = useState<'overview' | 'attack-chain' | 'terminal' | 'logs'>('overview');
  const [chatOpen, setChatOpen] = useState(true);
  const [missionStatus, setMissionStatus] = useState<'idle' | 'running' | 'paused'>('idle');
  const { connected, messages: _messages } = useWebSocket();

  const stats = [
    { label: 'Active Scans', value: 12, icon: Search, color: 'text-blue-400' },
    { label: 'Vulnerabilities', value: 47, icon: AlertTriangle, color: 'text-red-400' },
    { label: 'Tools Running', value: 8, icon: Zap, color: 'text-yellow-400' },
    { label: 'Agents Online', value: 5, icon: Cpu, color: 'text-green-400' },
    { label: 'Targets', value: 3, icon: Target, color: 'text-purple-400' },
    { label: 'Exploits Ready', value: 15, icon: Lock, color: 'text-orange-400' },
  ];

  return (
    <div className="relative min-h-screen bg-black text-green-400 font-mono overflow-hidden">
      <MatrixBackground />

      {/* Header */}
      <header className="relative z-10 border-b border-green-500/30 bg-black/80 backdrop-blur-sm">
        <div className="flex items-center justify-between px-6 py-4">
          <div className="flex items-center gap-4">
            <Shield className="w-8 h-8 text-green-500" />
            <div>
              <h1 className="text-2xl font-bold tracking-wider">PHANTOMSTRIKE</h1>
              <p className="text-xs text-green-600">AI-POWERED SECURITY PLATFORM v2.0</p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4" />
              <span className="text-sm">Target: example.com</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
              <span className="text-xs">{connected ? 'ONLINE' : 'OFFLINE'}</span>
            </div>
            <div className="flex gap-2">
              {missionStatus === 'idle' ? (
                <button
                  onClick={() => setMissionStatus('running')}
                  className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-500 text-black font-bold rounded transition-colors"
                >
                  <Play className="w-4 h-4" />
                  START MISSION
                </button>
              ) : missionStatus === 'running' ? (
                <button
                  onClick={() => setMissionStatus('paused')}
                  className="flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-500 text-black font-bold rounded transition-colors"
                >
                  <Pause className="w-4 h-4" />
                  PAUSE
                </button>
              ) : (
                <button
                  onClick={() => setMissionStatus('running')}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-black font-bold rounded transition-colors"
                >
                  <RotateCw className="w-4 h-4" />
                  RESUME
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex gap-1 px-6 pb-2">
          {(['overview', 'attack-chain', 'terminal', 'logs'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-bold transition-all ${
                activeTab === tab
                  ? 'bg-green-500/20 text-green-400 border-t-2 border-green-500'
                  : 'text-gray-500 hover:text-green-400'
              }`}
            >
              {tab.toUpperCase().replace('-', ' ')}
            </button>
          ))}
        </div>
      </header>

      {/* Main Content */}
      <main className="relative z-10 p-6">
        {activeTab === 'overview' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              {stats.map((stat, idx) => (
                <motion.div
                  key={stat.label}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: idx * 0.1 }}
                  className="bg-black/60 border border-green-500/30 rounded-lg p-4 hover:border-green-500/60 transition-colors"
                >
                  <div className="flex items-center justify-between mb-2">
                    <stat.icon className={`w-5 h-5 ${stat.color}`} />
                    <Activity className="w-4 h-4 text-green-600" />
                  </div>
                  <div className="text-2xl font-bold text-white">{stat.value}</div>
                  <div className="text-xs text-gray-400">{stat.label}</div>
                </motion.div>
              ))}
            </div>

            {/* Main Grid */}
            <div className="grid lg:grid-cols-3 gap-6">
              {/* Attack Chain Preview */}
              <div className="lg:col-span-2 space-y-4">
                <div className="bg-black/60 border border-green-500/30 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold flex items-center gap-2">
                      <Target className="w-5 h-5" />
                      ATTACK CHAIN VISUALIZATION
                    </h3>
                    <button
                      onClick={() => setActiveTab('attack-chain')}
                      className="text-xs text-green-500 hover:text-green-400"
                    >
                      VIEW FULL →
                    </button>
                  </div>
                  <div className="h-64">
                    <AttackChainFlow />
                  </div>
                </div>

                {/* Realtime Data Stream */}
                <RealtimeDataStream />
              </div>

              {/* Terminal Chat */}
              <div className="space-y-4">
                <div className="bg-black/60 border border-green-500/30 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold flex items-center gap-2">
                      <MessageSquare className="w-5 h-5" />
                      AI ASSISTANT
                    </h3>
                    <div className="flex gap-1">
                      <button
                        onClick={() => setChatOpen(!chatOpen)}
                        className="p-1 hover:bg-green-500/20 rounded"
                      >
                        {chatOpen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                  {chatOpen && <TerminalChat />}
                </div>

                {/* Quick Actions */}
                <div className="bg-black/60 border border-green-500/30 rounded-lg p-4">
                  <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                    <Zap className="w-5 h-5" />
                    QUICK ACTIONS
                  </h3>
                  <div className="space-y-2">
                    {['Run Nuclei Scan', 'Start Port Scan', 'Check for XSS', 'SQL Injection Test', 'Generate Report'].map((action) => (
                      <button
                        key={action}
                        className="w-full text-left px-3 py-2 bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 rounded text-sm transition-colors"
                      >
                        {action}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'attack-chain' && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="h-[calc(100vh-200px)]"
          >
            <AttackChainFlow />
          </motion.div>
        )}

        {activeTab === 'terminal' && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="h-[calc(100vh-200px)]"
          >
            <TerminalChat />
          </motion.div>
        )}

        {activeTab === 'logs' && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <RealtimeDataStream />
          </motion.div>
        )}
      </main>

      {/* Footer */}
      <footer className="fixed bottom-0 left-0 right-0 z-10 bg-black/80 border-t border-green-500/30 px-6 py-2">
        <div className="flex items-center justify-between text-xs text-gray-500">
          <div className="flex items-center gap-4">
            <span>PhantomStrike v2.0</span>
            <span>|</span>
            <span>151+ Tools Available</span>
            <span>|</span>
            <span className="text-green-500">System Operational</span>
          </div>
          <div className="flex items-center gap-4">
            <span>WS: {connected ? 'Connected' : 'Disconnected'}</span>
            <span>Last Update: {new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
