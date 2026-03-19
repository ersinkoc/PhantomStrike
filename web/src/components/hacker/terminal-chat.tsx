import { useEffect, useState } from 'react';
import { TerminalOutput, TerminalInput } from 'react-terminal-ui';

interface Message {
  type: 'output' | 'input' | 'error';
  content: string;
  timestamp: Date;
}

interface TerminalChatProps {
  missionId?: string;
}

export function TerminalChat({ missionId }: TerminalChatProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      type: 'output',
      content: `
╔══════════════════════════════════════════════════════════╗
║     PHANTOMSTRIKE AI - SECURITY ASSISTANT v2.0          ║
║     Type 'help' for available commands                  ║
╚══════════════════════════════════════════════════════════╝
      `,
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');

  const handleInput = (command: string) => {
    const cmd = command.trim().toLowerCase();

    // Add user input
    setMessages(prev => [...prev, { type: 'input', content: `> ${command}`, timestamp: new Date() }]);

    // Process command
    setTimeout(() => {
      let response = '';

      switch (cmd) {
        case 'help':
          response = `
Available commands:
  scan <target>     - Start security scan
  status            - Show mission status
  tools             - List available tools
  vulns             - Show vulnerabilities
  chain             - View attack chain
  chat <message>    - Chat with AI
  clear             - Clear terminal
          `;
          break;
        case 'status':
          response = `
[SYSTEM STATUS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Mission: ${missionId || 'Not active'}
Status: RUNNING
Agents: 5 online
Last scan: 2 minutes ago
Critical vulns: 3 found
          `;
          break;
        case 'tools':
          response = `
[AVAILABLE TOOLS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
nuclei     - Web vulnerability scanner
nmap       - Network scanner
sqlmap     - SQL injection tool
metasploit - Exploitation framework
crackmapexec - AD exploitation
          `;
          break;
        case 'clear':
          setMessages([{
            type: 'output',
            content: 'Terminal cleared.',
            timestamp: new Date(),
          }]);
          return;
        default:
          if (cmd.startsWith('scan ')) {
            const target = cmd.slice(5);
            response = `Initiating scan on target: ${target}...\n[████████████████████] 100%\nScan complete. Found 12 open ports.`;
          } else if (cmd.startsWith('chat ')) {
            response = `AI Assistant: "I'm analyzing the security posture of your target. Based on preliminary scans, I recommend focusing on web application vulnerabilities and exposed services."`;
          } else {
            response = `Command not found: ${cmd}. Type 'help' for available commands.`;
          }
      }

      setMessages(prev => [...prev, { type: 'output', content: response, timestamp: new Date() }]);
    }, 300);
  };

  return (
    <div className="h-full bg-black/90 border border-green-500/30 rounded-lg overflow-hidden font-mono text-sm">
      <div className="bg-green-900/20 px-4 py-2 border-b border-green-500/30 flex items-center gap-2">
        <div className="w-3 h-3 rounded-full bg-red-500" />
        <div className="w-3 h-3 rounded-full bg-yellow-500" />
        <div className="w-3 h-3 rounded-full bg-green-500" />
        <span className="text-green-400 ml-2">AI Terminal v2.0</span>
      </div>

      <div className="h-[400px] overflow-y-auto p-4 space-y-1">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`${
              msg.type === 'input'
                ? 'text-green-400'
                : msg.type === 'error'
                  ? 'text-red-400'
                  : 'text-green-300'
            } whitespace-pre-wrap`}
          >
            {msg.content}
          </div>
        ))}
      </div>

      <div className="border-t border-green-500/30 p-2 flex">
        <span className="text-green-500 mr-2">{'>'}</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              handleInput(input);
              setInput('');
            }
          }}
          className="flex-1 bg-transparent text-green-400 outline-none font-mono"
          placeholder="Enter command..."
        />
      </div>
    </div>
  );
}
