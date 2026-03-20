import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Play, Pause, XCircle, Terminal, Bug, GitBranch, Loader2, Wrench, FileText, Download, ChevronDown, ChevronRight, Plus } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { cn, statusColor, severityColor, formatDate, formatDuration } from "@/lib/utils";
import type { Mission, Vulnerability } from "@/types";
import { useState, useEffect, useRef } from "react";
import { useAuthStore } from "@/stores/auth";

type Tab = "overview" | "console" | "findings" | "chain" | "tools" | "report";

interface ToolExecution {
  id: string;
  tool_name: string;
  status: string;
  exit_code: number;
  duration_ms: number;
  started_at: string;
  stdout?: string;
  stderr?: string;
}

interface Report {
  id: string;
  mission_id: string;
  title: string;
  format: string;
  status: string;
  created_at: string;
}

interface LogEntry {
  id: string;
  type: "thinking" | "tool_start" | "tool_complete" | "tool_error" | "vuln_found" | "phase_change" | "system";
  agent: string;
  message: string;
  timestamp: Date;
  data?: Record<string, unknown>;
}

export default function MissionDetail() {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const { token } = useAuthStore();

  const { data: mission } = useQuery({
    queryKey: ["mission", id],
    queryFn: () => api.get<Mission>(`/missions/${id}`),
    refetchInterval: 5000,
  });

  const { data: vulns } = useQuery({
    queryKey: ["mission-vulns", id],
    queryFn: () => api.get<{ vulnerabilities: Vulnerability[] }>(`/missions/${id}/vulns`),
  });

  const startMutation = useMutation({
    mutationFn: () => api.post(`/missions/${id}/start`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["mission", id] }); toast.success("Mission started"); },
  });

  const pauseMutation = useMutation({
    mutationFn: () => api.post(`/missions/${id}/pause`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["mission", id] }); toast.info("Mission paused"); },
  });

  const cancelMutation = useMutation({
    mutationFn: () => api.post(`/missions/${id}/cancel`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["mission", id] }); toast.warning("Mission cancelled"); },
  });

  // WebSocket connection for real-time logs
  useEffect(() => {
    if (!token || !id) return;

    const wsUrl = `ws://${window.location.host}/ws?token=${token}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "subscribe", data: { mission_id: id } }));
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "subscribed") {
          setLogs(prev => [...prev, {
            id: crypto.randomUUID(),
            type: "system",
            agent: "system",
            message: "Connected to mission stream",
            timestamp: new Date(),
          }]);
        } else if (["thinking", "tool_start", "tool_complete", "tool_error", "vuln_found", "phase_change"].includes(msg.type)) {
          const logEntry: LogEntry = {
            id: crypto.randomUUID(),
            type: msg.type as LogEntry["type"],
            agent: msg.data?.agent || "agent",
            message: formatLogMessage(msg),
            timestamp: new Date(),
            data: msg.data,
          };
          setLogs(prev => [...prev, logEntry]);
        }
      } catch {
        // ignore invalid messages
      }
    };

    ws.onerror = () => {
      setLogs(prev => [...prev, {
        id: crypto.randomUUID(),
        type: "system",
        agent: "system",
        message: "WebSocket connection error",
        timestamp: new Date(),
      }]);
    };

    return () => {
      ws.close();
    };
  }, [token, id]);

  // Auto-scroll logs
  useEffect(() => {
    if (activeTab === "console" && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, activeTab]);

  if (!mission) return <div className="text-[var(--color-muted-foreground)]">Loading...</div>;

  const tabs = [
    { id: "overview" as const, label: "Overview", icon: GitBranch },
    { id: "console" as const, label: "Console", icon: Terminal },
    { id: "findings" as const, label: `Findings (${vulns?.vulnerabilities?.length ?? 0})`, icon: Bug },
    { id: "chain" as const, label: "Attack Chain", icon: GitBranch },
    { id: "tools" as const, label: "Tools", icon: Wrench },
    { id: "report" as const, label: "Report", icon: FileText },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold">{mission.name}</h1>
          <div className="mt-1 flex items-center gap-3 text-sm text-[var(--color-muted-foreground)]">
            <span className={cn("font-medium capitalize", statusColor(mission.status))}>{mission.status}</span>
            <span>·</span>
            <span>{mission.mode}</span>
            <span>·</span>
            <span>{mission.depth}</span>
            {mission.current_phase && <><span>·</span><span className="text-[var(--color-primary)]">{mission.current_phase}</span></>}
          </div>
        </div>
        <div className="flex gap-2">
          {mission.status === "created" && (
            <button onClick={() => startMutation.mutate()} disabled={startMutation.isPending} className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50">
              {startMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Start
            </button>
          )}
          {["running", "planning", "recon", "scanning", "exploitation"].includes(mission.status) && (
            <button onClick={() => pauseMutation.mutate()} disabled={pauseMutation.isPending} className="flex items-center gap-1.5 rounded-lg border border-amber-500/30 px-3 py-1.5 text-sm text-amber-400 hover:bg-amber-500/10">
              <Pause className="h-4 w-4" /> Pause
            </button>
          )}
          {!["completed", "cancelled", "failed"].includes(mission.status) && (
            <button onClick={() => cancelMutation.mutate()} disabled={cancelMutation.isPending} className="flex items-center gap-1.5 rounded-lg border border-[var(--color-destructive)]/30 px-3 py-1.5 text-sm text-[var(--color-destructive)] hover:bg-[var(--color-destructive)]/10">
              <XCircle className="h-4 w-4" /> Cancel
            </button>
          )}
        </div>
      </div>

      {/* Progress */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-4">
        <div className="mb-2 flex justify-between text-sm">
          <span className="text-[var(--color-muted-foreground)]">Progress</span>
          <span className="font-mono text-[var(--color-primary)]">{mission.progress}%</span>
        </div>
        <div className="h-2 rounded-full bg-[var(--color-muted)]">
          <div className="h-2 rounded-full bg-[var(--color-primary)] transition-all duration-500" style={{ width: `${mission.progress}%` }} />
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        {tabs.map((tab) => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={cn("flex items-center gap-1.5 border-b-2 px-4 py-2 text-sm transition-colors",
              activeTab === tab.id ? "border-[var(--color-primary)] text-[var(--color-primary)]" : "border-transparent text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
            )}>
            <tab.icon className="h-4 w-4" /> {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-2 gap-4">
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-4">
            <h3 className="mb-2 text-sm font-semibold text-[var(--color-muted-foreground)]">Target</h3>
            <pre className="text-sm font-mono text-[var(--color-primary)]">{JSON.stringify(mission.target, null, 2)}</pre>
          </div>
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-4">
            <h3 className="mb-2 text-sm font-semibold text-[var(--color-muted-foreground)]">Timeline</h3>
            <div className="space-y-2 text-sm">
              <p><span className="text-[var(--color-muted-foreground)]">Created:</span> {formatDate(mission.created_at)}</p>
              {mission.started_at && <p><span className="text-[var(--color-muted-foreground)]">Started:</span> {formatDate(mission.started_at)}</p>}
              {mission.completed_at && <p><span className="text-[var(--color-muted-foreground)]">Completed:</span> {formatDate(mission.completed_at)}</p>}
            </div>
          </div>
        </div>
      )}

      {activeTab === "console" && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[#0D0D12] p-4 font-mono text-sm h-96 overflow-y-auto">
          {logs.length === 0 ? (
            <div className="text-[var(--color-muted-foreground)]">
              <p className="text-[var(--color-primary)]">$ phantomstrike mission run --id {id}</p>
              <p className="mt-2 text-emerald-400">Waiting for agent output...</p>
            </div>
          ) : (
            <div className="space-y-1">
              {logs.map((log) => (
                <div key={log.id} className={cn("flex gap-3", getLogColor(log.type))}>
                  <span className="shrink-0 text-zinc-600">{log.timestamp.toLocaleTimeString()}</span>
                  <span className="shrink-0 w-16 text-xs uppercase">[{log.agent}]</span>
                  <span className="break-all">{log.message}</span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          )}
        </div>
      )}

      {activeTab === "findings" && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
          {vulns?.vulnerabilities?.length ? (
            <div className="divide-y divide-[var(--color-border)]">
              {vulns.vulnerabilities.map((v) => (
                <div key={v.id} className="flex items-center justify-between px-5 py-3">
                  <div>
                    <p className="font-medium">{v.title}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)]">{v.target} · {v.found_by}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {v.cvss_score && <span className="font-mono text-sm">{v.cvss_score}</span>}
                    <span className={cn("rounded px-2 py-0.5 text-xs font-semibold uppercase", severityColor(v.severity))}>{v.severity}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-[var(--color-muted-foreground)]">No findings yet</div>
          )}
        </div>
      )}

      {activeTab === "chain" && <AttackChainView missionId={id!} />}

      {activeTab === "tools" && <ToolExecutionsView missionId={id!} />}

      {activeTab === "report" && <ReportView missionId={id!} />}
    </div>
  );
}

function formatLogMessage(msg: { type: string; data?: Record<string, unknown> }): string {
  switch (msg.type) {
    case "thinking":
      return msg.data?.thought as string || "Thinking...";
    case "tool_start":
      return `→ Running ${msg.data?.tool}...`;
    case "tool_complete":
      return `✓ ${msg.data?.tool} completed (${msg.data?.duration}ms)`;
    case "tool_error":
      return `✗ ${msg.data?.tool} failed: ${msg.data?.error}`;
    case "vuln_found":
      return `🐛 Found ${msg.data?.severity} vulnerability: ${msg.data?.title}`;
    case "phase_change":
      return `▶ Entering ${msg.data?.phase} phase`;
    default:
      return JSON.stringify(msg.data);
  }
}

function getLogColor(type: LogEntry["type"]): string {
  switch (type) {
    case "thinking": return "text-zinc-400";
    case "tool_start": return "text-blue-400";
    case "tool_complete": return "text-emerald-400";
    case "tool_error": return "text-[#FF3366]";
    case "vuln_found": return "text-amber-400";
    case "phase_change": return "text-[var(--color-primary)]";
    default: return "text-zinc-500";
  }
}

// Tool Executions View Component
function ToolExecutionsView({ missionId }: { missionId: string }) {
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [showFullOutput, setShowFullOutput] = useState<Record<string, boolean>>({});

  const { data, isLoading } = useQuery({
    queryKey: ["mission-tools", missionId],
    queryFn: () => api.get<{ tool_executions: ToolExecution[] }>(`/missions/${missionId}/tools`),
    refetchInterval: 5000,
  });

  const toolExecutions = data?.tool_executions || [];

  if (isLoading) {
    return <div className="text-[var(--color-muted-foreground)]">Loading tool executions...</div>;
  }

  if (toolExecutions.length === 0) {
    return (
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-12 text-center">
        <Wrench className="mx-auto h-12 w-12 opacity-30 text-[var(--color-muted-foreground)]" />
        <p className="mt-4 text-[var(--color-muted-foreground)]">No tool executions yet</p>
        <p className="text-xs text-[var(--color-muted-foreground)] mt-1">
          Tools will appear here as the mission runs
        </p>
      </div>
    );
  }

  function toolStatusColor(status: string): string {
    switch (status.toLowerCase()) {
      case "success": case "completed": return "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30";
      case "running": return "bg-blue-500/15 text-blue-400 border border-blue-500/30";
      case "failed": case "error": return "bg-[#FF3366]/15 text-[#FF3366] border border-[#FF3366]/30";
      case "timeout": return "bg-amber-500/15 text-amber-400 border border-amber-500/30";
      default: return "bg-zinc-500/15 text-zinc-400 border border-zinc-500/30";
    }
  }

  const TRUNCATE_LENGTH = 500;

  function renderOutput(label: string, content: string | undefined, toolId: string, field: string) {
    if (!content) return null;
    const key = `${toolId}-${field}`;
    const isLong = content.length > TRUNCATE_LENGTH;
    const expanded = showFullOutput[key];
    const displayContent = isLong && !expanded ? content.slice(0, TRUNCATE_LENGTH) + "..." : content;

    return (
      <div className="mt-2">
        <p className="text-xs font-semibold text-[var(--color-muted-foreground)] mb-1">{label}</p>
        <pre className="whitespace-pre-wrap break-all rounded-lg bg-[#0D0D12] p-3 text-xs font-mono text-zinc-300">
          {displayContent}
        </pre>
        {isLong && (
          <button
            onClick={() => setShowFullOutput(prev => ({ ...prev, [key]: !expanded }))}
            className="mt-1 text-xs text-[var(--color-primary)] hover:underline"
          >
            {expanded ? "Show less" : "Show more"}
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
      {/* Table Header */}
      <div className="grid grid-cols-[1fr_100px_80px_100px_140px_32px] gap-3 px-5 py-3 border-b border-[var(--color-border)] text-xs font-semibold text-[var(--color-muted-foreground)] uppercase tracking-wider">
        <span>Tool</span>
        <span>Status</span>
        <span>Exit Code</span>
        <span>Duration</span>
        <span>Started</span>
        <span></span>
      </div>

      {/* Rows */}
      <div className="divide-y divide-[var(--color-border)]">
        {toolExecutions.map((tool) => (
          <div key={tool.id}>
            <div
              className="grid grid-cols-[1fr_100px_80px_100px_140px_32px] gap-3 px-5 py-3 items-center cursor-pointer hover:bg-[var(--color-muted)]/30 transition-colors"
              onClick={() => setExpandedRow(expandedRow === tool.id ? null : tool.id)}
            >
              <span className="font-medium text-sm truncate">{tool.tool_name}</span>
              <span>
                <span className={cn("rounded-full px-2 py-0.5 text-xs font-semibold capitalize", toolStatusColor(tool.status))}>
                  {tool.status}
                </span>
              </span>
              <span className="font-mono text-sm text-[var(--color-muted-foreground)]">{tool.exit_code}</span>
              <span className="text-sm text-[var(--color-muted-foreground)]">{formatDuration(tool.duration_ms)}</span>
              <span className="text-xs text-[var(--color-muted-foreground)]">{formatDate(tool.started_at)}</span>
              <span className="text-[var(--color-muted-foreground)]">
                {expandedRow === tool.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </span>
            </div>

            {expandedRow === tool.id && (
              <div className="px-5 pb-4">
                {renderOutput("stdout", tool.stdout, tool.id, "stdout")}
                {renderOutput("stderr", tool.stderr, tool.id, "stderr")}
                {!tool.stdout && !tool.stderr && (
                  <p className="text-xs text-[var(--color-muted-foreground)] italic">No output captured</p>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// Report View Component
function ReportView({ missionId }: { missionId: string }) {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [reportTitle, setReportTitle] = useState("");
  const [reportFormat, setReportFormat] = useState<"json" | "md" | "html">("html");

  const { data, isLoading } = useQuery({
    queryKey: ["mission-reports", missionId],
    queryFn: () => api.get<{ reports: Report[] }>(`/missions/${missionId}/reports`),
  });

  const generateMutation = useMutation({
    mutationFn: () =>
      api.post("/reports", {
        mission_id: missionId,
        format: reportFormat,
        title: reportTitle || `Mission Report - ${new Date().toLocaleDateString()}`,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mission-reports", missionId] });
      toast.success("Report generated successfully");
      setShowForm(false);
      setReportTitle("");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to generate report");
    },
  });

  const reports = data?.reports || [];

  if (isLoading) {
    return <div className="text-[var(--color-muted-foreground)]">Loading reports...</div>;
  }

  function formatBadge(format: string): string {
    switch (format.toLowerCase()) {
      case "html": return "bg-blue-500/15 text-blue-400 border border-blue-500/30";
      case "json": return "bg-amber-500/15 text-amber-400 border border-amber-500/30";
      case "md": case "markdown": return "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30";
      default: return "bg-zinc-500/15 text-zinc-400 border border-zinc-500/30";
    }
  }

  return (
    <div className="space-y-4">
      {/* Generate Report Button */}
      <div className="flex justify-end">
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90"
        >
          <Plus className="h-4 w-4" /> Generate Report
        </button>
      </div>

      {/* Generate Report Form */}
      {showForm && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-5">
          <h3 className="text-sm font-semibold mb-4">Generate New Report</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">Title</label>
              <input
                type="text"
                value={reportTitle}
                onChange={(e) => setReportTitle(e.target.value)}
                placeholder="Mission Report"
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm placeholder:text-[var(--color-muted-foreground)] focus:border-[var(--color-primary)] focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">Format</label>
              <select
                value={reportFormat}
                onChange={(e) => setReportFormat(e.target.value as "json" | "md" | "html")}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
              >
                <option value="html">HTML</option>
                <option value="json">JSON</option>
                <option value="md">Markdown</option>
              </select>
            </div>
          </div>
          <div className="mt-4 flex gap-2 justify-end">
            <button
              onClick={() => setShowForm(false)}
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-muted)]/30"
            >
              Cancel
            </button>
            <button
              onClick={() => generateMutation.mutate()}
              disabled={generateMutation.isPending}
              className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
            >
              {generateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
              Generate
            </button>
          </div>
        </div>
      )}

      {/* Reports List */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        {reports.length > 0 ? (
          <div className="divide-y divide-[var(--color-border)]">
            {reports.map((report) => (
              <div key={report.id} className="flex items-center justify-between px-5 py-3">
                <div className="flex items-center gap-3">
                  <FileText className="h-5 w-5 text-[var(--color-muted-foreground)]" />
                  <div>
                    <p className="font-medium text-sm">{report.title}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)]">{formatDate(report.created_at)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={cn("rounded-full px-2 py-0.5 text-xs font-semibold uppercase", formatBadge(report.format))}>
                    {report.format}
                  </span>
                  <a
                    href={`/api/v1/reports/${report.id}/download`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 rounded-lg border border-[var(--color-border)] px-2.5 py-1 text-xs text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)] hover:bg-[var(--color-muted)]/30 transition-colors"
                  >
                    <Download className="h-3.5 w-3.5" /> Download
                  </a>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center">
            <FileText className="mx-auto h-12 w-12 opacity-30 text-[var(--color-muted-foreground)]" />
            <p className="mt-4 text-[var(--color-muted-foreground)]">No reports generated yet</p>
            <p className="text-xs text-[var(--color-muted-foreground)] mt-1">
              Click "Generate Report" to create one
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// Attack Chain View Component
function AttackChainView({ missionId }: { missionId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["attack-chain", missionId],
    queryFn: () => api.get<{ nodes: any[]; edges: any[] }>(`/missions/${missionId}/chain`),
  });

  if (isLoading) {
    return <div className="text-[var(--color-muted-foreground)]">Loading attack chain...</div>;
  }

  const nodes = data?.nodes || [];
  const edges = data?.edges || [];

  if (nodes.length === 0) {
    return (
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-12 text-center">
        <GitBranch className="mx-auto h-12 w-12 opacity-30 text-[var(--color-muted-foreground)]" />
        <p className="mt-4 text-[var(--color-muted-foreground)]">No attack chain data available yet</p>
        <p className="text-xs text-[var(--color-muted-foreground)] mt-1">
          The attack chain will be built as the mission progresses
        </p>
      </div>
    );
  }

  // Build adjacency list
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const children = new Map<string, string[]>();
  edges.forEach(e => {
    if (!children.has(e.source)) children.set(e.source, []);
    children.get(e.source)!.push(e.target);
  });

  // Find root nodes
  const targets = new Set(edges.map(e => e.target));
  const roots = nodes.filter(n => !targets.has(n.id));

  function renderNode(nodeId: string, depth: number = 0): React.ReactNode {
    const node = nodeMap.get(nodeId);
    if (!node) return null!;

    const nodeChildren = children.get(nodeId) || [];
    const isVuln = node.node_type === "vulnerability";
    const isTool = node.node_type === "tool";
    const isTarget = node.node_type === "target";

    return (
      <div key={nodeId} className="relative">
        <div
          className={cn(
            "flex items-center gap-3 p-3 rounded-lg border transition-all",
            isVuln && "border-red-500/30 bg-red-500/5",
            isTool && "border-blue-500/30 bg-blue-500/5",
            isTarget && "border-emerald-500/30 bg-emerald-500/5",
            !isVuln && !isTool && !isTarget && "border-[var(--color-border)] bg-[var(--color-card)]"
          )}
          style={{ marginLeft: `${depth * 24}px` }}
        >
          {/* Node Icon */}
          <div className={cn(
            "w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold",
            isVuln && "bg-red-500/20 text-red-400",
            isTool && "bg-blue-500/20 text-blue-400",
            isTarget && "bg-emerald-500/20 text-emerald-400",
            !isVuln && !isTool && !isTarget && "bg-[var(--color-muted)] text-[var(--color-muted-foreground)]"
          )}>
            {isVuln ? "⚠" : isTool ? "🔧" : isTarget ? "🎯" : "●"}
          </div>

          {/* Node Content */}
          <div className="flex-1 min-w-0">
            <p className="font-medium text-sm truncate">{node.label}</p>
            <div className="flex items-center gap-2 text-xs text-[var(--color-muted-foreground)]">
              <span className="uppercase">{node.node_type}</span>
              {node.phase && <span>· {node.phase}</span>}
              {node.severity && (
                <span className={cn(
                  "px-1.5 py-0.5 rounded text-xs font-semibold uppercase",
                  node.severity === "critical" && "bg-red-500/20 text-red-400",
                  node.severity === "high" && "bg-orange-500/20 text-orange-400",
                  node.severity === "medium" && "bg-yellow-500/20 text-yellow-400",
                  node.severity === "low" && "bg-blue-500/20 text-blue-400"
                )}>
                  {node.severity}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Render Children */}
        {nodeChildren.length > 0 && (
          <div className="mt-2 relative">
            {/* Connection Line */}
            <div className="absolute left-4 top-0 bottom-4 w-px bg-[var(--color-border)]" />
            <div className="space-y-2 pt-2">
              {nodeChildren.map(childId => renderNode(childId, depth + 1))}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-6">
      <h3 className="text-lg font-semibold mb-4">Attack Chain</h3>
      <div className="space-y-3 overflow-x-auto">
        {roots.map(root => renderNode(root.id))}
      </div>

      {/* Legend */}
      <div className="mt-6 pt-4 border-t border-[var(--color-border)] flex flex-wrap gap-4 text-xs">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs">🎯</div>
          <span className="text-[var(--color-muted-foreground)]">Target</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs">🔧</div>
          <span className="text-[var(--color-muted-foreground)]">Tool</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-red-500/20 text-red-400 flex items-center justify-center text-xs">⚠</div>
          <span className="text-[var(--color-muted-foreground)]">Vulnerability</span>
        </div>
      </div>
    </div>
  );
}
