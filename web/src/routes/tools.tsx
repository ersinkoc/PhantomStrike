import { useState, useRef, useEffect, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Wrench,
  ToggleLeft,
  ToggleRight,
  Play,
  X,
  Loader2,
  CheckCircle2,
  XCircle,
  Zap,
  Globe,
  Shield,
  Search,
  Clock,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { formatDuration } from "@/lib/utils";
import type { Tool } from "@/types";

// ---------- types for tool definitions ----------

interface ToolParameter {
  name: string;
  type: string;
  required: boolean;
  flag?: string;
  default?: string | number | boolean;
  description?: string;
}

interface ToolDefinition {
  name: string;
  short_description?: string;
  description?: string;
  parameters?: ToolParameter[];
  docker?: { image?: string };
}

interface ToolRunResult {
  tool: string;
  status: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  error?: string;
}

// ---------- Quick Scan presets ----------

interface QuickScanPreset {
  label: string;
  toolName: string;
  icon: React.ReactNode;
  description: string;
  defaultFlags?: string;
}

const QUICK_SCANS: QuickScanPreset[] = [
  {
    label: "Quick Nmap Scan",
    toolName: "nmap",
    icon: <Search className="h-4 w-4" />,
    description: "Port scan with service detection",
    defaultFlags: "-sV -T4 --top-ports 100",
  },
  {
    label: "Quick Nuclei Scan",
    toolName: "nuclei",
    icon: <Shield className="h-4 w-4" />,
    description: "Vulnerability scan with default templates",
    defaultFlags: "-silent -nc -severity critical,high,medium",
  },
  {
    label: "Quick HTTP Probe",
    toolName: "httpx",
    icon: <Globe className="h-4 w-4" />,
    description: "Probe for live HTTP services",
    defaultFlags: "-silent -status-code -title -tech-detect",
  },
];

// ---------- Quick Scan Target Dialog ----------

function QuickScanDialog({
  preset,
  onClose,
  onRun,
}: {
  preset: QuickScanPreset;
  onClose: () => void;
  onRun: (target: string) => void;
}) {
  const [target, setTarget] = useState("");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
          <div className="flex items-center gap-2">
            <Zap className="h-4 w-4 text-[#00FFD1]" />
            <h3 className="font-bold text-sm">{preset.label}</h3>
          </div>
          <button
            onClick={onClose}
            className="text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="px-5 py-4 space-y-3">
          <p className="text-xs text-[var(--color-muted-foreground)]">{preset.description}</p>
          <div>
            <label className="text-xs font-mono text-[var(--color-muted-foreground)] mb-1 block">
              TARGET <span className="text-[#FF3366]">*</span>
            </label>
            <input
              type="text"
              autoFocus
              placeholder="e.g. 192.168.1.1 or example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && target.trim()) onRun(target.trim());
              }}
              className="w-full rounded-md border px-3 py-2 text-sm font-mono bg-[var(--color-background)] border-[var(--color-border)] text-[var(--color-foreground)] placeholder:text-[var(--color-muted-foreground)] placeholder:opacity-50 focus:outline-none focus:ring-1 focus:ring-[#00FFD1]/50"
            />
          </div>
          <div className="text-xs text-[var(--color-muted-foreground)] font-mono">
            Flags: {preset.defaultFlags}
          </div>
        </div>
        <div className="flex justify-end border-t border-[var(--color-border)] px-5 py-3 gap-2">
          <button
            onClick={onClose}
            className="rounded-lg border border-[var(--color-border)] px-4 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              if (target.trim()) onRun(target.trim());
            }}
            disabled={!target.trim()}
            className="flex items-center gap-2 rounded-lg bg-[#00FFD1] px-4 py-1.5 text-sm font-bold text-black hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play className="h-3.5 w-3.5" /> Run
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------- Main Tools Page ----------

export default function Tools() {
  const queryClient = useQueryClient();
  const [runPanel, setRunPanel] = useState<{
    toolName: string;
    initialFlags?: string;
    initialTarget?: string;
  } | null>(null);
  const [quickScanPreset, setQuickScanPreset] = useState<QuickScanPreset | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["tools"],
    queryFn: () => api.get<{ tools: Tool[] }>("/tools"),
  });

  const toggleMutation = useMutation({
    mutationFn: (name: string) => api.put(`/tools/${name}/toggle`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tools"] });
      toast.success("Tool toggled");
    },
  });

  // Group by category
  const grouped = new Map<string, Tool[]>();
  data?.tools?.forEach((t) => {
    const cat = t.category.split("/")[0];
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(t);
  });

  const handleQuickScanRun = (preset: QuickScanPreset, target: string) => {
    setQuickScanPreset(null);
    setRunPanel({
      toolName: preset.toolName,
      initialFlags: preset.defaultFlags,
      initialTarget: target,
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Tools</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">
          {data?.tools?.length ?? 0} security tools available
        </p>
      </div>

      {/* Quick Scan Section */}
      <div className="rounded-xl border border-[#00FFD1]/20 bg-[#00FFD1]/5">
        <div className="border-b border-[#00FFD1]/20 px-5 py-3 flex items-center gap-2">
          <Zap className="h-4 w-4 text-[#00FFD1]" />
          <h2 className="font-semibold text-sm text-[#00FFD1]">Quick Scan</h2>
        </div>
        <div className="px-5 py-4 flex flex-wrap gap-3">
          {QUICK_SCANS.map((preset) => (
            <button
              key={preset.toolName}
              onClick={() => setQuickScanPreset(preset)}
              className="flex items-center gap-2.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-4 py-2.5 text-sm font-medium hover:border-[#00FFD1]/40 hover:bg-[#00FFD1]/5 transition-colors"
            >
              <span className="text-[#00FFD1]">{preset.icon}</span>
              <div className="text-left">
                <p className="font-mono text-xs">{preset.label}</p>
                <p className="text-[10px] text-[var(--color-muted-foreground)]">
                  {preset.description}
                </p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Tool list */}
      {isLoading ? (
        <div className="text-[var(--color-muted-foreground)]">Loading...</div>
      ) : (
        Array.from(grouped.entries()).map(([category, tools]) => (
          <div
            key={category}
            className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]"
          >
            <div className="border-b border-[var(--color-border)] px-5 py-3">
              <h2 className="font-semibold capitalize">{category}</h2>
            </div>
            <div className="divide-y divide-[var(--color-border)]">
              {tools.map((tool) => (
                <div
                  key={tool.name}
                  className="flex items-center justify-between px-5 py-3"
                >
                  <div className="flex items-center gap-3">
                    <Wrench className="h-4 w-4 text-[var(--color-muted-foreground)]" />
                    <div>
                      <p className="font-medium font-mono text-sm">{tool.name}</p>
                      <p className="text-xs text-[var(--color-muted-foreground)]">
                        {tool.category}
                        {tool.avg_exec_time != null &&
                          ` · avg ${formatDuration(tool.avg_exec_time)}`}
                        {tool.success_rate != null &&
                          ` · ${tool.success_rate}% success`}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() =>
                        setRunPanel({ toolName: tool.name })
                      }
                      disabled={!tool.enabled}
                      className="flex items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1 text-xs font-mono text-[var(--color-muted-foreground)] hover:border-[#00FFD1]/40 hover:text-[#00FFD1] hover:bg-[#00FFD1]/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                    >
                      <Play className="h-3 w-3" /> Run
                    </button>
                    <button
                      onClick={() => toggleMutation.mutate(tool.name)}
                      className="text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
                    >
                      {tool.enabled ? (
                        <ToggleRight className="h-6 w-6 text-[var(--color-primary)]" />
                      ) : (
                        <ToggleLeft className="h-6 w-6" />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))
      )}

      {/* Quick Scan Target Dialog */}
      {quickScanPreset && (
        <QuickScanDialog
          preset={quickScanPreset}
          onClose={() => setQuickScanPreset(null)}
          onRun={(target) => handleQuickScanRun(quickScanPreset, target)}
        />
      )}

      {/* Tool Run Panel */}
      {runPanel && (
        <ToolRunPanelWithTarget
          toolName={runPanel.toolName}
          initialFlags={runPanel.initialFlags}
          initialTarget={runPanel.initialTarget}
          onClose={() => setRunPanel(null)}
        />
      )}
    </div>
  );
}

// Wrapper that injects initialTarget into the panel's params once loaded
function ToolRunPanelWithTarget({
  toolName,
  initialFlags,
  initialTarget,
  onClose,
}: {
  toolName: string;
  initialFlags?: string;
  initialTarget?: string;
  onClose: () => void;
}) {
  const [params, setParams] = useState<Record<string, string>>({});
  const [result, setResult] = useState<ToolRunResult | null>(null);
  const [status, setStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [startTime, setStartTime] = useState<number | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const outputRef = useRef<HTMLPreElement>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { data: toolData } = useQuery({
    queryKey: ["tool", toolName],
    queryFn: () =>
      api.get<{ name: string; definition: ToolDefinition }>(`/tools/${toolName}`),
  });

  const def = toolData?.definition;
  const toolParams = def?.parameters ?? [];

  // Set defaults + initial overrides
  useEffect(() => {
    if (!def) return;
    const defaults: Record<string, string> = {};
    for (const p of toolParams) {
      if (p.name === "flags" && initialFlags) {
        defaults[p.name] = initialFlags;
      } else if (p.name === "target" && initialTarget) {
        defaults[p.name] = initialTarget;
      } else if (p.default !== undefined && p.default !== false) {
        defaults[p.name] = String(p.default);
      }
    }
    setParams(defaults);
  }, [def, initialFlags, initialTarget, toolParams]);

  // Timer
  useEffect(() => {
    if (status === "running" && startTime) {
      timerRef.current = setInterval(() => {
        setElapsed(Date.now() - startTime);
      }, 100);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [status, startTime]);

  // Auto-scroll
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [result]);

  const runTool = useCallback(async () => {
    for (const p of toolParams) {
      if (p.required && !params[p.name]) {
        toast.error(`Missing required parameter: ${p.name}`);
        return;
      }
    }

    setStatus("running");
    setResult(null);
    const now = Date.now();
    setStartTime(now);
    setElapsed(0);

    try {
      const payload: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(params)) {
        if (v !== "") payload[k] = v;
      }
      const res = await api.post<ToolRunResult>(`/tools/${toolName}/run`, {
        params: payload,
      });
      setResult(res);
      setStatus(res.status === "error" || res.exit_code !== 0 ? "failed" : "completed");
    } catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : "Unknown error";
      setResult({
        tool: toolName,
        status: "error",
        exit_code: -1,
        stdout: "",
        stderr: errMsg,
        duration_ms: Date.now() - now,
        error: errMsg,
      });
      setStatus("failed");
    }
  }, [toolName, params, toolParams]);

  const statusIndicator = () => {
    switch (status) {
      case "running":
        return (
          <span className="flex items-center gap-1.5 text-[#00FFD1] text-xs font-mono">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> RUNNING
          </span>
        );
      case "completed":
        return (
          <span className="flex items-center gap-1.5 text-emerald-400 text-xs font-mono">
            <CheckCircle2 className="h-3.5 w-3.5" /> COMPLETED
          </span>
        );
      case "failed":
        return (
          <span className="flex items-center gap-1.5 text-[#FF3366] text-xs font-mono">
            <XCircle className="h-3.5 w-3.5" /> FAILED
          </span>
        );
      default:
        return (
          <span className="text-xs font-mono text-[var(--color-muted-foreground)]">READY</span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="relative w-full max-w-3xl max-h-[90vh] flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
          <div className="flex items-center gap-3">
            <Terminal className="h-5 w-5 text-[#00FFD1]" />
            <div>
              <h2 className="font-bold font-mono text-sm">{toolName}</h2>
              <p className="text-xs text-[var(--color-muted-foreground)]">
                {def?.short_description ?? "Loading..."}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {statusIndicator()}
            {(status === "running" || status === "completed" || status === "failed") && (
              <span className="flex items-center gap-1 text-xs text-[var(--color-muted-foreground)] font-mono">
                <Clock className="h-3 w-3" />
                {result?.duration_ms
                  ? formatDuration(result.duration_ms)
                  : formatDuration(elapsed)}
              </span>
            )}
            <button
              onClick={onClose}
              className="text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Parameters */}
        <div className="border-b border-[var(--color-border)] px-5 py-4 space-y-3 overflow-y-auto max-h-[40vh]">
          {toolParams.map((p) => (
            <div key={p.name}>
              <label className="flex items-center gap-2 text-xs font-mono text-[var(--color-muted-foreground)] mb-1">
                <span className="uppercase">{p.name}</span>
                {p.required && <span className="text-[#FF3366]">*</span>}
                {p.flag && p.flag !== "" && (
                  <span className="text-[var(--color-muted-foreground)] opacity-50">
                    ({p.flag})
                  </span>
                )}
              </label>
              <input
                type="text"
                placeholder={p.description ?? p.name}
                value={params[p.name] ?? ""}
                onChange={(e) =>
                  setParams((prev) => ({ ...prev, [p.name]: e.target.value }))
                }
                disabled={status === "running"}
                className={`w-full rounded-md border px-3 py-2 text-sm font-mono bg-[var(--color-background)] border-[var(--color-border)] text-[var(--color-foreground)] placeholder:text-[var(--color-muted-foreground)] placeholder:opacity-50 focus:outline-none focus:ring-1 focus:ring-[#00FFD1]/50 disabled:opacity-50 ${
                  p.name === "target" ? "ring-1 ring-[#00FFD1]/30" : ""
                }`}
              />
            </div>
          ))}
          {toolParams.length === 0 && (
            <p className="text-xs text-[var(--color-muted-foreground)]">Loading parameters...</p>
          )}
        </div>

        {/* Action bar */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-2">
          <div className="text-xs text-[var(--color-muted-foreground)] font-mono">
            {def?.docker?.image ? (
              <span>Docker: {def.docker.image}</span>
            ) : (
              <span>Process mode (local)</span>
            )}
          </div>
          <button
            onClick={runTool}
            disabled={status === "running"}
            className="flex items-center gap-2 rounded-lg bg-[#00FFD1] px-4 py-1.5 text-sm font-bold text-black hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {status === "running" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            {status === "running" ? "Running..." : "Run"}
          </button>
        </div>

        {/* Output terminal */}
        <div className="flex-1 min-h-[200px] max-h-[40vh] overflow-hidden">
          <pre
            ref={outputRef}
            className="h-full overflow-auto bg-black px-5 py-3 text-xs font-mono text-emerald-400 leading-relaxed whitespace-pre-wrap break-all"
          >
            {status === "idle" && (
              <span className="text-[var(--color-muted-foreground)]">
                {">"} Output will appear here after running the tool...
              </span>
            )}
            {status === "running" && !result && (
              <span className="text-[#00FFD1]">
                {">"} Executing {toolName}...{"\n"}
                {">"} Waiting for output...
              </span>
            )}
            {result?.stdout && (
              <span className="text-emerald-400">{result.stdout}</span>
            )}
            {result?.stderr && (
              <>
                {result.stdout && "\n"}
                <span className="text-[#FF3366]">{result.stderr}</span>
              </>
            )}
            {result?.error && !result.stderr && (
              <span className="text-[#FF3366]">Error: {result.error}</span>
            )}
            {status === "completed" && result && (
              <>
                {"\n\n"}
                <span className="text-[var(--color-muted-foreground)]">
                  --- Completed in {formatDuration(result.duration_ms)} | Exit code:{" "}
                  {result.exit_code} ---
                </span>
              </>
            )}
            {status === "failed" && result && (
              <>
                {"\n\n"}
                <span className="text-[#FF3366]">
                  --- Failed in {formatDuration(result.duration_ms)} | Exit code:{" "}
                  {result.exit_code} ---
                </span>
              </>
            )}
          </pre>
        </div>
      </div>
    </div>
  );
}
