import { useQuery } from "@tanstack/react-query";
import { Settings, Bot, Server } from "lucide-react";
import { api } from "@/lib/api";

export default function SettingsPage() {
  const { data } = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<Record<string, any>>("/settings"),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">Platform configuration</p>
      </div>

      {/* Providers */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-5 py-3">
          <Bot className="h-4 w-4 text-[var(--color-primary)]" />
          <h2 className="font-semibold">LLM Providers</h2>
        </div>
        <div className="divide-y divide-[var(--color-border)]">
          {data?.providers && Object.entries(data.providers).filter(([k]) => !["default", "fallback_chain"].includes(k)).map(([name, config]: [string, any]) => (
            <div key={name} className="flex items-center justify-between px-5 py-3">
              <div>
                <p className="font-medium capitalize">{name}</p>
                <p className="text-xs text-[var(--color-muted-foreground)]">Model: {config.model || "N/A"}</p>
              </div>
              <span className={`rounded px-2 py-0.5 text-xs ${config.configured ? "bg-emerald-500/10 text-emerald-400" : "bg-zinc-500/10 text-zinc-400"}`}>
                {config.configured ? "Configured" : config.base_url ? "Local" : "Not configured"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Agent Config */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-5 py-3">
          <Settings className="h-4 w-4 text-[var(--color-primary)]" />
          <h2 className="font-semibold">Agent Configuration</h2>
        </div>
        <div className="space-y-3 p-5">
          {data?.agent && Object.entries(data.agent).map(([key, value]) => (
            <div key={key} className="flex items-center justify-between">
              <span className="text-sm text-[var(--color-muted-foreground)]">{key.replace(/_/g, " ")}</span>
              <span className="font-mono text-sm">{String(value)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* MCP */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-5 py-3">
          <Server className="h-4 w-4 text-[var(--color-primary)]" />
          <h2 className="font-semibold">MCP Server</h2>
        </div>
        <div className="space-y-3 p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-[var(--color-muted-foreground)]">Status</span>
            <span className={`rounded px-2 py-0.5 text-xs ${data?.mcp?.enabled ? "bg-emerald-500/10 text-emerald-400" : "bg-zinc-500/10 text-zinc-400"}`}>
              {data?.mcp?.enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-[var(--color-muted-foreground)]">Port</span>
            <span className="font-mono text-sm">{data?.mcp?.port ?? "8081"}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
