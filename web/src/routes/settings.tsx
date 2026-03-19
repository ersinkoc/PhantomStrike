import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Settings, Bot, Server, Pencil, Save, X, Bell, Send } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";

interface NotificationChannel {
  type: string;
  name: string;
  enabled: boolean;
  event_filters: string[];
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);

  const { data } = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<Record<string, any>>("/settings"),
  });

  const { data: channels } = useQuery({
    queryKey: ["notification-channels"],
    queryFn: () =>
      api.get<{ channels: NotificationChannel[] }>("/notifications/channels"),
  });

  const testChannelMutation = useMutation({
    mutationFn: (type: string) =>
      api.post(`/notifications/channels/${type}/test`),
    onSuccess: () => toast.success("Test notification sent"),
    onError: (err: Error) =>
      toast.error(err.message || "Failed to send test notification"),
  });

  // Editable form state
  const [providerDefault, setProviderDefault] = useState("");
  const [maxIterations, setMaxIterations] = useState(0);
  const [maxParallelTools, setMaxParallelTools] = useState(0);
  const [autoReview, setAutoReview] = useState(false);

  // Sync form state when data loads or edit mode enters
  useEffect(() => {
    if (data) {
      setProviderDefault(data.providers?.default || "");
      setMaxIterations(data.agent?.max_iterations || 0);
      setMaxParallelTools(data.agent?.max_parallel_tools || 0);
      setAutoReview(data.agent?.auto_review || false);
    }
  }, [data]);

  const saveMutation = useMutation({
    mutationFn: (payload: Record<string, any>) =>
      api.put("/settings", payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      toast.success("Settings saved");
      setEditing(false);
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to save settings");
    },
  });

  const handleSave = () => {
    saveMutation.mutate({
      providers: {
        default: providerDefault,
      },
      agent: {
        max_iterations: maxIterations,
        max_parallel_tools: maxParallelTools,
        auto_review: autoReview,
      },
    });
  };

  const handleCancel = () => {
    setEditing(false);
    // Reset form to original values
    if (data) {
      setProviderDefault(data.providers?.default || "");
      setMaxIterations(data.agent?.max_iterations || 0);
      setMaxParallelTools(data.agent?.max_parallel_tools || 0);
      setAutoReview(data.agent?.auto_review || false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Settings</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">Platform configuration</p>
        </div>
        <div className="flex gap-2">
          {editing ? (
            <>
              <button
                onClick={handleCancel}
                className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
              >
                <X className="h-4 w-4" /> Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saveMutation.isPending}
                className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
              >
                <Save className="h-4 w-4" /> Save
              </button>
            </>
          ) : (
            <button
              onClick={() => setEditing(true)}
              className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm hover:bg-[var(--color-accent)]"
            >
              <Pencil className="h-4 w-4" /> Edit
            </button>
          )}
        </div>
      </div>

      {/* Providers */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-5 py-3">
          <Bot className="h-4 w-4 text-[var(--color-primary)]" />
          <h2 className="font-semibold">LLM Providers</h2>
        </div>
        {editing && (
          <div className="border-b border-[var(--color-border)] px-5 py-3">
            <label className="flex items-center justify-between">
              <span className="text-sm text-[var(--color-muted-foreground)]">Default Provider</span>
              <input
                type="text"
                value={providerDefault}
                onChange={(e) => setProviderDefault(e.target.value)}
                className="w-48 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-1.5 text-sm focus:border-[var(--color-primary)] focus:outline-none"
              />
            </label>
          </div>
        )}
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
          {editing ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm text-[var(--color-muted-foreground)]">max iterations</span>
                <input
                  type="number"
                  value={maxIterations}
                  onChange={(e) => setMaxIterations(Number(e.target.value))}
                  className="w-32 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-1.5 text-sm font-mono focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-[var(--color-muted-foreground)]">max parallel tools</span>
                <input
                  type="number"
                  value={maxParallelTools}
                  onChange={(e) => setMaxParallelTools(Number(e.target.value))}
                  className="w-32 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-1.5 text-sm font-mono focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-[var(--color-muted-foreground)]">auto review</span>
                <button
                  type="button"
                  onClick={() => setAutoReview(!autoReview)}
                  className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${
                    autoReview ? "bg-[var(--color-primary)]" : "bg-[var(--color-muted)]"
                  }`}
                >
                  <span
                    className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${
                      autoReview ? "translate-x-5" : "translate-x-0"
                    }`}
                  />
                </button>
              </div>
              {/* Show remaining read-only fields */}
              {data?.agent && Object.entries(data.agent)
                .filter(([key]) => !["max_iterations", "max_parallel_tools", "auto_review"].includes(key))
                .map(([key, value]) => (
                  <div key={key} className="flex items-center justify-between">
                    <span className="text-sm text-[var(--color-muted-foreground)]">{key.replace(/_/g, " ")}</span>
                    <span className="font-mono text-sm">{String(value)}</span>
                  </div>
                ))}
            </>
          ) : (
            data?.agent && Object.entries(data.agent).map(([key, value]) => (
              <div key={key} className="flex items-center justify-between">
                <span className="text-sm text-[var(--color-muted-foreground)]">{key.replace(/_/g, " ")}</span>
                <span className="font-mono text-sm">{String(value)}</span>
              </div>
            ))
          )}
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

      {/* Notifications */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-5 py-3">
          <Bell className="h-4 w-4 text-[var(--color-primary)]" />
          <h2 className="font-semibold">Notifications</h2>
        </div>
        <div className="divide-y divide-[var(--color-border)]">
          {channels?.channels && channels.channels.length > 0 ? (
            channels.channels.map((channel) => (
              <div
                key={channel.type}
                className="flex items-center justify-between px-5 py-3"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{channel.name}</p>
                    <span className="rounded bg-zinc-500/10 px-2 py-0.5 text-xs text-zinc-400">
                      {channel.type}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        channel.enabled
                          ? "bg-emerald-500/10 text-emerald-400"
                          : "bg-zinc-500/10 text-zinc-400"
                      }`}
                    >
                      {channel.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  {channel.event_filters && channel.event_filters.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {channel.event_filters.map((filter) => (
                        <span
                          key={filter}
                          className="rounded bg-[var(--color-accent)] px-1.5 py-0.5 text-xs text-[var(--color-muted-foreground)]"
                        >
                          {filter}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <button
                  onClick={() => testChannelMutation.mutate(channel.type)}
                  disabled={testChannelMutation.isPending}
                  className="ml-4 flex shrink-0 items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] disabled:opacity-50"
                >
                  <Send className="h-3.5 w-3.5" />
                  Test
                </button>
              </div>
            ))
          ) : (
            <div className="px-5 py-8 text-center text-sm text-[var(--color-muted-foreground)]">
              No notification channels configured
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
