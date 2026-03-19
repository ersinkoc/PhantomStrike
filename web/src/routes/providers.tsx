import { useState, useMemo, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Cpu, RefreshCw, Eye, EyeOff, Zap, CheckCircle2, XCircle,
  Loader2, Search, Check, X, ChevronDown, ChevronUp, Save,
  ArrowUpDown,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { cn, formatDate } from "@/lib/utils";

/* ---------- Types ---------- */

interface Provider {
  id: string;
  name: string;
  api_base_url: string;
  is_enabled: boolean;
  is_configured: boolean;
  is_local: boolean;
  sdk_type: string;
  model_count?: number;
  priority?: number;
  last_synced_at?: string;
}

interface Model {
  id: string;
  name: string;
  provider_id: string;
  provider_name?: string;
  family?: string;
  context_window?: number;
  tool_call?: boolean;
  reasoning?: boolean;
  cost_input?: number;
  cost_output?: number;
}

interface Preferences {
  default_provider: string;
  default_model: string;
  planner_provider?: string;
  planner_model?: string;
  executor_provider?: string;
  executor_model?: string;
  reviewer_provider?: string;
  reviewer_model?: string;
  embedding_provider?: string;
  embedding_model?: string;
}

/* ---------- Helpers ---------- */

type SortKey = "name" | "context_window" | "input_cost" | "output_cost";
type SortDir = "asc" | "desc";

function formatNumber(n?: number): string {
  if (n == null) return "-";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

function formatCost(n?: number): string {
  if (n == null) return "-";
  return `$${n.toFixed(2)}`;
}

/* ---------- Provider Card ---------- */

function ProviderCard({
  provider,
  models,
  onRefresh,
}: {
  provider: Provider;
  models: Model[];
  onRefresh: () => void;
}) {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [testStatus, setTestStatus] = useState<"idle" | "testing" | "success" | "error">("idle");
  const [editPriority, setEditPriority] = useState(false);
  const [priority, setPriority] = useState(provider.priority ?? 0);

  const toggleMutation = useMutation({
    mutationFn: () =>
      api.put(`/providers/${provider.id}`, {
        is_enabled: !provider.is_enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["providers"] });
      toast.success(
        `${provider.name} ${provider.is_enabled ? "disabled" : "enabled"}`
      );
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const saveKeyMutation = useMutation({
    mutationFn: () =>
      api.put(`/providers/${provider.id}`, { api_key: apiKey }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["providers"] });
      toast.success("API key saved");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const savePriorityMutation = useMutation({
    mutationFn: () =>
      api.put(`/providers/${provider.id}`, { priority }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["providers"] });
      toast.success("Priority updated");
      setEditPriority(false);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const handleTest = async () => {
    setTestStatus("testing");
    try {
      if (apiKey && !provider.is_local) {
        await api.put(`/providers/${provider.id}`, { api_key: apiKey });
      }
      const result = await api.post<{success?: boolean; error?: string}>(`/providers/${provider.id}/test`);
      if (result.success === false) throw new Error(result.error || 'Connection failed');
      setTestStatus("success");
      toast.success(`${provider.name} connected successfully`);
      onRefresh();
    } catch (err) {
      setTestStatus("error");
      toast.error(
        err instanceof Error ? err.message : `Connection failed`
      );
    }
  };

  const providerModels = models.filter(
    (m) => m.provider_id === provider.id
  );

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between px-5 py-4 cursor-pointer hover:bg-[var(--color-accent)]/50 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--color-accent)]">
            <Cpu className="h-5 w-5 text-[var(--color-primary)]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <p className="font-semibold">{provider.name}</p>
              <span
                className={cn(
                  "rounded px-2 py-0.5 text-xs",
                  provider.is_configured
                    ? "bg-emerald-500/10 text-emerald-400"
                    : "bg-zinc-500/10 text-zinc-400"
                )}
              >
                {provider.is_configured ? "Configured" : "Not configured"}
              </span>
            </div>
            <p className="text-xs text-[var(--color-muted-foreground)]">
              {provider.api_base_url}
              <span className="ml-2">
                {providerModels.length} model
                {providerModels.length !== 1 ? "s" : ""}
              </span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Priority */}
          <div className="flex items-center gap-1.5">
            {editPriority ? (
              <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                <input
                  type="number"
                  value={priority}
                  onChange={(e) => setPriority(Number(e.target.value))}
                  className="w-14 rounded border border-[var(--color-border)] bg-[var(--color-background)] px-2 py-1 text-xs font-mono text-center outline-none focus:border-[var(--color-primary)]"
                  min={0}
                />
                <button
                  onClick={() => savePriorityMutation.mutate()}
                  className="text-[var(--color-primary)] hover:opacity-80"
                >
                  <Check className="h-3.5 w-3.5" />
                </button>
                <button
                  onClick={() => {
                    setEditPriority(false);
                    setPriority(provider.priority ?? 0);
                  }}
                  className="text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setEditPriority(true);
                }}
                className="rounded bg-[var(--color-accent)] px-2 py-0.5 text-xs text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
                title="Edit priority"
              >
                P{provider.priority ?? 0}
              </button>
            )}
          </div>

          {/* Toggle */}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              toggleMutation.mutate();
            }}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors",
              provider.is_enabled
                ? "bg-[var(--color-primary)]"
                : "bg-[var(--color-muted)]"
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform",
                provider.is_enabled ? "translate-x-5" : "translate-x-0"
              )}
            />
          </button>

          {expanded ? (
            <ChevronUp className="h-4 w-4 text-[var(--color-muted-foreground)]" />
          ) : (
            <ChevronDown className="h-4 w-4 text-[var(--color-muted-foreground)]" />
          )}
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t border-[var(--color-border)]">
          {/* API Key Section */}
          {!provider.is_local && (
            <div className="border-b border-[var(--color-border)] px-5 py-4 space-y-3">
              <p className="text-sm font-medium">API Key</p>
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <input
                    type={showKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={
                      provider.is_configured
                        ? "Enter new key to update..."
                        : "Enter API key..."
                    }
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 pr-10 text-sm outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
                  >
                    {showKey ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
                <button
                  onClick={() => saveKeyMutation.mutate()}
                  disabled={!apiKey || saveKeyMutation.isPending}
                  className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] disabled:opacity-50"
                >
                  <Save className="h-4 w-4" />
                  Save
                </button>
                <button
                  onClick={handleTest}
                  disabled={testStatus === "testing"}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors disabled:opacity-50",
                    testStatus === "success"
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                      : testStatus === "error"
                        ? "bg-red-500/10 text-red-400 border border-red-500/30"
                        : "border border-[var(--color-border)] text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
                  )}
                >
                  {testStatus === "testing" ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : testStatus === "success" ? (
                    <CheckCircle2 className="h-4 w-4" />
                  ) : testStatus === "error" ? (
                    <XCircle className="h-4 w-4" />
                  ) : (
                    <Zap className="h-4 w-4" />
                  )}
                  Test
                </button>
              </div>
            </div>
          )}

          {/* Local provider test */}
          {!!provider.is_local && (
            <div className="border-b border-[var(--color-border)] px-5 py-4">
              <div className="flex items-center gap-3">
                <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-400">
                  No API key required
                </span>
                <button
                  onClick={handleTest}
                  disabled={testStatus === "testing"}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors disabled:opacity-50",
                    testStatus === "success"
                      ? "bg-emerald-500/10 text-emerald-400"
                      : testStatus === "error"
                        ? "bg-red-500/10 text-red-400"
                        : "border border-[var(--color-border)] text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
                  )}
                >
                  {testStatus === "testing" ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : testStatus === "success" ? (
                    <CheckCircle2 className="h-3.5 w-3.5" />
                  ) : testStatus === "error" ? (
                    <XCircle className="h-3.5 w-3.5" />
                  ) : (
                    <Zap className="h-3.5 w-3.5" />
                  )}
                  Test Connection
                </button>
              </div>
            </div>
          )}

          {/* Models list */}
          <div className="px-5 py-4">
            <p className="mb-2 text-sm font-medium">
              Models ({providerModels.length})
            </p>
            {providerModels.length > 0 ? (
              <div className="max-h-60 space-y-1 overflow-y-auto">
                {providerModels.map((m) => (
                  <div
                    key={m.id}
                    className="flex items-center justify-between rounded-lg px-3 py-2 text-sm hover:bg-[var(--color-accent)]/50"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-sm">{m.name}</p>
                      <p className="text-xs text-[var(--color-muted-foreground)]">
                        {m.family && <span>{m.family}</span>}
                        {m.context_window && (
                          <span className="ml-2">
                            {formatNumber(m.context_window)} ctx
                          </span>
                        )}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {m.tool_call && (
                        <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-xs text-blue-400">
                          tools
                        </span>
                      )}
                      {m.reasoning && (
                        <span className="rounded bg-purple-500/10 px-1.5 py-0.5 text-xs text-purple-400">
                          reasoning
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-[var(--color-muted-foreground)]">
                No models available for this provider.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------- Providers List with Search ---------- */

const POPULAR = ["anthropic", "openai", "groq", "ollama", "deepseek", "mistral", "google", "gemini", "openrouter", "together", "fireworks", "cohere"];

function ProvidersList({ providers, models, onRefresh }: { providers: Provider[]; models: Model[]; onRefresh: () => void }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "popular" | "configured">("popular");

  const filtered = useMemo(() => {
    let list = [...providers];

    // Filter
    if (filter === "popular") {
      list = list.filter((p) => POPULAR.includes(p.id) || p.is_configured || p.is_enabled);
    } else if (filter === "configured") {
      list = list.filter((p) => p.is_configured || p.is_enabled);
    }

    // Search
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((p) =>
        p.name.toLowerCase().includes(q) || p.id.toLowerCase().includes(q)
      );
    }

    // Sort: configured first, then popular, then alphabetical
    list.sort((a, b) => {
      if (a.is_configured !== b.is_configured) return a.is_configured ? -1 : 1;
      if (a.is_enabled !== b.is_enabled) return a.is_enabled ? -1 : 1;
      const ai = POPULAR.indexOf(a.id);
      const bi = POPULAR.indexOf(b.id);
      if (ai >= 0 && bi >= 0) return ai - bi;
      if (ai >= 0) return -1;
      if (bi >= 0) return 1;
      return a.name.localeCompare(b.name);
    });

    return list;
  }, [providers, search, filter]);

  return (
    <div className="space-y-4">
      {/* Search & Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-muted-foreground)]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search providers..."
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] py-2 pl-10 pr-3 text-sm outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
          />
        </div>
        <div className="flex gap-1 rounded-lg border border-[var(--color-border)] p-1">
          {(["popular", "configured", "all"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                "rounded-md px-3 py-1 text-xs font-medium capitalize transition-colors",
                filter === f
                  ? "bg-[var(--color-primary)] text-[var(--color-primary-foreground)]"
                  : "text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
              )}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Provider Cards */}
      <div className="space-y-3">
        {filtered.map((provider) => (
          <ProviderCard
            key={provider.id}
            provider={provider}
            models={models}
            onRefresh={onRefresh}
          />
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] px-5 py-12 text-center">
          <p className="text-[var(--color-muted-foreground)]">
            {providers.length === 0
              ? 'No providers found. Click "Sync from models.dev" to get started.'
              : "No providers match your search."}
          </p>
        </div>
      )}
    </div>
  );
}

/* ---------- Models Table ---------- */

function ModelsTable({ models }: { models: Model[] }) {
  const [search, setSearch] = useState("");
  const [providerFilter, setProviderFilter] = useState("");
  const [familyFilter, setFamilyFilter] = useState("");
  const [toolCallFilter, setToolCallFilter] = useState<"" | "yes" | "no">("");
  const [reasoningFilter, setReasoningFilter] = useState<"" | "yes" | "no">("");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const providers = useMemo(
    () => [...new Set(models.map((m) => m.provider_name).filter(Boolean))].sort(),
    [models]
  );

  const families = useMemo(
    () => [...new Set(models.map((m) => m.family).filter(Boolean))].sort(),
    [models]
  );

  const filtered = useMemo(() => {
    let result = [...models];

    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (m) =>
          m.name.toLowerCase().includes(q) ||
          m.id.toLowerCase().includes(q)
      );
    }
    if (providerFilter) {
      result = result.filter((m) => m.provider_name === providerFilter);
    }
    if (familyFilter) {
      result = result.filter((m) => m.family === familyFilter);
    }
    if (toolCallFilter === "yes") {
      result = result.filter((m) => m.tool_call === true);
    } else if (toolCallFilter === "no") {
      result = result.filter((m) => m.tool_call !== true);
    }
    if (reasoningFilter === "yes") {
      result = result.filter((m) => m.reasoning === true);
    } else if (reasoningFilter === "no") {
      result = result.filter((m) => m.reasoning !== true);
    }

    result.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "name":
          cmp = a.name.localeCompare(b.name);
          break;
        case "context_window":
          cmp = (a.context_window ?? 0) - (b.context_window ?? 0);
          break;
        case "input_cost":
          cmp =
            (a.cost_input ?? 0) -
            (b.cost_input ?? 0);
          break;
        case "output_cost":
          cmp =
            (a.cost_output ?? 0) -
            (b.cost_output ?? 0);
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });

    return result;
  }, [
    models,
    search,
    providerFilter,
    familyFilter,
    toolCallFilter,
    reasoningFilter,
    sortKey,
    sortDir,
  ]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const SortHeader = ({
    label,
    sortField,
    className,
  }: {
    label: string;
    sortField: SortKey;
    className?: string;
  }) => (
    <th
      className={cn(
        "cursor-pointer px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]",
        className
      )}
      onClick={() => toggleSort(sortField)}
    >
      <div className="flex items-center gap-1">
        {label}
        <ArrowUpDown
          className={cn(
            "h-3 w-3",
            sortKey === sortField
              ? "text-[var(--color-primary)]"
              : "opacity-40"
          )}
        />
      </div>
    </th>
  );

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-muted-foreground)]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search models..."
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] py-2 pl-10 pr-3 text-sm outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
          />
        </div>
        <select
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
        >
          <option value="">All Providers</option>
          {providers.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select
          value={familyFilter}
          onChange={(e) => setFamilyFilter(e.target.value)}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
        >
          <option value="">All Families</option>
          {families.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
        <select
          value={toolCallFilter}
          onChange={(e) =>
            setToolCallFilter(e.target.value as "" | "yes" | "no")
          }
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
        >
          <option value="">Tool Call</option>
          <option value="yes">Yes</option>
          <option value="no">No</option>
        </select>
        <select
          value={reasoningFilter}
          onChange={(e) =>
            setReasoningFilter(e.target.value as "" | "yes" | "no")
          }
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
        >
          <option value="">Reasoning</option>
          <option value="yes">Yes</option>
          <option value="no">No</option>
        </select>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
        <table className="w-full">
          <thead className="bg-[var(--color-card)]">
            <tr>
              <SortHeader label="Model" sortField="name" />
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--color-muted-foreground)]">
                Provider
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--color-muted-foreground)]">
                Family
              </th>
              <SortHeader
                label="Context"
                sortField="context_window"
              />
              <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider text-[var(--color-muted-foreground)]">
                Tools
              </th>
              <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider text-[var(--color-muted-foreground)]">
                Reasoning
              </th>
              <SortHeader
                label="Input $/1M"
                sortField="input_cost"
              />
              <SortHeader
                label="Output $/1M"
                sortField="output_cost"
              />
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {filtered.map((m) => (
              <tr
                key={m.id}
                className="hover:bg-[var(--color-accent)]/50 transition-colors"
              >
                <td className="px-4 py-3 text-sm font-mono whitespace-nowrap">
                  {m.name}
                </td>
                <td className="px-4 py-3 text-sm text-[var(--color-muted-foreground)]">
                  {m.provider_name || "-"}
                </td>
                <td className="px-4 py-3 text-sm text-[var(--color-muted-foreground)]">
                  {m.family || "-"}
                </td>
                <td className="px-4 py-3 text-sm font-mono text-[var(--color-muted-foreground)]">
                  {formatNumber(m.context_window)}
                </td>
                <td className="px-4 py-3 text-center">
                  {m.tool_call ? (
                    <Check className="mx-auto h-4 w-4 text-emerald-400" />
                  ) : (
                    <span className="text-[var(--color-muted-foreground)]">-</span>
                  )}
                </td>
                <td className="px-4 py-3 text-center">
                  {m.reasoning ? (
                    <Check className="mx-auto h-4 w-4 text-purple-400" />
                  ) : (
                    <span className="text-[var(--color-muted-foreground)]">-</span>
                  )}
                </td>
                <td className="px-4 py-3 text-sm font-mono text-[var(--color-muted-foreground)]">
                  {formatCost(m.cost_input)}
                </td>
                <td className="px-4 py-3 text-sm font-mono text-[var(--color-muted-foreground)]">
                  {formatCost(m.cost_output)}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td
                  colSpan={8}
                  className="px-4 py-8 text-center text-sm text-[var(--color-muted-foreground)]"
                >
                  No models found matching your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-[var(--color-muted-foreground)]">
        Showing {filtered.length} of {models.length} models
      </p>
    </div>
  );
}

/* ---------- Preferences Section ---------- */

function PreferencesSection({
  providers,
  models,
}: {
  providers: Provider[];
  models: Model[];
}) {
  const queryClient = useQueryClient();
  const configuredProviders = providers.filter(
    (p) => p.is_enabled && (p.is_configured || p.is_local)
  );

  const { data: prefs } = useQuery({
    queryKey: ["preferences"],
    queryFn: () => api.get<{ preferences: Record<string, { provider_id: string; model_id: string }> }>("/preferences"),
  });

  const [form, setForm] = useState<Preferences>({
    default_provider: "",
    default_model: "",
    planner_provider: "",
    planner_model: "",
    executor_provider: "",
    executor_model: "",
    reviewer_provider: "",
    reviewer_model: "",
    embedding_provider: "",
    embedding_model: "",
  });

  // Sync form when prefs data loads
  useEffect(() => {
    if (prefs?.preferences) {
      const p = prefs.preferences;
      setForm({
        default_provider: p.default?.provider_id || "",
        default_model: p.default?.model_id || "",
        planner_provider: p.planner?.provider_id || "",
        planner_model: p.planner?.model_id || "",
        executor_provider: p.executor?.provider_id || "",
        executor_model: p.executor?.model_id || "",
        reviewer_provider: p.reviewer?.provider_id || "",
        reviewer_model: p.reviewer?.model_id || "",
        embedding_provider: p.embedding?.provider_id || "",
        embedding_model: p.embedding?.model_id || "",
      });
    }
  }, [prefs]);

  const saveMutation = useMutation({
    mutationFn: () => {
      const payload: Record<string, { provider_id: string; model_id: string }> = {};
      if (form.default_provider && form.default_model) {
        payload.default = { provider_id: form.default_provider, model_id: form.default_model };
      }
      if (form.planner_provider && form.planner_model) {
        payload.planner = { provider_id: form.planner_provider, model_id: form.planner_model };
      }
      if (form.executor_provider && form.executor_model) {
        payload.executor = { provider_id: form.executor_provider, model_id: form.executor_model };
      }
      if (form.reviewer_provider && form.reviewer_model) {
        payload.reviewer = { provider_id: form.reviewer_provider, model_id: form.reviewer_model };
      }
      if (form.embedding_provider && form.embedding_model) {
        payload.embedding = { provider_id: form.embedding_provider, model_id: form.embedding_model };
      }
      return api.put("/preferences", payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["preferences"] });
      toast.success("Preferences saved");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const getModelsForProvider = (providerId: string) =>
    models.filter(
      (m) => m.provider_id === providerId && m.tool_call !== false
    );

  const AgentRow = ({
    label,
    providerKey,
    modelKey,
    optional = false,
  }: {
    label: string;
    providerKey: keyof Preferences;
    modelKey: keyof Preferences;
    optional?: boolean;
  }) => (
    <div className="grid grid-cols-[120px_1fr_1fr] items-center gap-3">
      <span className="text-sm text-[var(--color-muted-foreground)]">
        {label}
      </span>
      <select
        value={(form[providerKey] as string) || ""}
        onChange={(e) => {
          setForm((prev) => ({
            ...prev,
            [providerKey]: e.target.value,
            [modelKey]: "",
          }));
        }}
        className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
      >
        <option value="">{optional ? "Use default" : "Select provider..."}</option>
        {configuredProviders.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>
      <select
        value={(form[modelKey] as string) || ""}
        onChange={(e) =>
          setForm((prev) => ({ ...prev, [modelKey]: e.target.value }))
        }
        disabled={!form[providerKey]}
        className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)] disabled:opacity-50"
      >
        <option value="">Select model...</option>
        {form[providerKey] &&
          getModelsForProvider(form[providerKey] as string).map((m) => (
            <option key={m.id} value={m.id}>
              {m.name}
            </option>
          ))}
      </select>
    </div>
  );

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
        <div className="flex items-center gap-2">
          <Cpu className="h-4 w-4 text-[var(--color-primary)]" />
          <h2 className="font-semibold">AI Agent Configuration</h2>
        </div>
        <button
          onClick={() => saveMutation.mutate()}
          disabled={saveMutation.isPending}
          className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
        >
          <Save className="h-4 w-4" />
          Save
        </button>
      </div>
      <div className="space-y-4 p-5">
        <AgentRow
          label="Default"
          providerKey="default_provider"
          modelKey="default_model"
        />
        <div className="h-px bg-[var(--color-border)]" />
        <AgentRow
          label="Planner"
          providerKey="planner_provider"
          modelKey="planner_model"
          optional
        />
        <AgentRow
          label="Executor"
          providerKey="executor_provider"
          modelKey="executor_model"
          optional
        />
        <AgentRow
          label="Reviewer"
          providerKey="reviewer_provider"
          modelKey="reviewer_model"
          optional
        />
        <div className="h-px bg-[var(--color-border)]" />
        <AgentRow
          label="Embedding"
          providerKey="embedding_provider"
          modelKey="embedding_model"
          optional
        />
      </div>
    </div>
  );
}

/* ---------- Main Page ---------- */

export default function ProvidersPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"providers" | "models">(
    "providers"
  );

  const { data: providersData, isLoading: providersLoading } = useQuery({
    queryKey: ["providers"],
    queryFn: () => api.get<{ providers: Provider[] }>("/providers"),
  });

  const { data: modelsData, isLoading: modelsLoading } = useQuery({
    queryKey: ["models"],
    queryFn: () => api.get<{ models: Model[] }>("/models"),
  });

  const syncMutation = useMutation({
    mutationFn: () => api.post("/providers/sync"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["providers"] });
      queryClient.invalidateQueries({ queryKey: ["models"] });
      toast.success("Providers and models synced from models.dev");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const providers = providersData?.providers || [];
  const models = modelsData?.models || [];

  const lastSynced = providers.find((p) => p.last_synced_at)?.last_synced_at;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">AI Providers</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">
            Manage AI providers, models, and agent configuration
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastSynced && (
            <span className="text-xs text-[var(--color-muted-foreground)]">
              Last synced: {formatDate(lastSynced)}
            </span>
          )}
          <button
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
            className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm hover:bg-[var(--color-accent)] disabled:opacity-50"
          >
            <RefreshCw
              className={cn(
                "h-4 w-4",
                syncMutation.isPending && "animate-spin"
              )}
            />
            Sync from models.dev
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] p-1">
        <button
          onClick={() => setActiveTab("providers")}
          className={cn(
            "flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors",
            activeTab === "providers"
              ? "bg-[var(--color-primary)] text-[var(--color-primary-foreground)]"
              : "text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
          )}
        >
          Providers ({providers.length})
        </button>
        <button
          onClick={() => setActiveTab("models")}
          className={cn(
            "flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors",
            activeTab === "models"
              ? "bg-[var(--color-primary)] text-[var(--color-primary-foreground)]"
              : "text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
          )}
        >
          Models ({models.length})
        </button>
      </div>

      {/* Content */}
      {(providersLoading || modelsLoading) && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-[var(--color-muted-foreground)]" />
        </div>
      )}

      {!providersLoading && !modelsLoading && activeTab === "providers" && (
        <ProvidersList
          providers={providers}
          models={models}
          onRefresh={() => queryClient.invalidateQueries({ queryKey: ["providers"] })}
        />
      )}

      {!providersLoading && !modelsLoading && activeTab === "models" && (
        <ModelsTable models={models} />
      )}

      {/* Preferences */}
      {!providersLoading && !modelsLoading && (
        <PreferencesSection providers={providers} models={models} />
      )}
    </div>
  );
}
