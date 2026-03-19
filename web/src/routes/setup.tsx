import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield, ChevronRight, ChevronLeft, Loader2, Check,
  Eye, EyeOff, Zap, CheckCircle2, XCircle, ArrowRight,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

/* ---------- Types ---------- */

interface Provider {
  id: string;
  name: string;
  api_base_url: string;
  is_enabled: boolean;
  is_configured: boolean;
  is_local: boolean;
  sdk_type: string;
  env_var: string;
  model_count?: number;
  priority?: number;
}

interface Model {
  id: string;
  model_id: string;
  name: string;
  provider_id: string;
  provider_name?: string;
  family?: string;
  context_window?: number;
  supports_tool_calls?: boolean;
  supports_reasoning?: boolean;
}

interface SyncResult {
  providers_count: number;
  models_count: number;
}

/* ---------- Constants ---------- */

const STEPS = [
  { label: "Welcome", num: 1 },
  { label: "Sync", num: 2 },
  { label: "Providers", num: 3 },
  { label: "Defaults", num: 4 },
  { label: "Done", num: 5 },
];

/* ---------- Sub-components ---------- */

function ProgressBar({ step }: { step: number }) {
  return (
    <div className="flex items-center gap-2">
      {STEPS.map((s, i) => (
        <div key={s.num} className="flex items-center gap-2">
          <div
            className={cn(
              "flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-bold transition-colors",
              step > s.num
                ? "bg-[var(--color-primary)] text-[var(--color-primary-foreground)]"
                : step === s.num
                  ? "border-2 border-[var(--color-primary)] text-[var(--color-primary)]"
                  : "border border-[var(--color-border)] text-[var(--color-muted-foreground)]"
            )}
          >
            {step > s.num ? <Check className="h-4 w-4" /> : s.num}
          </div>
          {i < STEPS.length - 1 && (
            <div
              className={cn(
                "hidden h-px w-8 sm:block",
                step > s.num
                  ? "bg-[var(--color-primary)]"
                  : "bg-[var(--color-border)]"
              )}
            />
          )}
        </div>
      ))}
    </div>
  );
}

function ProviderRow({
  provider,
  apiKey,
  showKey,
  testStatus,
  onKeyChange,
  onToggleShowKey,
  onTest,
}: {
  provider: Provider;
  apiKey: string;
  showKey: boolean;
  testStatus: "idle" | "testing" | "success" | "error";
  onKeyChange: (v: string) => void;
  onToggleShowKey: () => void;
  onTest: () => void;
}) {
  const isLocal = provider.is_local === true;

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] p-4">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--color-accent)]">
          <Zap className="h-5 w-5 text-[var(--color-primary)]" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className="font-semibold capitalize">{provider.name}</p>
            {provider.is_configured && (
              <span className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-400">
                Configured
              </span>
            )}
          </div>
          <p className="text-xs text-[var(--color-muted-foreground)]">
            {provider.model_count != null && `${provider.model_count} models`}
          </p>
        </div>
      </div>

      {!isLocal && (
        <div className="mt-3 flex items-center gap-2">
          <div className="relative flex-1">
            <input
              type={showKey ? "text" : "password"}
              value={apiKey}
              onChange={(e) => onKeyChange(e.target.value)}
              placeholder="Enter API key..."
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 pr-10 text-sm outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
            />
            <button
              type="button"
              onClick={onToggleShowKey}
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
            onClick={onTest}
            disabled={!apiKey || testStatus === "testing"}
            className={cn(
              "flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors disabled:opacity-50",
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
            {testStatus === "testing"
              ? "Testing..."
              : testStatus === "success"
                ? "Connected"
                : testStatus === "error"
                  ? "Failed"
                  : "Test"}
          </button>
        </div>
      )}

      {provider.is_enabled && isLocal && (
        <div className="mt-3">
          <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-400">
            No API key required (local)
          </span>
          <button
            onClick={onTest}
            disabled={testStatus === "testing"}
            className={cn(
              "ml-2 inline-flex items-center gap-1.5 rounded-lg px-3 py-1 text-sm font-medium transition-colors disabled:opacity-50",
              testStatus === "success"
                ? "bg-emerald-500/10 text-emerald-400"
                : testStatus === "error"
                  ? "bg-red-500/10 text-red-400"
                  : "text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
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
            {testStatus === "success" ? "Connected" : testStatus === "error" ? "Failed" : "Test"}
          </button>
        </div>
      )}
    </div>
  );
}

/* ---------- Main Setup Wizard ---------- */

export default function SetupWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);

  /* Step 2 state */
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<SyncResult | null>(null);

  /* Step 3 state */
  const [providers, setProviders] = useState<Provider[]>([]);
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});
  const [testStatuses, setTestStatuses] = useState<Record<string, "idle" | "testing" | "success" | "error">>({});

  /* Step 4 state */
  const [defaultProvider, setDefaultProvider] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [plannerProvider, setPlannerProvider] = useState("");
  const [plannerModel, setPlannerModel] = useState("");
  const [executorProvider, setExecutorProvider] = useState("");
  const [executorModel, setExecutorModel] = useState("");
  const [reviewerProvider, setReviewerProvider] = useState("");
  const [reviewerModel, setReviewerModel] = useState("");
  const [models, setModels] = useState<Model[]>([]);
  const [completing, setCompleting] = useState(false);

  /* Load providers on step 3 */
  const POPULAR_IDS = [
    "anthropic", "openai", "groq", "ollama", "deepseek", "mistral",
    "google", "gemini", "openrouter", "together", "fireworks", "cohere",
  ];

  const loadProviders = useCallback(async () => {
    try {
      const res = await api.get<{ providers: Provider[] }>("/providers");
      const all = res.providers || [];
      // Show popular providers first, then enabled ones, then hide the rest
      const sorted = all
        .filter((p) => POPULAR_IDS.includes(p.id) || p.is_enabled || p.is_configured)
        .sort((a, b) => {
          const ai = POPULAR_IDS.indexOf(a.id);
          const bi = POPULAR_IDS.indexOf(b.id);
          if (ai >= 0 && bi >= 0) return ai - bi;
          if (ai >= 0) return -1;
          if (bi >= 0) return 1;
          return a.name.localeCompare(b.name);
        });
      setProviders(sorted);
    } catch {
      // providers may not exist yet
    }
  }, []);

  const loadModels = useCallback(async () => {
    try {
      const res = await api.get<{ models: Model[] }>("/models");
      setModels(res.models || []);
    } catch {
      // models may not exist yet
    }
  }, []);

  useEffect(() => {
    if (step === 3) {
      loadProviders();
    }
    if (step === 4) {
      loadProviders();
      loadModels();
    }
  }, [step, loadProviders, loadModels]);

  /* Handlers */

  const handleSync = async () => {
    setSyncing(true);
    try {
      const result = await api.post<SyncResult>("/providers/sync");
      setSyncResult(result);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Sync failed");
    } finally {
      setSyncing(false);
    }
  };

  const handleTestConnection = async (provider: Provider) => {
    setTestStatuses((prev) => ({ ...prev, [provider.id]: "testing" }));

    try {
      // Save key first if there is one
      const key = apiKeys[provider.id];
      if (key && !provider.is_local) {
        await api.put(`/providers/${provider.id}`, { api_key: key, is_enabled: true });
      }

      await api.post(`/providers/${provider.id}/test`);
      setTestStatuses((prev) => ({ ...prev, [provider.id]: "success" }));
      toast.success(`${provider.name} connected successfully`);
      // Refresh provider list for updated is_configured
      loadProviders();
    } catch (err) {
      setTestStatuses((prev) => ({ ...prev, [provider.id]: "error" }));
      toast.error(
        err instanceof Error ? err.message : `${provider.name} connection failed`
      );
    }
  };

  const handleCompleteSetup = async () => {
    setCompleting(true);
    try {
      // Save preferences
      const prefs: Record<string, { provider_id: string; model_id: string }> = {
        default: { provider_id: defaultProvider, model_id: defaultModel },
      };
      if (plannerProvider && plannerModel) {
        prefs.planner = { provider_id: plannerProvider, model_id: plannerModel };
      }
      if (executorProvider && executorModel) {
        prefs.executor = { provider_id: executorProvider, model_id: executorModel };
      }
      if (reviewerProvider && reviewerModel) {
        prefs.reviewer = { provider_id: reviewerProvider, model_id: reviewerModel };
      }
      await api.put("/preferences", prefs);

      // Complete setup
      await api.post("/setup/complete");

      setStep(5);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to complete setup");
    } finally {
      setCompleting(false);
    }
  };

  const configuredProviders = providers.filter(
    (p) => p.is_enabled && (p.is_configured || p.is_local)
  );

  const hasConfigured = configuredProviders.length > 0;

  const filteredModels = (providerId: string, toolCallOnly = true) => {
    let filtered = models.filter((m) => m.provider_id === providerId);
    if (toolCallOnly) {
      filtered = filtered.filter((m) => m.supports_tool_calls !== false);
    }
    return filtered;
  };

  /* Auto-trigger sync on step 2 */
  useEffect(() => {
    if (step === 2 && !syncing && !syncResult) {
      handleSync();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--color-background)] p-4">
      <div className="w-full max-w-2xl space-y-8">
        {/* Progress */}
        <div className="flex justify-center">
          <ProgressBar step={step} />
        </div>

        {/* Card */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-8">
          {/* ---- Step 1: Welcome ---- */}
          {step === 1 && (
            <div className="space-y-6 text-center">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-primary)]/10">
                <Shield className="h-9 w-9 text-[var(--color-primary)]" />
              </div>
              <div>
                <h1 className="text-3xl font-bold">
                  Welcome to Phantom
                  <span className="text-[var(--color-primary)]">Strike</span>
                </h1>
                <p className="mt-2 text-[var(--color-muted-foreground)]">
                  Let's configure your AI providers to get started with
                  autonomous penetration testing.
                </p>
              </div>
              <button
                onClick={() => setStep(2)}
                className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-primary)] px-6 py-3 text-sm font-semibold text-[var(--color-primary-foreground)] transition-opacity hover:opacity-90"
              >
                Get Started
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}

          {/* ---- Step 2: Sync ---- */}
          {step === 2 && (
            <div className="space-y-6 text-center">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-primary)]/10">
                {syncing ? (
                  <Loader2 className="h-9 w-9 animate-spin text-[var(--color-primary)]" />
                ) : (
                  <CheckCircle2 className="h-9 w-9 text-[var(--color-primary)]" />
                )}
              </div>
              <div>
                <h2 className="text-2xl font-bold">
                  {syncing
                    ? "Syncing AI Providers..."
                    : "Sync Complete"}
                </h2>
                <p className="mt-2 text-[var(--color-muted-foreground)]">
                  {syncing
                    ? "Fetching available AI providers and models from models.dev..."
                    : syncResult
                      ? `Found ${syncResult.providers_count} providers with ${syncResult.models_count} models`
                      : "Ready to continue"}
                </p>
              </div>
              {!syncing && (
                <button
                  onClick={() => setStep(3)}
                  className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-primary)] px-6 py-3 text-sm font-semibold text-[var(--color-primary-foreground)] transition-opacity hover:opacity-90"
                >
                  Continue
                  <ChevronRight className="h-4 w-4" />
                </button>
              )}
            </div>
          )}

          {/* ---- Step 3: Configure Providers ---- */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-2xl font-bold">Configure Providers</h2>
                <p className="mt-1 text-sm text-[var(--color-muted-foreground)]">
                  Enable at least one AI provider and enter your API key.
                </p>
              </div>

              <div className="max-h-[28rem] space-y-3 overflow-y-auto pr-1">
                {providers.map((provider) => (
                  <ProviderRow
                    key={provider.id}
                    provider={provider}
                    apiKey={apiKeys[provider.id] || ""}
                    showKey={showKeys[provider.id] || false}
                    testStatus={testStatuses[provider.id] || "idle"}
                    onKeyChange={(v) =>
                      setApiKeys((prev) => ({ ...prev, [provider.id]: v }))
                    }
                    onToggleShowKey={() =>
                      setShowKeys((prev) => ({
                        ...prev,
                        [provider.id]: !prev[provider.id],
                      }))
                    }
                    onTest={() => handleTestConnection(provider)}
                  />
                ))}
                {providers.length === 0 && (
                  <div className="py-8 text-center text-sm text-[var(--color-muted-foreground)]">
                    No providers found. Try syncing again.
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between">
                <button
                  onClick={() => setStep(2)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
                >
                  <ChevronLeft className="h-4 w-4" /> Back
                </button>
                <button
                  onClick={() => setStep(4)}
                  disabled={!hasConfigured}
                  className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-primary)] px-6 py-2.5 text-sm font-semibold text-[var(--color-primary-foreground)] transition-opacity hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Continue
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
              {!hasConfigured && (
                <p className="text-center text-xs text-[var(--color-muted-foreground)]">
                  Configure at least one provider to continue.
                </p>
              )}
            </div>
          )}

          {/* ---- Step 4: Select Default Model ---- */}
          {step === 4 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-2xl font-bold">Select Default Model</h2>
                <p className="mt-1 text-sm text-[var(--color-muted-foreground)]">
                  Choose the default AI model for PhantomStrike agents.
                </p>
              </div>

              {/* Default */}
              <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-4 space-y-3">
                <p className="text-sm font-semibold text-[var(--color-foreground)]">
                  Default Agent
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                      Provider
                    </label>
                    <select
                      value={defaultProvider}
                      onChange={(e) => {
                        setDefaultProvider(e.target.value);
                        setDefaultModel("");
                      }}
                      className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
                    >
                      <option value="">Select provider...</option>
                      {configuredProviders.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                      Model
                    </label>
                    <select
                      value={defaultModel}
                      onChange={(e) => setDefaultModel(e.target.value)}
                      disabled={!defaultProvider}
                      className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)] disabled:opacity-50"
                    >
                      <option value="">Select model...</option>
                      {defaultProvider &&
                        filteredModels(defaultProvider).map((m) => (
                          <option key={m.id} value={m.model_id}>
                            {m.name}
                          </option>
                        ))}
                    </select>
                  </div>
                </div>
              </div>

              {/* Optional overrides */}
              <details className="group">
                <summary className="cursor-pointer text-sm text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]">
                  Advanced: Agent-specific overrides (optional)
                </summary>
                <div className="mt-3 space-y-4">
                  {/* Planner */}
                  <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-4 space-y-3">
                    <p className="text-sm font-semibold text-[var(--color-foreground)]">
                      Planner Agent
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                          Provider
                        </label>
                        <select
                          value={plannerProvider}
                          onChange={(e) => {
                            setPlannerProvider(e.target.value);
                            setPlannerModel("");
                          }}
                          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
                        >
                          <option value="">Use default</option>
                          {configuredProviders.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                          Model
                        </label>
                        <select
                          value={plannerModel}
                          onChange={(e) => setPlannerModel(e.target.value)}
                          disabled={!plannerProvider}
                          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)] disabled:opacity-50"
                        >
                          <option value="">Select model...</option>
                          {plannerProvider &&
                            filteredModels(plannerProvider).map((m) => (
                              <option key={m.id} value={m.model_id}>
                                {m.name}
                              </option>
                            ))}
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Executor */}
                  <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-4 space-y-3">
                    <p className="text-sm font-semibold text-[var(--color-foreground)]">
                      Executor Agent
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                          Provider
                        </label>
                        <select
                          value={executorProvider}
                          onChange={(e) => {
                            setExecutorProvider(e.target.value);
                            setExecutorModel("");
                          }}
                          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
                        >
                          <option value="">Use default</option>
                          {configuredProviders.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                          Model
                        </label>
                        <select
                          value={executorModel}
                          onChange={(e) => setExecutorModel(e.target.value)}
                          disabled={!executorProvider}
                          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)] disabled:opacity-50"
                        >
                          <option value="">Select model...</option>
                          {executorProvider &&
                            filteredModels(executorProvider).map((m) => (
                              <option key={m.id} value={m.model_id}>
                                {m.name}
                              </option>
                            ))}
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Reviewer */}
                  <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-4 space-y-3">
                    <p className="text-sm font-semibold text-[var(--color-foreground)]">
                      Reviewer Agent
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                          Provider
                        </label>
                        <select
                          value={reviewerProvider}
                          onChange={(e) => {
                            setReviewerProvider(e.target.value);
                            setReviewerModel("");
                          }}
                          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
                        >
                          <option value="">Use default</option>
                          {configuredProviders.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-xs text-[var(--color-muted-foreground)]">
                          Model
                        </label>
                        <select
                          value={reviewerModel}
                          onChange={(e) => setReviewerModel(e.target.value)}
                          disabled={!reviewerProvider}
                          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)] disabled:opacity-50"
                        >
                          <option value="">Select model...</option>
                          {reviewerProvider &&
                            filteredModels(reviewerProvider).map((m) => (
                              <option key={m.id} value={m.model_id}>
                                {m.name}
                              </option>
                            ))}
                        </select>
                      </div>
                    </div>
                  </div>
                </div>
              </details>

              <div className="flex items-center justify-between">
                <button
                  onClick={() => setStep(3)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
                >
                  <ChevronLeft className="h-4 w-4" /> Back
                </button>
                <button
                  onClick={handleCompleteSetup}
                  disabled={!defaultProvider || !defaultModel || completing}
                  className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-primary)] px-6 py-2.5 text-sm font-semibold text-[var(--color-primary-foreground)] transition-opacity hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {completing ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : null}
                  Complete Setup
                </button>
              </div>
            </div>
          )}

          {/* ---- Step 5: Done ---- */}
          {step === 5 && (
            <div className="space-y-6 text-center">
              <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-emerald-500/10">
                <CheckCircle2
                  className="h-12 w-12 text-emerald-400"
                  style={{
                    animation: "fadeIn 0.5s ease-out, pulse 2s ease-in-out 0.5s",
                  }}
                />
              </div>
              <div>
                <h2 className="text-2xl font-bold">Setup Complete!</h2>
                <p className="mt-2 text-[var(--color-muted-foreground)]">
                  PhantomStrike is ready. Your AI providers are configured and
                  ready to hunt.
                </p>
              </div>
              <button
                onClick={() => navigate("/")}
                className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-primary)] px-6 py-3 text-sm font-semibold text-[var(--color-primary-foreground)] transition-opacity hover:opacity-90"
              >
                Go to Dashboard
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {/* Step indicator text */}
        <p className="text-center text-xs text-[var(--color-muted-foreground)]">
          Step {step} of {STEPS.length}
        </p>
      </div>
    </div>
  );
}
