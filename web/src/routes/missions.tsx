import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus, Crosshair, FileCode, Loader2, X } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { cn, statusColor, formatDate } from "@/lib/utils";
import type { Mission } from "@/types";

interface MissionTemplate {
  id: string;
  name: string;
  description?: string;
  mode: string;
  depth: string;
  tags?: string[];
}

export default function Missions() {
  const [showCreate, setShowCreate] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["missions"],
    queryFn: () => api.get<{ missions: Mission[] }>("/missions?limit=50"),
  });

  const createMutation = useMutation({
    mutationFn: (data: { name: string; target: { scope: string[] }; mode: string; depth: string }) =>
      api.post("/missions", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["missions"] });
      setShowCreate(false);
      toast.success("Mission created");
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Missions</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">Security test engagements</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowTemplates(true)}
            className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-foreground)]"
          >
            <FileCode className="h-4 w-4" /> From Template
          </button>
          <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 rounded-lg bg-[var(--color-primary)] px-4 py-2 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90">
            <Plus className="h-4 w-4" /> New Mission
          </button>
        </div>
      </div>

      {/* Create Modal */}
      {showCreate && <CreateMissionModal onClose={() => setShowCreate(false)} onSubmit={(d) => createMutation.mutate(d)} isLoading={createMutation.isPending} />}

      {/* Template Picker */}
      {showTemplates && (
        <TemplatePicker
          onClose={() => setShowTemplates(false)}
          onCreated={() => {
            setShowTemplates(false);
            queryClient.invalidateQueries({ queryKey: ["missions"] });
          }}
        />
      )}

      {/* Mission List */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        {isLoading ? (
          <div className="p-8 text-center text-[var(--color-muted-foreground)]">Loading...</div>
        ) : data?.missions?.length ? (
          <div className="divide-y divide-[var(--color-border)]">
            {data.missions.map((m) => (
              <Link key={m.id} to={`/missions/${m.id}`} className="flex items-center justify-between px-5 py-4 hover:bg-[var(--color-accent)] transition-colors">
                <div className="flex items-center gap-3">
                  <Crosshair className="h-5 w-5 text-[var(--color-primary)]" />
                  <div>
                    <p className="font-medium">{m.name}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)]">{m.mode} · {m.depth} · {formatDate(m.created_at)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="w-32 rounded-full bg-[var(--color-muted)] h-2">
                    <div className="h-2 rounded-full bg-[var(--color-primary)] transition-all" style={{ width: `${m.progress}%` }} />
                  </div>
                  <span className={cn("text-sm font-medium capitalize", statusColor(m.status))}>{m.status}</span>
                </div>
              </Link>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center text-[var(--color-muted-foreground)]">
            <Crosshair className="mx-auto h-10 w-10 opacity-30" />
            <p className="mt-3">No missions yet</p>
          </div>
        )}
      </div>
    </div>
  );
}

function CreateMissionModal({ onClose, onSubmit, isLoading }: { onClose: () => void; onSubmit: (d: any) => void; isLoading: boolean }) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [mode, setMode] = useState("autonomous");
  const [depth, setDepth] = useState("standard");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-lg rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-6" onClick={(e) => e.stopPropagation()}>
        <h2 className="mb-4 text-lg font-bold">New Mission</h2>
        <form onSubmit={(e) => { e.preventDefault(); onSubmit({ name, target: { scope: scope.split("\n").filter(Boolean) }, mode, depth }); }} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm text-[var(--color-muted-foreground)]">Mission Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} required className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]" placeholder="ACME Corp External Pentest" />
          </div>
          <div>
            <label className="mb-1 block text-sm text-[var(--color-muted-foreground)]">Target Scope (one per line)</label>
            <textarea value={scope} onChange={(e) => setScope(e.target.value)} required rows={3} className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm font-mono outline-none focus:border-[var(--color-primary)]" placeholder={"*.example.com\n10.0.0.0/24"} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm text-[var(--color-muted-foreground)]">Mode</label>
              <select value={mode} onChange={(e) => setMode(e.target.value)} className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none">
                <option value="autonomous">Autonomous</option>
                <option value="guided">Guided</option>
                <option value="manual">Manual</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-sm text-[var(--color-muted-foreground)]">Depth</label>
              <select value={depth} onChange={(e) => setDepth(e.target.value)} className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none">
                <option value="quick">Quick</option>
                <option value="standard">Standard</option>
                <option value="deep">Deep</option>
                <option value="exhaustive">Exhaustive</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm hover:bg-[var(--color-accent)]">Cancel</button>
            <button type="submit" disabled={isLoading} className="rounded-lg bg-[var(--color-primary)] px-4 py-2 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50">
              {isLoading ? "Creating..." : "Create Mission"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function TemplatePicker({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [selectedTemplate, setSelectedTemplate] = useState<MissionTemplate | null>(null);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["mission-templates"],
    queryFn: () => api.get<{ templates: MissionTemplate[] }>("/missions/templates"),
  });

  const templates = data?.templates ?? [];

  const createFromTemplateMutation = useMutation({
    mutationFn: () =>
      api.post("/missions/from-template", {
        template_id: selectedTemplate!.id,
        name: name || selectedTemplate!.name,
        target: { scope: scope.split("\n").filter(Boolean) },
      }),
    onSuccess: () => {
      toast.success("Mission created from template");
      onCreated();
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to create mission from template");
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[85vh] overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] flex flex-col" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-4">
          <div>
            <h2 className="text-lg font-bold">Create from Template</h2>
            <p className="text-xs text-[var(--color-muted-foreground)]">
              {selectedTemplate ? "Configure your mission" : "Select a template to get started"}
            </p>
          </div>
          <button onClick={onClose} className="rounded p-1 hover:bg-[var(--color-accent)]">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5">
          {selectedTemplate ? (
            /* Template configuration form */
            <div className="space-y-4">
              <div className="rounded-lg border border-[var(--color-primary)]/30 bg-[var(--color-primary)]/5 p-3">
                <div className="flex items-center gap-2">
                  <FileCode className="h-4 w-4 text-[var(--color-primary)]" />
                  <span className="font-medium text-sm">{selectedTemplate.name}</span>
                  <span className="rounded bg-[var(--color-muted)] px-1.5 py-0.5 text-xs">{selectedTemplate.mode}</span>
                  <span className="rounded bg-[var(--color-muted)] px-1.5 py-0.5 text-xs">{selectedTemplate.depth}</span>
                </div>
                {selectedTemplate.description && (
                  <p className="mt-1 text-xs text-[var(--color-muted-foreground)]">{selectedTemplate.description}</p>
                )}
              </div>

              <div>
                <label className="mb-1 block text-sm text-[var(--color-muted-foreground)]">Mission Name</label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={selectedTemplate.name}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm outline-none focus:border-[var(--color-primary)]"
                />
              </div>

              <div>
                <label className="mb-1 block text-sm text-[var(--color-muted-foreground)]">Target Scope (one per line)</label>
                <textarea
                  value={scope}
                  onChange={(e) => setScope(e.target.value)}
                  rows={3}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm font-mono outline-none focus:border-[var(--color-primary)]"
                  placeholder={"*.example.com\n10.0.0.0/24"}
                />
              </div>

              <div className="flex gap-2 justify-end pt-2">
                <button
                  onClick={() => setSelectedTemplate(null)}
                  className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
                >
                  Back
                </button>
                <button
                  onClick={() => createFromTemplateMutation.mutate()}
                  disabled={!scope.trim() || createFromTemplateMutation.isPending}
                  className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-4 py-2 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
                >
                  {createFromTemplateMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Crosshair className="h-4 w-4" />
                  )}
                  Create Mission
                </button>
              </div>
            </div>
          ) : (
            /* Template list */
            <>
              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-6 w-6 animate-spin text-[var(--color-muted-foreground)]" />
                </div>
              ) : templates.length > 0 ? (
                <div className="space-y-2">
                  {templates.map((tpl) => (
                    <button
                      key={tpl.id}
                      onClick={() => {
                        setSelectedTemplate(tpl);
                        setName(tpl.name);
                      }}
                      className="w-full rounded-lg border border-[var(--color-border)] p-4 text-left transition-colors hover:bg-[var(--color-accent)] hover:border-[var(--color-primary)]/30"
                    >
                      <div className="flex items-center gap-2">
                        <FileCode className="h-5 w-5 text-[var(--color-primary)]" />
                        <span className="font-medium">{tpl.name}</span>
                      </div>
                      {tpl.description && (
                        <p className="mt-1 text-sm text-[var(--color-muted-foreground)]">{tpl.description}</p>
                      )}
                      <div className="mt-2 flex items-center gap-2">
                        <span className="rounded bg-[var(--color-muted)] px-2 py-0.5 text-xs capitalize">{tpl.mode}</span>
                        <span className="rounded bg-[var(--color-muted)] px-2 py-0.5 text-xs capitalize">{tpl.depth}</span>
                        {tpl.tags?.map((tag) => (
                          <span key={tag} className="rounded bg-[var(--color-primary)]/10 px-2 py-0.5 text-xs text-[var(--color-primary)]">{tag}</span>
                        ))}
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="py-12 text-center text-[var(--color-muted-foreground)]">
                  <FileCode className="mx-auto h-10 w-10 opacity-30" />
                  <p className="mt-3">No templates available</p>
                  <p className="mt-1 text-xs">Templates can be created from completed missions</p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
