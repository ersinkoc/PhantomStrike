import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bug, X, ExternalLink, Save, Trash2, Loader2, Crosshair } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { cn, severityColor, severityBg, formatDate } from "@/lib/utils";
import type { Vulnerability } from "@/types";
import { useState } from "react";

const STATUSES = ["open", "confirmed", "exploited", "fixed", "false_positive", "accepted"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function Vulnerabilities() {
  const [filter, setFilter] = useState("");
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["vulns", filter],
    queryFn: () => api.get<{ vulnerabilities: Vulnerability[] }>(`/vulnerabilities?limit=100${filter ? `&severity=${filter}` : ""}`),
  });

  const handleClose = () => setSelectedVuln(null);

  const handleSaved = (updated: Vulnerability) => {
    setSelectedVuln(updated);
    queryClient.invalidateQueries({ queryKey: ["vulns"] });
  };

  const handleDeleted = () => {
    setSelectedVuln(null);
    queryClient.invalidateQueries({ queryKey: ["vulns"] });
  };

  const severities = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Vulnerabilities</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">All discovered security findings</p>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <button onClick={() => setFilter("")} className={cn("rounded-lg px-3 py-1.5 text-sm", !filter ? "bg-[var(--color-primary)]/10 text-[var(--color-primary)]" : "text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]")}>All</button>
        {severities.map((s) => (
          <button key={s} onClick={() => setFilter(s)} className={cn("rounded-lg px-3 py-1.5 text-sm capitalize", filter === s ? `${severityBg(s)} ${severityColor(s)} border` : "text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]")}>{s}</button>
        ))}
      </div>

      {/* List */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        {isLoading ? (
          <div className="p-8 text-center text-[var(--color-muted-foreground)]">Loading...</div>
        ) : data?.vulnerabilities?.length ? (
          <div className="divide-y divide-[var(--color-border)]">
            {data.vulnerabilities.map((v) => (
              <div key={v.id} onClick={() => setSelectedVuln(v)} className="flex items-center justify-between px-5 py-4 hover:bg-[var(--color-accent)] transition-colors cursor-pointer">
                <div className="flex items-center gap-3">
                  <Bug className={cn("h-5 w-5", severityColor(v.severity))} />
                  <div>
                    <p className="font-medium">{v.title}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)]">
                      {v.target && <span>{v.target} · </span>}
                      {v.found_by && <span>{v.found_by} · </span>}
                      {formatDate(v.created_at)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="rounded bg-[var(--color-muted)] px-2 py-0.5 text-xs capitalize">{v.status}</span>
                  {v.cvss_score != null && (
                    <span className={cn("w-10 text-right font-mono text-sm font-bold", cvssColor(v.cvss_score))}>
                      {v.cvss_score}
                    </span>
                  )}
                  <span className={cn("w-16 rounded border px-2 py-0.5 text-center text-xs font-bold uppercase", severityBg(v.severity), severityColor(v.severity))}>{v.severity}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center text-[var(--color-muted-foreground)]">
            <Bug className="mx-auto h-10 w-10 opacity-30" />
            <p className="mt-3">No vulnerabilities found</p>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedVuln && (
        <VulnDetailModal
          vuln={selectedVuln}
          onClose={handleClose}
          onSaved={handleSaved}
          onDeleted={handleDeleted}
        />
      )}
    </div>
  );
}

function cvssColor(score: number): string {
  if (score >= 9.0) return "text-[#FF3366]";
  if (score >= 7.0) return "text-orange-500";
  if (score >= 4.0) return "text-amber-500";
  if (score >= 0.1) return "text-blue-500";
  return "text-zinc-400";
}

function cvssLabel(score: number): string {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >= 0.1) return "Low";
  return "None";
}

function VulnDetailModal({
  vuln,
  onClose,
  onSaved,
  onDeleted,
}: {
  vuln: Vulnerability;
  onClose: () => void;
  onSaved: (v: Vulnerability) => void;
  onDeleted: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Editable fields
  const [editTitle, setEditTitle] = useState(vuln.title);
  const [editStatus, setEditStatus] = useState(vuln.status);
  const [editSeverity, setEditSeverity] = useState(vuln.severity);
  const [editDescription, setEditDescription] = useState(vuln.description ?? "");
  const [editRemediation, setEditRemediation] = useState(vuln.remediation ?? "");

  const updateMutation = useMutation({
    mutationFn: () =>
      api.put<Vulnerability>(`/vulnerabilities/${vuln.id}`, {
        title: editTitle,
        status: editStatus,
        severity: editSeverity,
        description: editDescription,
        remediation: editRemediation,
      }),
    onSuccess: (data) => {
      toast.success("Vulnerability updated");
      setEditing(false);
      onSaved(data);
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to update vulnerability");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/vulnerabilities/${vuln.id}`),
    onSuccess: () => {
      toast.success("Vulnerability deleted");
      onDeleted();
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to delete vulnerability");
    },
  });

  const startEdit = () => {
    setEditTitle(vuln.title);
    setEditStatus(vuln.status);
    setEditSeverity(vuln.severity);
    setEditDescription(vuln.description ?? "");
    setEditRemediation(vuln.remediation ?? "");
    setEditing(true);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start justify-between border-b border-[var(--color-border)] p-5">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={cn("rounded border px-2 py-0.5 text-xs font-bold uppercase", severityBg(vuln.severity), severityColor(vuln.severity))}>{vuln.severity}</span>
              {vuln.cvss_score != null && (
                <span className={cn("rounded px-2 py-0.5 text-xs font-bold", cvssColor(vuln.cvss_score), "bg-[var(--color-muted)]")}>
                  CVSS {vuln.cvss_score} ({cvssLabel(vuln.cvss_score)})
                </span>
              )}
              <span className="rounded bg-[var(--color-muted)] px-2 py-0.5 text-xs capitalize">{vuln.status}</span>
            </div>
            <h2 className="mt-2 text-xl font-bold">{vuln.title}</h2>
          </div>
          <button onClick={onClose} className="rounded p-1 hover:bg-[var(--color-accent)] ml-3 shrink-0">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-4 p-5">
          {editing ? (
            /* Edit Mode */
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">Title</label>
                <input
                  type="text"
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">Status</label>
                  <select
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value)}
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                  >
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>
                        {s.replace("_", " ")}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">Severity</label>
                  <select
                    value={editSeverity}
                    onChange={(e) => setEditSeverity(e.target.value as Vulnerability["severity"])}
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                  >
                    {SEVERITIES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">Description</label>
                <textarea
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  rows={4}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">Remediation</label>
                <textarea
                  value={editRemediation}
                  onChange={(e) => setEditRemediation(e.target.value)}
                  rows={3}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>
              <div className="flex gap-2 justify-end pt-2">
                <button
                  onClick={() => setEditing(false)}
                  className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-muted)]/30"
                >
                  Cancel
                </button>
                <button
                  onClick={() => updateMutation.mutate()}
                  disabled={updateMutation.isPending}
                  className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
                >
                  {updateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                  Save Changes
                </button>
              </div>
            </div>
          ) : (
            /* View Mode */
            <>
              {/* Meta Grid */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-[var(--color-muted-foreground)]">Target:</span>
                  <p className="font-mono">{vuln.target || "N/A"}</p>
                </div>
                <div>
                  <span className="text-[var(--color-muted-foreground)]">Component:</span>
                  <p>{vuln.affected_component || "N/A"}</p>
                </div>
                <div>
                  <span className="text-[var(--color-muted-foreground)]">Status:</span>
                  <p className="capitalize">{vuln.status}</p>
                </div>
                <div>
                  <span className="text-[var(--color-muted-foreground)]">Found by:</span>
                  <p>{vuln.found_by || "Unknown"}</p>
                </div>
                <div>
                  <span className="text-[var(--color-muted-foreground)]">Created:</span>
                  <p>{formatDate(vuln.created_at)}</p>
                </div>
                {vuln.cwe_id && (
                  <div>
                    <span className="text-[var(--color-muted-foreground)]">CWE:</span>
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace("CWE-", "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-[var(--color-primary)] hover:underline"
                    >
                      {vuln.cwe_id} <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                )}
                {vuln.cve_ids?.length ? (
                  <div className="col-span-2">
                    <span className="text-[var(--color-muted-foreground)]">CVEs:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {vuln.cve_ids.map((cve) => (
                        <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 rounded bg-[var(--color-primary)]/10 px-2 py-0.5 text-xs text-[var(--color-primary)] hover:underline">
                          {cve} <ExternalLink className="h-3 w-3" />
                        </a>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>

              {/* Mission context */}
              {vuln.mission_id && (
                <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-3">
                  <div className="flex items-center gap-2 text-sm">
                    <Crosshair className="h-4 w-4 text-[var(--color-primary)]" />
                    <span className="text-[var(--color-muted-foreground)]">Mission:</span>
                    <a
                      href={`/missions/${vuln.mission_id}`}
                      className="text-[var(--color-primary)] hover:underline font-mono text-xs"
                    >
                      {vuln.mission_id.slice(0, 8)}...
                    </a>
                    {vuln.found_by && (
                      <>
                        <span className="text-[var(--color-muted-foreground)]">via</span>
                        <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-xs text-blue-400 border border-blue-500/30">
                          {vuln.found_by}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* CVSS Score Badge */}
              {vuln.cvss_score != null && (
                <div className="flex items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-3">
                  <div className={cn("text-2xl font-bold", cvssColor(vuln.cvss_score))}>
                    {vuln.cvss_score}
                  </div>
                  <div>
                    <p className={cn("font-semibold text-sm", cvssColor(vuln.cvss_score))}>
                      {cvssLabel(vuln.cvss_score)}
                    </p>
                    {vuln.cvss_vector && (
                      <p className="font-mono text-xs text-[var(--color-muted-foreground)]">{vuln.cvss_vector}</p>
                    )}
                  </div>
                  {/* Visual bar */}
                  <div className="flex-1 ml-4">
                    <div className="h-2 rounded-full bg-[var(--color-muted)]">
                      <div
                        className={cn("h-2 rounded-full transition-all", cvssColor(vuln.cvss_score).replace("text-", "bg-"))}
                        style={{ width: `${(vuln.cvss_score / 10) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Description */}
              {vuln.description && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-[var(--color-muted-foreground)]">Description</h3>
                  <p className="text-sm leading-relaxed">{vuln.description}</p>
                </div>
              )}

              {/* Evidence */}
              {vuln.evidence && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-[var(--color-muted-foreground)]">Evidence</h3>
                  <pre className="max-h-60 overflow-auto rounded-lg border border-[var(--color-border)] bg-[#0D0D12] p-3 text-xs font-mono text-zinc-300">{vuln.evidence}</pre>
                </div>
              )}

              {/* Remediation */}
              {vuln.remediation && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-[var(--color-muted-foreground)]">Remediation</h3>
                  <p className="text-sm leading-relaxed">{vuln.remediation}</p>
                </div>
              )}

              {/* Tags */}
              {vuln.tags?.length ? (
                <div className="flex flex-wrap gap-2 pt-2">
                  {vuln.tags.map((tag) => (
                    <span key={tag} className="rounded bg-[var(--color-muted)] px-2 py-0.5 text-xs">{tag}</span>
                  ))}
                </div>
              ) : null}
            </>
          )}
        </div>

        {/* Footer actions */}
        {!editing && (
          <div className="flex items-center justify-between border-t border-[var(--color-border)] p-5">
            <div>
              {confirmDelete ? (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-[var(--color-destructive)]">Are you sure?</span>
                  <button
                    onClick={() => deleteMutation.mutate()}
                    disabled={deleteMutation.isPending}
                    className="flex items-center gap-1 rounded-lg bg-[var(--color-destructive)] px-3 py-1.5 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-50"
                  >
                    {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                    Confirm Delete
                  </button>
                  <button
                    onClick={() => setConfirmDelete(false)}
                    className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-muted)]/30"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmDelete(true)}
                  className="flex items-center gap-1.5 rounded-lg border border-[var(--color-destructive)]/30 px-3 py-1.5 text-sm text-[var(--color-destructive)] hover:bg-[var(--color-destructive)]/10"
                >
                  <Trash2 className="h-4 w-4" /> Delete
                </button>
              )}
            </div>
            <button
              onClick={startEdit}
              className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90"
            >
              <Save className="h-4 w-4" /> Edit
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
