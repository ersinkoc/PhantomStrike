import { useQuery } from "@tanstack/react-query";
import { Bug, X, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import { cn, severityColor, severityBg, formatDate } from "@/lib/utils";
import type { Vulnerability } from "@/types";
import { useState } from "react";

export default function Vulnerabilities() {
  const [filter, setFilter] = useState("");
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["vulns", filter],
    queryFn: () => api.get<{ vulnerabilities: Vulnerability[] }>(`/vulnerabilities?limit=100${filter ? `&severity=${filter}` : ""}`),
  });

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
                  {v.cvss_score != null && <span className="w-10 text-right font-mono text-sm">{v.cvss_score}</span>}
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
      {selectedVuln && <VulnDetailModal vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />}
    </div>
  );
}

function VulnDetailModal({ vuln, onClose }: { vuln: Vulnerability; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start justify-between border-b border-[var(--color-border)] p-5">
          <div>
            <div className="flex items-center gap-2">
              <span className={cn("rounded border px-2 py-0.5 text-xs font-bold uppercase", severityBg(vuln.severity), severityColor(vuln.severity))}>{vuln.severity}</span>
              {vuln.cvss_score && <span className="font-mono text-sm text-[var(--color-muted-foreground)]">CVSS: {vuln.cvss_score}</span>}
            </div>
            <h2 className="mt-2 text-xl font-bold">{vuln.title}</h2>
          </div>
          <button onClick={onClose} className="rounded p-1 hover:bg-[var(--color-accent)]">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-4 p-5">
          {/* Meta */}
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
            {vuln.cve_ids?.length ? (
              <div>
                <span className="text-[var(--color-muted-foreground)]">CVEs:</span>
                <div className="flex flex-wrap gap-1">
                  {vuln.cve_ids.map((cve) => (
                    <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 text-[var(--color-primary)] hover:underline">
                      {cve} <ExternalLink className="h-3 w-3" />
                    </a>
                  ))}
                </div>
              </div>
            ) : null}
          </div>

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
              <pre className="max-h-48 overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-3 text-xs font-mono">{vuln.evidence}</pre>
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
        </div>
      </div>
    </div>
  );
}
