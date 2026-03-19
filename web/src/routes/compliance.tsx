import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  ClipboardCheck, Loader2, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, AlertTriangle, FileText, Plus,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { cn, severityColor, severityBg } from "@/lib/utils";
import type { Mission } from "@/types";

interface ComplianceRequirement {
  id: string;
  title: string;
  description?: string;
  status: "compliant" | "non_compliant" | "partial" | "not_applicable";
  related_vulns?: number;
  remediation?: string;
  details?: string;
}

interface ComplianceReport {
  id?: string;
  framework: string;
  mission_id: string;
  score: number;
  total_requirements: number;
  compliant: number;
  non_compliant: number;
  partial: number;
  requirements: ComplianceRequirement[];
  findings?: ComplianceFinding[];
  generated_at?: string;
}

interface ComplianceFinding {
  vuln_title: string;
  severity: string;
  requirement_id: string;
  status: string;
}

const FRAMEWORKS = [
  { value: "owasp_top10", label: "OWASP Top 10" },
  { value: "cwe_top25", label: "CWE Top 25" },
  { value: "nist_csf", label: "NIST CSF" },
];

export default function Compliance() {
  const [showForm, setShowForm] = useState(false);
  const [selectedMission, setSelectedMission] = useState("");
  const [selectedFramework, setSelectedFramework] = useState("owasp_top10");
  const [report, setReport] = useState<ComplianceReport | null>(null);

  const { data: missionsData } = useQuery({
    queryKey: ["missions-all"],
    queryFn: () => api.get<{ missions: Mission[] }>("/missions?limit=100"),
  });

  const missions = missionsData?.missions ?? [];

  const generateMutation = useMutation({
    mutationFn: () =>
      api.post<ComplianceReport>("/compliance/report", {
        mission_id: selectedMission,
        framework: selectedFramework,
      }),
    onSuccess: (data) => {
      setReport(data);
      setShowForm(false);
      toast.success("Compliance report generated");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to generate report");
    },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Compliance Reports</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">
            Map findings against security frameworks
          </p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 rounded-lg bg-[var(--color-primary)] px-4 py-2 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90"
        >
          <Plus className="h-4 w-4" /> Generate Report
        </button>
      </div>

      {/* Generate Form */}
      {showForm && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-5">
          <h3 className="text-sm font-semibold mb-4">Generate Compliance Report</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">
                Mission
              </label>
              <select
                value={selectedMission}
                onChange={(e) => setSelectedMission(e.target.value)}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
              >
                <option value="">Select a mission...</option>
                {missions.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">
                Framework
              </label>
              <select
                value={selectedFramework}
                onChange={(e) => setSelectedFramework(e.target.value)}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
              >
                {FRAMEWORKS.map((fw) => (
                  <option key={fw.value} value={fw.value}>
                    {fw.label}
                  </option>
                ))}
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
              disabled={!selectedMission || generateMutation.isPending}
              className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
            >
              {generateMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <FileText className="h-4 w-4" />
              )}
              Generate
            </button>
          </div>
        </div>
      )}

      {/* Report View */}
      {report ? (
        <ComplianceReportView report={report} />
      ) : (
        !showForm && (
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-16 text-center">
            <ClipboardCheck className="mx-auto h-16 w-16 opacity-20 text-[var(--color-muted-foreground)]" />
            <p className="mt-4 text-[var(--color-muted-foreground)]">
              No compliance report loaded
            </p>
            <p className="mt-1 text-xs text-[var(--color-muted-foreground)]">
              Click "Generate Report" to map your findings against a security framework
            </p>
          </div>
        )
      )}
    </div>
  );
}

function ComplianceReportView({ report }: { report: ComplianceReport }) {
  const [expandedReq, setExpandedReq] = useState<string | null>(null);

  const frameworkLabel =
    FRAMEWORKS.find((fw) => fw.value === report.framework)?.label ?? report.framework;

  const scorePercent = Math.round(report.score);

  function scoreColor(score: number): string {
    if (score >= 80) return "text-emerald-400";
    if (score >= 60) return "text-amber-400";
    return "text-[#FF3366]";
  }

  function scoreBarColor(score: number): string {
    if (score >= 80) return "bg-emerald-400";
    if (score >= 60) return "bg-amber-400";
    return "bg-[#FF3366]";
  }

  function statusIcon(status: string) {
    switch (status) {
      case "compliant":
        return <CheckCircle2 className="h-5 w-5 text-emerald-400" />;
      case "non_compliant":
        return <XCircle className="h-5 w-5 text-[#FF3366]" />;
      case "partial":
        return <AlertTriangle className="h-5 w-5 text-amber-400" />;
      default:
        return <div className="h-5 w-5 rounded-full border-2 border-zinc-600" />;
    }
  }

  function statusBadge(status: string): string {
    switch (status) {
      case "compliant":
        return "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30";
      case "non_compliant":
        return "bg-[#FF3366]/15 text-[#FF3366] border border-[#FF3366]/30";
      case "partial":
        return "bg-amber-500/15 text-amber-400 border border-amber-500/30";
      default:
        return "bg-zinc-500/15 text-zinc-400 border border-zinc-500/30";
    }
  }

  return (
    <div className="space-y-6">
      {/* Score Card */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold">{frameworkLabel}</h2>
            {report.generated_at && (
              <p className="text-xs text-[var(--color-muted-foreground)]">
                Generated {new Date(report.generated_at).toLocaleString()}
              </p>
            )}
          </div>
          <div className="text-right">
            <p className={cn("text-4xl font-bold", scoreColor(scorePercent))}>{scorePercent}%</p>
            <p className="text-xs text-[var(--color-muted-foreground)]">Compliant</p>
          </div>
        </div>

        {/* Progress bar */}
        <div className="h-3 rounded-full bg-[var(--color-muted)]">
          <div
            className={cn("h-3 rounded-full transition-all duration-700", scoreBarColor(scorePercent))}
            style={{ width: `${scorePercent}%` }}
          />
        </div>

        {/* Summary stats */}
        <div className="mt-4 grid grid-cols-4 gap-4">
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-3 text-center">
            <p className="text-xl font-bold">{report.total_requirements}</p>
            <p className="text-xs text-[var(--color-muted-foreground)]">Total Requirements</p>
          </div>
          <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-center">
            <p className="text-xl font-bold text-emerald-400">{report.compliant}</p>
            <p className="text-xs text-[var(--color-muted-foreground)]">Compliant</p>
          </div>
          <div className="rounded-lg border border-[#FF3366]/20 bg-[#FF3366]/5 p-3 text-center">
            <p className="text-xl font-bold text-[#FF3366]">{report.non_compliant}</p>
            <p className="text-xs text-[var(--color-muted-foreground)]">Non-Compliant</p>
          </div>
          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-center">
            <p className="text-xl font-bold text-amber-400">{report.partial}</p>
            <p className="text-xs text-[var(--color-muted-foreground)]">Partial</p>
          </div>
        </div>
      </div>

      {/* Requirements list */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        <div className="border-b border-[var(--color-border)] px-5 py-3">
          <h3 className="font-semibold">Requirements</h3>
        </div>
        <div className="divide-y divide-[var(--color-border)]">
          {report.requirements.map((req) => (
            <div key={req.id}>
              <button
                onClick={() => setExpandedReq(expandedReq === req.id ? null : req.id)}
                className="w-full flex items-center gap-3 px-5 py-3 text-left hover:bg-[var(--color-muted)]/20 transition-colors"
              >
                {statusIcon(req.status)}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-[var(--color-muted-foreground)]">{req.id}</span>
                    <span className="font-medium text-sm truncate">{req.title}</span>
                  </div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {req.related_vulns != null && req.related_vulns > 0 && (
                    <span className="text-xs text-[var(--color-muted-foreground)]">
                      {req.related_vulns} vuln{req.related_vulns !== 1 ? "s" : ""}
                    </span>
                  )}
                  <span className={cn("rounded-full px-2 py-0.5 text-xs font-semibold capitalize", statusBadge(req.status))}>
                    {req.status.replace("_", " ")}
                  </span>
                  {expandedReq === req.id ? (
                    <ChevronDown className="h-4 w-4 text-[var(--color-muted-foreground)]" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-[var(--color-muted-foreground)]" />
                  )}
                </div>
              </button>

              {expandedReq === req.id && (
                <div className="px-5 pb-4 pl-14 space-y-3">
                  {req.description && (
                    <p className="text-sm text-[var(--color-muted-foreground)] leading-relaxed">
                      {req.description}
                    </p>
                  )}
                  {req.details && (
                    <div>
                      <p className="text-xs font-semibold text-[var(--color-muted-foreground)] mb-1">Details</p>
                      <p className="text-sm leading-relaxed">{req.details}</p>
                    </div>
                  )}
                  {req.remediation && (
                    <div>
                      <p className="text-xs font-semibold text-[var(--color-muted-foreground)] mb-1">Remediation</p>
                      <p className="text-sm leading-relaxed">{req.remediation}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Findings table */}
      {report.findings && report.findings.length > 0 && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
          <div className="border-b border-[var(--color-border)] px-5 py-3">
            <h3 className="font-semibold">Findings Mapping</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-xs font-semibold uppercase tracking-wider text-[var(--color-muted-foreground)]">
                  <th className="px-5 py-3 text-left">Vulnerability</th>
                  <th className="px-5 py-3 text-left">Severity</th>
                  <th className="px-5 py-3 text-left">Requirement</th>
                  <th className="px-5 py-3 text-left">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {report.findings.map((f, idx) => (
                  <tr key={idx} className="hover:bg-[var(--color-muted)]/20 transition-colors">
                    <td className="px-5 py-3 font-medium">{f.vuln_title}</td>
                    <td className="px-5 py-3">
                      <span className={cn("rounded border px-2 py-0.5 text-xs font-bold uppercase", severityBg(f.severity), severityColor(f.severity))}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-5 py-3 font-mono text-xs">{f.requirement_id}</td>
                    <td className="px-5 py-3 capitalize">{f.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
