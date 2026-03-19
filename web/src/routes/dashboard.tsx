import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Crosshair, Bug, Shield, Activity, Plus, RefreshCw, FileText, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { cn, severityColor } from "@/lib/utils";
import type { Mission, VulnStats } from "@/types";

function StatCard({ icon: Icon, label, value, color }: { icon: typeof Crosshair; label: string; value: string | number; color: string }) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-5">
      <div className="flex items-center gap-3">
        <div className={cn("flex h-10 w-10 items-center justify-center rounded-lg", color)}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-2xl font-bold">{value}</p>
          <p className="text-xs text-[var(--color-muted-foreground)]">{label}</p>
        </div>
      </div>
    </div>
  );
}

const quickActions = [
  { to: "/missions", icon: Plus, label: "New Mission", color: "bg-[var(--color-primary)]/10 text-[var(--color-primary)] border-[var(--color-primary)]/30" },
  { to: "/providers", icon: RefreshCw, label: "Sync Providers", color: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
  { to: "/compliance", icon: FileText, label: "Generate Report", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
  { to: "/admin", icon: ShieldCheck, label: "View Audit Log", color: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
];

export default function Dashboard() {
  const { data: missions } = useQuery({
    queryKey: ["missions"],
    queryFn: () => api.get<{ missions: Mission[] }>("/missions?limit=5"),
  });

  const { data: vulnStats } = useQuery({
    queryKey: ["vuln-stats"],
    queryFn: () => api.get<VulnStats>("/vulnerabilities/stats"),
  });

  const activeMissions = missions?.missions?.filter((m) => !["completed", "cancelled", "failed"].includes(m.status)) ?? [];
  const stats = vulnStats ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">PhantomStrike overview</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard icon={Crosshair} label="Active Missions" value={activeMissions.length} color="bg-[var(--color-primary)]/10 text-[var(--color-primary)]" />
        <StatCard icon={Bug} label="Total Findings" value={stats.total} color="bg-[var(--color-destructive)]/10 text-[var(--color-destructive)]" />
        <StatCard icon={Shield} label="Critical" value={stats.critical} color="bg-[#FF3366]/10 text-[#FF3366]" />
        <StatCard icon={Activity} label="High" value={stats.high} color="bg-orange-500/10 text-orange-500" />
      </div>

      {/* Quick Actions */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-5">
        <h2 className="mb-4 font-semibold">Quick Actions</h2>
        <div className="grid grid-cols-4 gap-3">
          {quickActions.map((action) => (
            <Link
              key={action.to}
              to={action.to}
              className={cn(
                "flex items-center gap-3 rounded-lg border p-4 transition-colors hover:opacity-80",
                action.color
              )}
            >
              <action.icon className="h-5 w-5" />
              <span className="text-sm font-medium">{action.label}</span>
            </Link>
          ))}
        </div>
      </div>

      {/* Recent Missions */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        <div className="border-b border-[var(--color-border)] px-5 py-3">
          <h2 className="font-semibold">Recent Missions</h2>
        </div>
        <div className="divide-y divide-[var(--color-border)]">
          {missions?.missions?.length ? (
            missions.missions.map((m) => (
              <a key={m.id} href={`/missions/${m.id}`} className="flex items-center justify-between px-5 py-3 hover:bg-[var(--color-accent)] transition-colors">
                <div>
                  <p className="font-medium">{m.name}</p>
                  <p className="text-xs text-[var(--color-muted-foreground)]">{m.mode} · {m.depth}</p>
                </div>
                <div className="text-right">
                  <span className={cn("text-sm font-medium capitalize", m.status === "completed" ? "text-emerald-400" : m.status === "failed" ? "text-[var(--color-destructive)]" : "text-[var(--color-primary)]")}>
                    {m.status}
                  </span>
                  <p className="text-xs text-[var(--color-muted-foreground)]">{m.progress}%</p>
                </div>
              </a>
            ))
          ) : (
            <div className="px-5 py-8 text-center text-sm text-[var(--color-muted-foreground)]">
              No missions yet. Create your first mission to get started.
            </div>
          )}
        </div>
      </div>

      {/* Vulnerability Breakdown */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-5">
        <h2 className="mb-4 font-semibold">Vulnerability Breakdown</h2>
        <div className="flex gap-6">
          {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
            <div key={sev} className="text-center">
              <p className={cn("text-2xl font-bold", severityColor(sev))}>{stats[sev]}</p>
              <p className="text-xs capitalize text-[var(--color-muted-foreground)]">{sev}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
