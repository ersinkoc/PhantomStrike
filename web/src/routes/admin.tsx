import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, Users, ScrollText, ChevronLeft, ChevronRight } from "lucide-react";
import { api } from "@/lib/api";

interface AdminUser {
  id: string;
  name: string;
  email: string;
  role: string;
  last_login: string;
  created_at: string;
}

interface AuditEntry {
  id: string;
  action: string;
  resource: string;
  user_email: string;
  ip_address: string;
  created_at: string;
}

const roleBadgeColors: Record<string, string> = {
  admin: "bg-red-500/10 text-red-400",
  manager: "bg-orange-500/10 text-orange-400",
  analyst: "bg-blue-500/10 text-blue-400",
  viewer: "bg-zinc-500/10 text-zinc-400",
};

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<"users" | "audit">("users");
  const [auditOffset, setAuditOffset] = useState(0);
  const auditLimit = 20;

  const { data: usersData } = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => api.get<{ users: AdminUser[] }>("/admin/users"),
    enabled: activeTab === "users",
  });

  const { data: auditData, refetch: refetchAudit } = useQuery({
    queryKey: ["admin-audit", auditOffset],
    queryFn: () =>
      api.get<{ entries: AuditEntry[]; total: number }>(
        `/admin/audit?limit=${auditLimit}&offset=${auditOffset}`
      ),
    enabled: activeTab === "audit",
  });

  // Auto-refresh audit log every 30 seconds
  useEffect(() => {
    if (activeTab !== "audit") return;
    const interval = setInterval(() => {
      refetchAudit();
    }, 30000);
    return () => clearInterval(interval);
  }, [activeTab, refetchAudit]);

  const tabs = [
    { id: "users" as const, label: "Users", icon: Users },
    { id: "audit" as const, label: "Audit Log", icon: ScrollText },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Admin</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">
          User management and audit logs
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] p-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? "bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
                : "text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
            }`}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Users Tab */}
      {activeTab === "users" && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[var(--color-muted-foreground)]">
                  <th className="px-5 py-3 font-medium">Name</th>
                  <th className="px-5 py-3 font-medium">Email</th>
                  <th className="px-5 py-3 font-medium">Role</th>
                  <th className="px-5 py-3 font-medium">Last Login</th>
                  <th className="px-5 py-3 font-medium">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {usersData?.users?.map((user) => (
                  <tr key={user.id} className="hover:bg-[var(--color-accent)]/50">
                    <td className="px-5 py-3 font-medium">{user.name}</td>
                    <td className="px-5 py-3 text-[var(--color-muted-foreground)]">
                      {user.email}
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-medium ${
                          roleBadgeColors[user.role] ?? roleBadgeColors.viewer
                        }`}
                      >
                        {user.role}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-[var(--color-muted-foreground)]">
                      {user.last_login
                        ? new Date(user.last_login).toLocaleString()
                        : "Never"}
                    </td>
                    <td className="px-5 py-3 text-[var(--color-muted-foreground)]">
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
                {(!usersData?.users || usersData.users.length === 0) && (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-5 py-8 text-center text-[var(--color-muted-foreground)]"
                    >
                      No users found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Audit Log Tab */}
      {activeTab === "audit" && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[var(--color-muted-foreground)]">
                  <th className="px-5 py-3 font-medium">Action</th>
                  <th className="px-5 py-3 font-medium">Resource</th>
                  <th className="px-5 py-3 font-medium">User</th>
                  <th className="px-5 py-3 font-medium">IP Address</th>
                  <th className="px-5 py-3 font-medium">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {auditData?.entries?.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-[var(--color-accent)]/50"
                  >
                    <td className="px-5 py-3 font-medium">{entry.action}</td>
                    <td className="px-5 py-3 text-[var(--color-muted-foreground)]">
                      {entry.resource}
                    </td>
                    <td className="px-5 py-3 text-[var(--color-muted-foreground)]">
                      {entry.user_email}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-[var(--color-muted-foreground)]">
                      {entry.ip_address}
                    </td>
                    <td className="px-5 py-3 text-[var(--color-muted-foreground)]">
                      {new Date(entry.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
                {(!auditData?.entries || auditData.entries.length === 0) && (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-5 py-8 text-center text-[var(--color-muted-foreground)]"
                    >
                      No audit entries found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between border-t border-[var(--color-border)] px-5 py-3">
            <span className="text-xs text-[var(--color-muted-foreground)]">
              Showing {auditOffset + 1}
              {auditData?.entries
                ? `–${auditOffset + auditData.entries.length}`
                : ""}{" "}
              {auditData?.total != null && `of ${auditData.total}`}
            </span>
            <div className="flex gap-1">
              <button
                onClick={() =>
                  setAuditOffset(Math.max(0, auditOffset - auditLimit))
                }
                disabled={auditOffset === 0}
                className="rounded-lg border border-[var(--color-border)] p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] disabled:opacity-30"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                onClick={() => setAuditOffset(auditOffset + auditLimit)}
                disabled={
                  !auditData?.entries ||
                  auditData.entries.length < auditLimit
                }
                className="rounded-lg border border-[var(--color-border)] p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] disabled:opacity-30"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
