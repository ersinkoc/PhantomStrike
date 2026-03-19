import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, Crosshair, Shield, ShieldCheck, Wrench,
  BookOpen, FileText, Settings, LogOut, Bug,
  Terminal, UserCog, Zap, Clock, Store, Sun, Moon, Cpu, ClipboardCheck
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth";
import { useTheme } from "@/hooks/useTheme";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/hacker", icon: Terminal, label: "Hacker Mode" },
  { to: "/missions", icon: Crosshair, label: "Missions" },
  { to: "/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
  { to: "/tools", icon: Wrench, label: "Tools" },
  { to: "/roles", icon: UserCog, label: "Roles" },
  { to: "/skills", icon: Zap, label: "Skills" },
  { to: "/knowledge", icon: BookOpen, label: "Knowledge" },
  { to: "/reports", icon: FileText, label: "Reports" },
  { to: "/compliance", icon: ClipboardCheck, label: "Compliance" },
  { to: "/scheduler", icon: Clock, label: "Scheduler" },
  { to: "/marketplace", icon: Store, label: "Marketplace" },
  { to: "/providers", icon: Cpu, label: "AI Providers" },
  { to: "/settings", icon: Settings, label: "Settings" },
  { to: "/admin", icon: ShieldCheck, label: "Admin" },
];

export function Sidebar() {
  const { user, logout } = useAuthStore();
  const { theme, toggle: toggleTheme } = useTheme();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-60 flex-col border-r border-[var(--color-border)] bg-[var(--color-card)]">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 border-b border-[var(--color-border)] px-4">
        <Shield className="h-6 w-6 text-[var(--color-primary)]" />
        <span className="text-lg font-bold tracking-tight">
          Phantom<span className="text-[var(--color-primary)]">Strike</span>
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <ul className="space-y-1">
          {navItems.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                    isActive
                      ? "bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
                      : "text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-foreground)]"
                  )
                }
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* Theme Toggle */}
      <div className="border-t border-[var(--color-border)] px-3 py-2">
        <button
          onClick={toggleTheme}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-[var(--color-muted-foreground)] transition-colors hover:bg-[var(--color-accent)] hover:text-[var(--color-foreground)]"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
        </button>
      </div>

      {/* User */}
      <div className="border-t border-[var(--color-border)] p-3">
        <div className="flex items-center justify-between">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium">{user?.name ?? "User"}</p>
            <p className="truncate text-xs text-[var(--color-muted-foreground)]">{user?.email}</p>
          </div>
          <button onClick={logout} className="rounded p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-destructive)]" title="Logout">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
