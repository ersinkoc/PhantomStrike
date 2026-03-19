import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, Crosshair, Shield, Wrench,
  FileText, Settings, LogOut, Bug, Cpu, Sun, Moon,
  BookOpen, ClipboardCheck, Clock, Store, UserCog, Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth";
import { useTheme } from "@/hooks/useTheme";

const mainNav = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/missions", icon: Crosshair, label: "Missions" },
  { to: "/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
  { to: "/tools", icon: Wrench, label: "Tools" },
  { to: "/reports", icon: FileText, label: "Reports" },
];

const configNav = [
  { to: "/providers", icon: Cpu, label: "AI Providers" },
  { to: "/roles", icon: UserCog, label: "Roles" },
  { to: "/skills", icon: Zap, label: "Skills" },
  { to: "/knowledge", icon: BookOpen, label: "Knowledge" },
  { to: "/compliance", icon: ClipboardCheck, label: "Compliance" },
  { to: "/scheduler", icon: Clock, label: "Scheduler" },
  { to: "/marketplace", icon: Store, label: "Marketplace" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

function NavItem({ to, icon: Icon, label }: { to: string; icon: React.ComponentType<{ className?: string }>; label: string }) {
  return (
    <li>
      <NavLink
        to={to}
        end={to === "/"}
        className={({ isActive }) =>
          cn(
            "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
            isActive
              ? "bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
              : "text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-foreground)]"
          )
        }
      >
        <Icon className="h-4 w-4" />
        {label}
      </NavLink>
    </li>
  );
}

export function Sidebar() {
  const { logout } = useAuthStore();
  const { theme, toggle: toggleTheme } = useTheme();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-56 flex-col border-r border-[var(--color-border)] bg-[var(--color-card)]">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 border-b border-[var(--color-border)] px-4">
        <Shield className="h-6 w-6 text-[var(--color-primary)]" />
        <span className="text-lg font-bold tracking-tight">
          Phantom<span className="text-[var(--color-primary)]">Strike</span>
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-3">
        <ul className="space-y-0.5">
          {mainNav.map((item) => (
            <NavItem key={item.to} {...item} />
          ))}
        </ul>

        <div className="my-3 border-t border-[var(--color-border)]" />

        <p className="mb-1 px-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--color-muted-foreground)]">
          Configuration
        </p>
        <ul className="space-y-0.5">
          {configNav.map((item) => (
            <NavItem key={item.to} {...item} />
          ))}
        </ul>
      </nav>

      {/* Bottom */}
      <div className="border-t border-[var(--color-border)] p-2 space-y-0.5">
        <button
          onClick={toggleTheme}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-[var(--color-muted-foreground)] transition-colors hover:bg-[var(--color-accent)]"
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          {theme === "dark" ? "Light" : "Dark"}
        </button>
        <button
          onClick={logout}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-[var(--color-muted-foreground)] transition-colors hover:bg-[var(--color-accent)] hover:text-[var(--color-destructive)]"
        >
          <LogOut className="h-4 w-4" />
          Logout
        </button>
      </div>
    </aside>
  );
}
