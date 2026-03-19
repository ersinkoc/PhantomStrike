import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  Crosshair,
  Wrench,
  Bug,
  BookOpen,
  FileText,
  Settings,
  ShieldCheck,
  Search,
  type LucideIcon,
} from "lucide-react";

interface Action {
  id: string;
  label: string;
  path: string;
  icon: LucideIcon;
  keywords: string[];
}

const actions: Action[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    path: "/",
    icon: LayoutDashboard,
    keywords: ["home", "overview", "dashboard"],
  },
  {
    id: "missions",
    label: "Missions",
    path: "/missions",
    icon: Crosshair,
    keywords: ["missions", "scans", "tasks"],
  },
  {
    id: "tools",
    label: "Tools",
    path: "/tools",
    icon: Wrench,
    keywords: ["tools", "scanners", "utilities"],
  },
  {
    id: "vulnerabilities",
    label: "Vulnerabilities",
    path: "/vulnerabilities",
    icon: Bug,
    keywords: ["vulnerabilities", "vulns", "findings", "bugs"],
  },
  {
    id: "knowledge",
    label: "Knowledge",
    path: "/knowledge",
    icon: BookOpen,
    keywords: ["knowledge", "docs", "documentation", "wiki"],
  },
  {
    id: "reports",
    label: "Reports",
    path: "/reports",
    icon: FileText,
    keywords: ["reports", "export", "pdf"],
  },
  {
    id: "settings",
    label: "Settings",
    path: "/settings",
    icon: Settings,
    keywords: ["settings", "preferences", "config"],
  },
  {
    id: "admin",
    label: "Admin",
    path: "/admin",
    icon: ShieldCheck,
    keywords: ["admin", "administration", "users", "management"],
  },
];

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const filtered = actions.filter((action) => {
    if (!query) return true;
    const q = query.toLowerCase();
    return (
      action.label.toLowerCase().includes(q) ||
      action.keywords.some((kw) => kw.includes(q))
    );
  });

  const handleSelect = useCallback(
    (action: Action) => {
      navigate(action.path);
      onClose();
    },
    [navigate, onClose]
  );

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIndex(0);
      // Small delay to ensure the modal is rendered before focusing
      requestAnimationFrame(() => {
        inputRef.current?.focus();
      });
    }
  }, [open]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setSelectedIndex((i) => (i + 1) % Math.max(filtered.length, 1));
          break;
        case "ArrowUp":
          e.preventDefault();
          setSelectedIndex(
            (i) => (i - 1 + filtered.length) % Math.max(filtered.length, 1)
          );
          break;
        case "Enter":
          e.preventDefault();
          if (filtered[selectedIndex]) {
            handleSelect(filtered[selectedIndex]);
          }
          break;
        case "Escape":
          e.preventDefault();
          onClose();
          break;
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, filtered, selectedIndex, handleSelect, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-lg rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] shadow-2xl">
        {/* Search input */}
        <div className="flex items-center gap-3 border-b border-[var(--color-border)] px-4 py-3">
          <Search className="h-5 w-5 text-[var(--color-muted-foreground)]" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search actions..."
            className="flex-1 bg-transparent text-sm text-[var(--color-foreground)] placeholder-[var(--color-muted-foreground)] outline-none"
          />
          <kbd className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-xs text-[var(--color-muted-foreground)]">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-72 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="px-3 py-6 text-center text-sm text-[var(--color-muted-foreground)]">
              No results found.
            </div>
          ) : (
            filtered.map((action, index) => (
              <button
                key={action.id}
                onClick={() => handleSelect(action)}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${
                  index === selectedIndex
                    ? "bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
                    : "text-[var(--color-foreground)] hover:bg-[var(--color-accent)]"
                }`}
              >
                <action.icon className="h-4 w-4" />
                <span>{action.label}</span>
                {index === selectedIndex && (
                  <span className="ml-auto text-xs text-[var(--color-muted-foreground)]">
                    Enter
                  </span>
                )}
              </button>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-4 border-t border-[var(--color-border)] px-4 py-2 text-xs text-[var(--color-muted-foreground)]">
          <span className="flex items-center gap-1">
            <kbd className="rounded border border-[var(--color-border)] px-1 py-0.5">
              ↑↓
            </kbd>
            Navigate
          </span>
          <span className="flex items-center gap-1">
            <kbd className="rounded border border-[var(--color-border)] px-1 py-0.5">
              ↵
            </kbd>
            Open
          </span>
          <span className="flex items-center gap-1">
            <kbd className="rounded border border-[var(--color-border)] px-1 py-0.5">
              esc
            </kbd>
            Close
          </span>
        </div>
      </div>
    </div>
  );
}
