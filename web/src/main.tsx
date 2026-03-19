import React, { Suspense, StrictMode, useState, useEffect, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";

import { AppLayout } from "@/components/layout/app-layout";
import { useAuthStore } from "@/stores/auth";
import { CommandPalette } from "@/components/common/command-palette";

import Login from "@/routes/login";
import Dashboard from "@/routes/dashboard";

import "./index.css";

// Lazy-loaded route components for code splitting
const HackerDashboard = React.lazy(() => import("@/routes/hacker-dashboard"));
const Missions = React.lazy(() => import("@/routes/missions"));
const MissionDetail = React.lazy(() => import("@/routes/mission-detail"));
const Vulnerabilities = React.lazy(() => import("@/routes/vulnerabilities"));
const Tools = React.lazy(() => import("@/routes/tools"));
const Knowledge = React.lazy(() => import("@/routes/knowledge"));
const Reports = React.lazy(() => import("@/routes/reports"));
const Roles = React.lazy(() => import("@/routes/roles"));
const Skills = React.lazy(() => import("@/routes/skills"));
const Scheduler = React.lazy(() => import("@/routes/scheduler"));
const Marketplace = React.lazy(() => import("@/routes/marketplace"));
const SettingsPage = React.lazy(() => import("@/routes/settings"));
const AdminPage = React.lazy(() => import("@/routes/admin"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function LazyFallback() {
  return (
    <div className="flex items-center justify-center h-full w-full min-h-[200px]">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white" />
    </div>
  );
}

function App() {
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      setCommandPaletteOpen((prev) => !prev);
    }
  }, []);

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="hacker" element={<Suspense fallback={<LazyFallback />}><HackerDashboard /></Suspense>} />
            <Route path="missions" element={<Suspense fallback={<LazyFallback />}><Missions /></Suspense>} />
            <Route path="missions/:id" element={<Suspense fallback={<LazyFallback />}><MissionDetail /></Suspense>} />
            <Route path="vulnerabilities" element={<Suspense fallback={<LazyFallback />}><Vulnerabilities /></Suspense>} />
            <Route path="tools" element={<Suspense fallback={<LazyFallback />}><Tools /></Suspense>} />
            <Route path="knowledge" element={<Suspense fallback={<LazyFallback />}><Knowledge /></Suspense>} />
            <Route path="reports" element={<Suspense fallback={<LazyFallback />}><Reports /></Suspense>} />
            <Route path="roles" element={<Suspense fallback={<LazyFallback />}><Roles /></Suspense>} />
            <Route path="skills" element={<Suspense fallback={<LazyFallback />}><Skills /></Suspense>} />
            <Route path="scheduler" element={<Suspense fallback={<LazyFallback />}><Scheduler /></Suspense>} />
            <Route path="marketplace" element={<Suspense fallback={<LazyFallback />}><Marketplace /></Suspense>} />
            <Route path="settings" element={<Suspense fallback={<LazyFallback />}><SettingsPage /></Suspense>} />
            <Route path="admin" element={<Suspense fallback={<LazyFallback />}><AdminPage /></Suspense>} />
          </Route>
        </Routes>
        <CommandPalette open={commandPaletteOpen} onClose={() => setCommandPaletteOpen(false)} />
      </BrowserRouter>
      <Toaster theme="dark" position="bottom-right" richColors />
    </QueryClientProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
