import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";

import { AppLayout } from "@/components/layout/app-layout";
import { useAuthStore } from "@/stores/auth";

import Dashboard from "@/routes/dashboard";
import HackerDashboard from "@/routes/hacker-dashboard";
import Missions from "@/routes/missions";
import MissionDetail from "@/routes/mission-detail";
import Vulnerabilities from "@/routes/vulnerabilities";
import Tools from "@/routes/tools";
import SettingsPage from "@/routes/settings";
import Login from "@/routes/login";
import Knowledge from "@/routes/knowledge";
import Reports from "@/routes/reports";
import Roles from "@/routes/roles";
import Skills from "@/routes/skills";
import Scheduler from "@/routes/scheduler";
import Marketplace from "@/routes/marketplace";

import "./index.css";

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

function App() {
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
            <Route path="hacker" element={<HackerDashboard />} />
            <Route path="missions" element={<Missions />} />
            <Route path="missions/:id" element={<MissionDetail />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="tools" element={<Tools />} />
            <Route path="knowledge" element={<Knowledge />} />
            <Route path="reports" element={<Reports />} />
            <Route path="roles" element={<Roles />} />
            <Route path="skills" element={<Skills />} />
            <Route path="scheduler" element={<Scheduler />} />
            <Route path="marketplace" element={<Marketplace />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Routes>
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
