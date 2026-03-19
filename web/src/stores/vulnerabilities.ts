import { create } from "zustand";
import { api } from "@/lib/api";
import type { Vulnerability, VulnStats } from "@/types";

interface VulnerabilitiesState {
  vulnerabilities: Vulnerability[];
  currentVulnerability: Vulnerability | null;
  stats: VulnStats | null;
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchVulnerabilities: () => Promise<void>;
  fetchVulnerability: (id: string) => Promise<void>;
  createVulnerability: (data: Partial<Vulnerability>) => Promise<Vulnerability>;
  updateVulnerability: (id: string, data: Partial<Vulnerability>) => Promise<void>;
  deleteVulnerability: (id: string) => Promise<void>;
  fetchStats: () => Promise<void>;
  fetchMissionVulns: (missionId: string) => Promise<void>;
  setCurrentVulnerability: (vuln: Vulnerability | null) => void;
  clearError: () => void;
}

export const useVulnerabilitiesStore = create<VulnerabilitiesState>((set, get) => ({
  vulnerabilities: [],
  currentVulnerability: null,
  stats: null,
  isLoading: false,
  error: null,

  fetchVulnerabilities: async () => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.get<{ vulnerabilities: Vulnerability[] }>("/vulnerabilities");
      set({ vulnerabilities: res.vulnerabilities });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch vulnerabilities" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchVulnerability: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      const vuln = await api.get<Vulnerability>(`/vulnerabilities/${id}`);
      set({ currentVulnerability: vuln });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch vulnerability" });
    } finally {
      set({ isLoading: false });
    }
  },

  createVulnerability: async (data: Partial<Vulnerability>) => {
    set({ isLoading: true, error: null });
    try {
      const vuln = await api.post<Vulnerability>("/vulnerabilities", data);
      set((state) => ({
        vulnerabilities: [vuln, ...state.vulnerabilities],
      }));
      return vuln;
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to create vulnerability" });
      throw err;
    } finally {
      set({ isLoading: false });
    }
  },

  updateVulnerability: async (id: string, data: Partial<Vulnerability>) => {
    set({ isLoading: true, error: null });
    try {
      const vuln = await api.put<Vulnerability>(`/vulnerabilities/${id}`, data);
      set((state) => ({
        vulnerabilities: state.vulnerabilities.map((v) => (v.id === id ? vuln : v)),
        currentVulnerability: state.currentVulnerability?.id === id ? vuln : state.currentVulnerability,
      }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to update vulnerability" });
    } finally {
      set({ isLoading: false });
    }
  },

  deleteVulnerability: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.delete(`/vulnerabilities/${id}`);
      set((state) => ({
        vulnerabilities: state.vulnerabilities.filter((v) => v.id !== id),
        currentVulnerability: state.currentVulnerability?.id === id ? null : state.currentVulnerability,
      }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to delete vulnerability" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchStats: async () => {
    set({ isLoading: true, error: null });
    try {
      const stats = await api.get<VulnStats>("/vulnerabilities/stats");
      set({ stats });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch stats" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchMissionVulns: async (missionId: string) => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.get<{ vulnerabilities: Vulnerability[] }>(`/missions/${missionId}/vulns`);
      set({ vulnerabilities: res.vulnerabilities });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch mission vulnerabilities" });
    } finally {
      set({ isLoading: false });
    }
  },

  setCurrentVulnerability: (vuln: Vulnerability | null) => set({ currentVulnerability: vuln }),
  clearError: () => set({ error: null }),
}));
