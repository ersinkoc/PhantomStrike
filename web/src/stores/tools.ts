import { create } from "zustand";
import { api } from "@/lib/api";
import type { Tool } from "@/types";

interface ToolsState {
  tools: Tool[];
  categories: string[];
  currentTool: Tool | null;
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchTools: () => Promise<void>;
  fetchTool: (name: string) => Promise<void>;
  fetchCategories: () => Promise<void>;
  toggleTool: (name: string) => Promise<void>;
  setCurrentTool: (tool: Tool | null) => void;
  clearError: () => void;
}

export const useToolsStore = create<ToolsState>((set, get) => ({
  tools: [],
  categories: [],
  currentTool: null,
  isLoading: false,
  error: null,

  fetchTools: async () => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.get<{ tools: Tool[] }>("/tools");
      set({ tools: res.tools });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch tools" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchTool: async (name: string) => {
    set({ isLoading: true, error: null });
    try {
      const tool = await api.get<Tool>(`/tools/${name}`);
      set({ currentTool: tool });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch tool" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchCategories: async () => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.get<{ categories: string[] }>("/tools/categories");
      set({ categories: res.categories });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch categories" });
    } finally {
      set({ isLoading: false });
    }
  },

  toggleTool: async (name: string) => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.put<{ enabled: boolean }>(`/tools/${name}/toggle`, {});
      set((state) => ({
        tools: state.tools.map((t) =>
          t.name === name ? { ...t, enabled: res.enabled } : t
        ),
        currentTool:
          state.currentTool?.name === name
            ? { ...state.currentTool, enabled: res.enabled }
            : state.currentTool,
      }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to toggle tool" });
    } finally {
      set({ isLoading: false });
    }
  },

  setCurrentTool: (tool: Tool | null) => set({ currentTool: tool }),
  clearError: () => set({ error: null }),
}));
