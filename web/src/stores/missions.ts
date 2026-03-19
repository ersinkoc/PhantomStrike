import { create } from "zustand";
import { api } from "@/lib/api";
import type { Mission, Conversation, Message } from "@/types";

interface MissionsState {
  missions: Mission[];
  currentMission: Mission | null;
  conversations: Conversation[];
  messages: Message[];
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchMissions: () => Promise<void>;
  fetchMission: (id: string) => Promise<void>;
  createMission: (data: Partial<Mission>) => Promise<Mission>;
  updateMission: (id: string, data: Partial<Mission>) => Promise<void>;
  deleteMission: (id: string) => Promise<void>;
  startMission: (id: string) => Promise<void>;
  pauseMission: (id: string) => Promise<void>;
  cancelMission: (id: string) => Promise<void>;
  fetchConversations: (missionId: string) => Promise<void>;
  fetchMessages: (conversationId: string) => Promise<void>;
  sendMessage: (conversationId: string, content: string) => Promise<void>;
  setCurrentMission: (mission: Mission | null) => void;
  clearError: () => void;
}

export const useMissionsStore = create<MissionsState>((set, get) => ({
  missions: [],
  currentMission: null,
  conversations: [],
  messages: [],
  isLoading: false,
  error: null,

  fetchMissions: async () => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.get<{ missions: Mission[] }>("/missions");
      set({ missions: res.missions });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch missions" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchMission: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      const mission = await api.get<Mission>(`/missions/${id}`);
      set({ currentMission: mission });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch mission" });
    } finally {
      set({ isLoading: false });
    }
  },

  createMission: async (data: Partial<Mission>) => {
    set({ isLoading: true, error: null });
    try {
      const mission = await api.post<Mission>("/missions", data);
      set((state) => ({ missions: [mission, ...state.missions] }));
      return mission;
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to create mission" });
      throw err;
    } finally {
      set({ isLoading: false });
    }
  },

  updateMission: async (id: string, data: Partial<Mission>) => {
    set({ isLoading: true, error: null });
    try {
      const mission = await api.put<Mission>(`/missions/${id}`, data);
      set((state) => ({
        missions: state.missions.map((m) => (m.id === id ? mission : m)),
        currentMission: state.currentMission?.id === id ? mission : state.currentMission,
      }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to update mission" });
    } finally {
      set({ isLoading: false });
    }
  },

  deleteMission: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.delete(`/missions/${id}`);
      set((state) => ({
        missions: state.missions.filter((m) => m.id !== id),
        currentMission: state.currentMission?.id === id ? null : state.currentMission,
      }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to delete mission" });
    } finally {
      set({ isLoading: false });
    }
  },

  startMission: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.post(`/missions/${id}/start`);
      await get().fetchMission(id);
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to start mission" });
    } finally {
      set({ isLoading: false });
    }
  },

  pauseMission: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.post(`/missions/${id}/pause`);
      await get().fetchMission(id);
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to pause mission" });
    } finally {
      set({ isLoading: false });
    }
  },

  cancelMission: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.post(`/missions/${id}/cancel`);
      await get().fetchMission(id);
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to cancel mission" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchConversations: async (missionId: string) => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.get<{ conversations: Conversation[] }>(`/missions/${missionId}/conversations`);
      set({ conversations: res.conversations });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch conversations" });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchMessages: async (conversationId: string) => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.get<{ messages: Message[] }>(`/conversations/${conversationId}/messages`);
      set({ messages: res.messages });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to fetch messages" });
    } finally {
      set({ isLoading: false });
    }
  },

  sendMessage: async (conversationId: string, content: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.post(`/conversations/${conversationId}/messages`, { content });
      await get().fetchMessages(conversationId);
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to send message" });
    } finally {
      set({ isLoading: false });
    }
  },

  setCurrentMission: (mission: Mission | null) => set({ currentMission: mission }),
  clearError: () => set({ error: null }),
}));
