import { create } from "zustand";
import { api } from "@/lib/api";
import type { User } from "@/types";

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, name: string, password: string) => Promise<void>;
  logout: () => void;
  loadUser: () => Promise<void>;
  setAuth: (token: string, user: User) => void;
  clearAuth: () => void;
  setToken: (token: string) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: localStorage.getItem("token"),
  isAuthenticated: !!localStorage.getItem("token"),
  isLoading: false,

  login: async (email, password) => {
    set({ isLoading: true });
    try {
      const res = await api.post<{ token: string; refresh_token: string; user: User }>(
        "/auth/login",
        { email, password }
      );
      localStorage.setItem("token", res.token);
      localStorage.setItem("refresh_token", res.refresh_token);
      api.setToken(res.token);
      set({ user: res.user, token: res.token, isAuthenticated: true });
    } finally {
      set({ isLoading: false });
    }
  },

  register: async (email, name, password) => {
    set({ isLoading: true });
    try {
      const res = await api.post<{ token: string; refresh_token: string; user: User }>(
        "/auth/register",
        { email, name, password }
      );
      localStorage.setItem("token", res.token);
      localStorage.setItem("refresh_token", res.refresh_token);
      api.setToken(res.token);
      set({ user: res.user, token: res.token, isAuthenticated: true });
    } finally {
      set({ isLoading: false });
    }
  },

  logout: () => {
    localStorage.removeItem("token");
    localStorage.removeItem("refresh_token");
    api.setToken(null);
    set({ user: null, token: null, isAuthenticated: false });
  },

  loadUser: async () => {
    try {
      const user = await api.get<User>("/auth/me");
      set({ user, isAuthenticated: true });
    } catch {
      set({ user: null, isAuthenticated: false });
      localStorage.removeItem("token");
    }
  },

  setAuth: (token: string, user: User) => {
    localStorage.setItem("token", token);
    api.setToken(token);
    set({ token, user, isAuthenticated: true });
  },

  clearAuth: () => {
    localStorage.removeItem("token");
    localStorage.removeItem("refresh_token");
    api.setToken(null);
    set({ token: null, user: null, isAuthenticated: false });
  },

  setToken: (token: string) => {
    localStorage.setItem("token", token);
    api.setToken(token);
    set({ token });
  },
}));
