import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  avatar_url?: string;
}

export interface AuthResponse {
  token: string;
  refresh_token: string;
  user: User;
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface RegisterInput {
  email: string;
  name: string;
  password: string;
}

export interface UpdateProfileInput {
  name?: string;
  avatar_url?: string;
}

const AUTH_KEY = "auth";

export function useLogin() {
  const queryClient = useQueryClient();
  const { setAuth } = useAuthStore();

  return useMutation({
    mutationFn: async (input: LoginInput) => {
      const data = await api.post<AuthResponse>("/auth/login", input);
      return data;
    },
    onSuccess: (data) => {
      setAuth(data.token, data.user);
      queryClient.setQueryData([AUTH_KEY, "me"], data.user);
    },
  });
}

export function useRegister() {
  const queryClient = useQueryClient();
  const { setAuth } = useAuthStore();

  return useMutation({
    mutationFn: async (input: RegisterInput) => {
      const data = await api.post<AuthResponse>("/auth/register", input);
      return data;
    },
    onSuccess: (data) => {
      setAuth(data.token, data.user);
      queryClient.setQueryData([AUTH_KEY, "me"], data.user);
    },
  });
}

export function useMe() {
  return useQuery({
    queryKey: [AUTH_KEY, "me"],
    queryFn: async () => {
      const data = await api.get<User>("/auth/me");
      return data;
    },
    retry: false,
  });
}

export function useUpdateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: UpdateProfileInput) => {
      const data = await api.put<User>("/auth/me", input);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [AUTH_KEY, "me"] });
    },
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  const { clearAuth } = useAuthStore();

  return useMutation({
    mutationFn: async () => {
      const data = await api.post<{ status: string }>("/auth/logout");
      return data;
    },
    onSuccess: () => {
      clearAuth();
      queryClient.clear();
    },
  });
}

export function useRefreshToken() {
  const queryClient = useQueryClient();
  const { setToken } = useAuthStore();

  return useMutation({
    mutationFn: async (refreshToken: string) => {
      const data = await api.post<{ token: string; refresh_token: string }>("/auth/refresh", { refresh_token: refreshToken });
      return data;
    },
    onSuccess: (data) => {
      setToken(data.token);
      queryClient.invalidateQueries({ queryKey: [AUTH_KEY, "me"] });
    },
  });
}
