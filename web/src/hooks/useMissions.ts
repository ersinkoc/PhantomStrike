import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface Mission {
  id: string;
  name: string;
  description?: string;
  status: string;
  mode: string;
  depth: string;
  target: any;
  config?: any;
  phases?: string[];
  current_phase?: string;
  progress: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface MissionInput {
  name: string;
  description?: string;
  mode?: string;
  depth?: string;
  target: any;
  config?: any;
  phases?: string[];
}

const MISSIONS_KEY = "missions";

export function useMissions(limit = 20, offset = 0) {
  return useQuery({
    queryKey: [MISSIONS_KEY, limit, offset],
    queryFn: async () => {
      const data = await api.get<{ missions: Mission[]; total: number }>(`/missions?limit=${limit}&offset=${offset}`);
      return data;
    },
  });
}

export function useMission(id: string) {
  return useQuery({
    queryKey: [MISSIONS_KEY, id],
    queryFn: async () => {
      const data = await api.get<Mission>(`/missions/${id}`);
      return data;
    },
    enabled: !!id,
  });
}

export function useCreateMission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: MissionInput) => {
      const data = await api.post<{ id: string; status: string }>("/missions", input);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [MISSIONS_KEY] });
    },
  });
}

export function useUpdateMission(id: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: Partial<MissionInput>) => {
      const data = await api.put<{ status: string }>(`/missions/${id}`, input);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [MISSIONS_KEY, id] });
      queryClient.invalidateQueries({ queryKey: [MISSIONS_KEY] });
    },
  });
}

export function useDeleteMission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const data = await api.delete<{ status: string }>(`/missions/${id}`);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [MISSIONS_KEY] });
    },
  });
}

export function useStartMission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const data = await api.post<{ status: string }>(`/missions/${id}/start`);
      return data;
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: [MISSIONS_KEY, id] });
    },
  });
}

export function usePauseMission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const data = await api.post<{ status: string }>(`/missions/${id}/pause`);
      return data;
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: [MISSIONS_KEY, id] });
    },
  });
}

export function useCancelMission() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const data = await api.post<{ status: string }>(`/missions/${id}/cancel`);
      return data;
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: [MISSIONS_KEY, id] });
    },
  });
}

export function useMissionVulns(id: string) {
  return useQuery({
    queryKey: [MISSIONS_KEY, id, "vulns"],
    queryFn: async () => {
      const data = await api.get<{ vulnerabilities: any[] }>(`/missions/${id}/vulns`);
      return data;
    },
    enabled: !!id,
  });
}

export function useMissionChain(id: string) {
  return useQuery({
    queryKey: [MISSIONS_KEY, id, "chain"],
    queryFn: async () => {
      const data = await api.get<{ nodes: any[]; edges: any[] }>(`/missions/${id}/chain`);
      return data;
    },
    enabled: !!id,
  });
}
