import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface Tool {
  id: string;
  name: string;
  category: string;
  definition: any;
  source: string;
  enabled: boolean;
  install_count: number;
  avg_exec_time?: number;
  success_rate?: number;
  last_used?: string;
  created_at: string;
  updated_at: string;
}

export interface ToolCategory {
  category: string;
  count: number;
}

const TOOLS_KEY = "tools";

export function useTools(category?: string, enabledOnly = true) {
  return useQuery({
    queryKey: [TOOLS_KEY, category, enabledOnly],
    queryFn: async () => {
      const data = await api.get<{ tools: Tool[] }>("/tools");
      return data;
    },
  });
}

export function useTool(name: string) {
  return useQuery({
    queryKey: [TOOLS_KEY, name],
    queryFn: async () => {
      const data = await api.get<Tool>(`/tools/${name}`);
      return data;
    },
    enabled: !!name,
  });
}

export function useToolCategories() {
  return useQuery({
    queryKey: [TOOLS_KEY, "categories"],
    queryFn: async () => {
      const data = await api.get<{ categories: ToolCategory[] }>("/tools/categories");
      return data;
    },
  });
}

export function useToggleTool() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (name: string) => {
      const data = await api.put(`/tools/${name}/toggle`);
      return data;
    },
    onSuccess: (_, name) => {
      queryClient.invalidateQueries({ queryKey: [TOOLS_KEY, name] });
      queryClient.invalidateQueries({ queryKey: [TOOLS_KEY] });
    },
  });
}
