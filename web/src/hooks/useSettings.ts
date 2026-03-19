import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface Settings {
  providers: {
    default: string;
    fallback_chain: string[];
    anthropic: { model: string; configured: boolean };
    openai: { model: string; configured: boolean };
    ollama: { model: string; base_url: string };
    groq: { model: string; configured: boolean };
  };
  agent: {
    max_iterations: number;
    max_parallel_tools: number;
    auto_review: boolean;
  };
  mcp: {
    enabled: boolean;
    port: number;
  };
  auth: {
    allow_registration: boolean;
  };
}

const SETTINGS_KEY = "settings";

export function useSettings() {
  return useQuery({
    queryKey: [SETTINGS_KEY],
    queryFn: async () => {
      const data = await api.get<Settings>("/settings");
      return data;
    },
  });
}

export function useUpdateSettings() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (settings: Partial<Settings>) => {
      const data = await api.put("/settings", settings);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [SETTINGS_KEY] });
    },
  });
}
