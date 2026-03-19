import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface Vulnerability {
  id: string;
  mission_id?: string;
  title: string;
  description?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss_score?: number;
  cvss_vector?: string;
  status: "open" | "confirmed" | "exploited" | "fixed" | "false_positive" | "accepted";
  target?: string;
  affected_component?: string;
  evidence?: string;
  remediation?: string;
  cve_ids?: string[];
  cwe_id?: string;
  tags?: string[];
  found_by?: string;
  verified_by?: string;
  created_at: string;
  updated_at: string;
}

export interface VulnInput {
  mission_id?: string;
  title: string;
  description?: string;
  severity: string;
  cvss_score?: number;
  cvss_vector?: string;
  status?: string;
  target?: string;
  affected_component?: string;
  evidence?: string;
  remediation?: string;
  cve_ids?: string[];
  cwe_id?: string;
  tags?: string[];
  found_by?: string;
}

export interface VulnStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

const VULNS_KEY = "vulnerabilities";

export function useVulnerabilities(
  limit = 50,
  offset = 0,
  severity?: string,
  status?: string
) {
  return useQuery({
    queryKey: [VULNS_KEY, limit, offset, severity, status],
    queryFn: async () => {
      const params = new URLSearchParams();
      params.append("limit", limit.toString());
      params.append("offset", offset.toString());
      if (severity) params.append("severity", severity);
      if (status) params.append("status", status);

      const data = await api.get<{ vulnerabilities: Vulnerability[] }>(`/vulnerabilities?${params.toString()}`);
      return data;
    },
  });
}

export function useVulnerability(id: string) {
  return useQuery({
    queryKey: [VULNS_KEY, id],
    queryFn: async () => {
      const data = await api.get<Vulnerability>(`/vulnerabilities/${id}`);
      return data;
    },
    enabled: !!id,
  });
}

export function useCreateVulnerability() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: VulnInput) => {
      const data = await api.post("/vulnerabilities", input);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [VULNS_KEY] });
    },
  });
}

export function useUpdateVulnerability(id: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: Partial<VulnInput>) => {
      const data = await api.put(`/vulnerabilities/${id}`, input);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [VULNS_KEY, id] });
      queryClient.invalidateQueries({ queryKey: [VULNS_KEY] });
    },
  });
}

export function useDeleteVulnerability() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const data = await api.delete(`/vulnerabilities/${id}`);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [VULNS_KEY] });
    },
  });
}

export function useVulnStats() {
  return useQuery({
    queryKey: [VULNS_KEY, "stats"],
    queryFn: async () => {
      const data = await api.get<VulnStats>("/vulnerabilities/stats");
      return data;
    },
  });
}
