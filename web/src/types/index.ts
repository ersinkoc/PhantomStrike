export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  avatar_url?: string;
}

export interface Mission {
  id: string;
  name: string;
  description?: string;
  status: string;
  mode: string;
  depth: string;
  target: Record<string, unknown>;
  config?: Record<string, unknown>;
  phases?: string[];
  current_phase?: string;
  progress: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  mission_id?: string;
  title: string;
  description?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss_score?: number;
  cvss_vector?: string;
  status: string;
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

export interface Tool {
  name: string;
  category: string;
  enabled: boolean;
  source: string;
  avg_exec_time?: number;
  success_rate?: number;
  last_used?: string;
  definition?: Record<string, unknown>;
}

export interface Conversation {
  id: string;
  title?: string;
  agent_type?: string;
  status?: string;
  created_at: string;
}

export interface Message {
  id: string;
  role: string;
  content?: string;
  tool_calls?: unknown;
  tool_call_id?: string;
  model?: string;
  provider?: string;
  created_at: string;
}

export interface VulnStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface WSEvent {
  type: string;
  data: unknown;
}
