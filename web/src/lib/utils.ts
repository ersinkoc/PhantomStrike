import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date): string {
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "text-[#FF3366]";
    case "high": return "text-orange-500";
    case "medium": return "text-amber-500";
    case "low": return "text-blue-500";
    case "info": return "text-zinc-400";
    default: return "text-zinc-400";
  }
}

export function severityBg(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "bg-[#FF3366]/10 border-[#FF3366]/30";
    case "high": return "bg-orange-500/10 border-orange-500/30";
    case "medium": return "bg-amber-500/10 border-amber-500/30";
    case "low": return "bg-blue-500/10 border-blue-500/30";
    case "info": return "bg-zinc-500/10 border-zinc-500/30";
    default: return "bg-zinc-500/10 border-zinc-500/30";
  }
}

export function statusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "completed": return "text-emerald-400";
    case "running": case "scanning": case "exploitation": return "text-[#00FFD1]";
    case "failed": return "text-[#FF3366]";
    case "paused": return "text-amber-400";
    case "created": return "text-zinc-400";
    default: return "text-zinc-400";
  }
}
