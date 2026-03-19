import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Wrench, ToggleLeft, ToggleRight } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { formatDuration } from "@/lib/utils";
import type { Tool } from "@/types";

export default function Tools() {
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["tools"],
    queryFn: () => api.get<{ tools: Tool[] }>("/tools"),
  });

  const toggleMutation = useMutation({
    mutationFn: (name: string) => api.put(`/tools/${name}/toggle`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tools"] });
      toast.success("Tool toggled");
    },
  });

  // Group by category
  const grouped = new Map<string, Tool[]>();
  data?.tools?.forEach((t) => {
    const cat = t.category.split("/")[0];
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(t);
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Tools</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">{data?.tools?.length ?? 0} security tools available</p>
      </div>

      {isLoading ? (
        <div className="text-[var(--color-muted-foreground)]">Loading...</div>
      ) : (
        Array.from(grouped.entries()).map(([category, tools]) => (
          <div key={category} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
            <div className="border-b border-[var(--color-border)] px-5 py-3">
              <h2 className="font-semibold capitalize">{category}</h2>
            </div>
            <div className="divide-y divide-[var(--color-border)]">
              {tools.map((tool) => (
                <div key={tool.name} className="flex items-center justify-between px-5 py-3">
                  <div className="flex items-center gap-3">
                    <Wrench className="h-4 w-4 text-[var(--color-muted-foreground)]" />
                    <div>
                      <p className="font-medium font-mono text-sm">{tool.name}</p>
                      <p className="text-xs text-[var(--color-muted-foreground)]">
                        {tool.category}
                        {tool.avg_exec_time != null && ` · avg ${formatDuration(tool.avg_exec_time)}`}
                        {tool.success_rate != null && ` · ${tool.success_rate}% success`}
                      </p>
                    </div>
                  </div>
                  <button onClick={() => toggleMutation.mutate(tool.name)} className="text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]">
                    {tool.enabled ? <ToggleRight className="h-6 w-6 text-[var(--color-primary)]" /> : <ToggleLeft className="h-6 w-6" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
