import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Clock, Play, Trash2, ToggleLeft, ToggleRight } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function Scheduler() {
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["scheduler"],
    queryFn: () => api.get<{ jobs: any[] }>("/scheduler"),
  });

  const triggerMutation = useMutation({
    mutationFn: (id: string) => api.post(`/scheduler/${id}/trigger`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["scheduler"] }); toast.success("Job triggered"); },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/scheduler/${id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["scheduler"] }); toast.success("Job deleted"); },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Scheduler</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">Recurring scan schedules</p>
      </div>

      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        {isLoading ? (
          <div className="p-8 text-center text-[var(--color-muted-foreground)]">Loading...</div>
        ) : data?.jobs?.length ? (
          <div className="divide-y divide-[var(--color-border)]">
            {data.jobs.map((job: any) => (
              <div key={job.id} className="flex items-center justify-between px-5 py-4">
                <div className="flex items-center gap-3">
                  <Clock className="h-5 w-5 text-[var(--color-primary)]" />
                  <div>
                    <p className="font-medium">{job.name}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)]">
                      <span className="font-mono">{job.cron_expr}</span>
                      {job.last_run && <> · Last: {formatDate(job.last_run)}</>}
                      {job.next_run && <> · Next: {formatDate(job.next_run)}</>}
                      <> · Runs: {job.run_count}</>
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => triggerMutation.mutate(job.id)} className="rounded p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-primary)]" title="Trigger now">
                    <Play className="h-4 w-4" />
                  </button>
                  <button onClick={() => deleteMutation.mutate(job.id)} className="rounded p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-destructive)]" title="Delete">
                    <Trash2 className="h-4 w-4" />
                  </button>
                  {job.enabled ? <ToggleRight className="h-5 w-5 text-[var(--color-primary)]" /> : <ToggleLeft className="h-5 w-5 text-[var(--color-muted-foreground)]" />}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center text-[var(--color-muted-foreground)]">
            <Clock className="mx-auto h-10 w-10 opacity-30" />
            <p className="mt-3">No scheduled jobs</p>
          </div>
        )}
      </div>
    </div>
  );
}
