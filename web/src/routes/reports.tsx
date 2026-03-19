import { useQuery } from "@tanstack/react-query";
import { FileText, Download } from "lucide-react";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function Reports() {
  const { data, isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => api.get<{ reports: any[] }>("/reports"),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">Generated pentest reports</p>
      </div>

      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        {isLoading ? (
          <div className="p-8 text-center text-[var(--color-muted-foreground)]">Loading...</div>
        ) : data?.reports?.length ? (
          <div className="divide-y divide-[var(--color-border)]">
            {data.reports.map((r: any) => (
              <div key={r.id} className="flex items-center justify-between px-5 py-4">
                <div className="flex items-center gap-3">
                  <FileText className="h-5 w-5 text-[var(--color-primary)]" />
                  <div>
                    <p className="font-medium">{r.title}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)]">
                      {r.format.toUpperCase()} · {r.template} · {formatDate(r.created_at)}
                    </p>
                  </div>
                </div>
                <a href={`/api/v1/reports/${r.id}/download`} className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm hover:bg-[var(--color-accent)]">
                  <Download className="h-4 w-4" /> Download
                </a>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center text-[var(--color-muted-foreground)]">
            <FileText className="mx-auto h-10 w-10 opacity-30" />
            <p className="mt-3">No reports generated yet</p>
            <p className="mt-1 text-xs">Reports are generated from mission findings</p>
          </div>
        )}
      </div>
    </div>
  );
}
