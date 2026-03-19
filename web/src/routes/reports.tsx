import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, Download, Plus, X, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import type { Mission } from "@/types";

export default function Reports() {
  const queryClient = useQueryClient();
  const [showDialog, setShowDialog] = useState(false);
  const [title, setTitle] = useState("");
  const [missionId, setMissionId] = useState("");
  const [format, setFormat] = useState<"json" | "markdown" | "html">("markdown");

  const { data, isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => api.get<{ reports: any[] }>("/reports"),
  });

  const { data: missionsData } = useQuery({
    queryKey: ["missions"],
    queryFn: () => api.get<{ missions: Mission[] }>("/missions"),
    enabled: showDialog,
  });

  const generateMutation = useMutation({
    mutationFn: (payload: { mission_id: string; format: string; title: string }) =>
      api.post("/reports", payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      toast.success("Report generated");
      setShowDialog(false);
      setTitle("");
      setMissionId("");
      setFormat("markdown");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to generate report");
    },
  });

  const handleGenerate = () => {
    if (!missionId) {
      toast.error("Please select a mission");
      return;
    }
    if (!title.trim()) {
      toast.error("Please enter a title");
      return;
    }
    generateMutation.mutate({ mission_id: missionId, format, title: title.trim() });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Reports</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">Generated pentest reports</p>
        </div>
        <button
          onClick={() => setShowDialog(true)}
          className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90"
        >
          <Plus className="h-4 w-4" /> Generate Report
        </button>
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

      {/* Generate Report Dialog */}
      {showDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
              <h2 className="font-semibold">Generate Report</h2>
              <button
                onClick={() => setShowDialog(false)}
                className="rounded p-1 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="space-y-4 p-5">
              {/* Title */}
              <div>
                <label className="mb-1.5 block text-sm font-medium">Title</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Pentest Report - Q1 2026"
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>

              {/* Mission Selector */}
              <div>
                <label className="mb-1.5 block text-sm font-medium">Mission</label>
                <select
                  value={missionId}
                  onChange={(e) => setMissionId(e.target.value)}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                >
                  <option value="">Select a mission...</option>
                  {missionsData?.missions?.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name} ({m.status})
                    </option>
                  ))}
                </select>
              </div>

              {/* Format Selector */}
              <div>
                <label className="mb-1.5 block text-sm font-medium">Format</label>
                <div className="flex gap-2">
                  {(["json", "markdown", "html"] as const).map((f) => (
                    <button
                      key={f}
                      onClick={() => setFormat(f)}
                      className={`rounded-lg border px-4 py-2 text-sm transition-colors ${
                        format === f
                          ? "border-[var(--color-primary)] bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
                          : "border-[var(--color-border)] text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
                      }`}
                    >
                      {f.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
              <button
                onClick={() => setShowDialog(false)}
                className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={generateMutation.isPending}
                className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
              >
                {generateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
                Generate
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
