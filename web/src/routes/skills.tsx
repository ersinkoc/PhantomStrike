import { useQuery } from "@tanstack/react-query";
import { Zap, ChevronRight } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useState } from "react";

export default function Skills() {
  const [selected, setSelected] = useState<any>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["skills"],
    queryFn: () => api.get<{ skills: any[] }>("/skills"),
  });

  // Group by category
  const grouped = new Map<string, any[]>();
  data?.skills?.forEach((s: any) => {
    const cat = s.category || "general";
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(s);
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Skills</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">Security testing knowledge modules</p>
      </div>

      <div className="flex gap-6">
        {/* Skill List */}
        <div className="w-80 shrink-0 space-y-4">
          {isLoading ? (
            <div className="text-[var(--color-muted-foreground)]">Loading...</div>
          ) : (
            Array.from(grouped.entries()).map(([category, skills]) => (
              <div key={category}>
                <h3 className="mb-2 text-xs font-semibold uppercase text-[var(--color-muted-foreground)]">{category}</h3>
                <div className="space-y-1">
                  {skills.map((skill: any) => (
                    <button key={skill.name} onClick={() => setSelected(skill)}
                      className={cn("flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm transition-colors",
                        selected?.name === skill.name ? "bg-[var(--color-primary)]/10 text-[var(--color-primary)]" : "hover:bg-[var(--color-accent)]"
                      )}>
                      <div className="flex items-center gap-2">
                        <Zap className="h-3.5 w-3.5" />
                        <span>{skill.name}</span>
                      </div>
                      <ChevronRight className="h-3.5 w-3.5 text-[var(--color-muted-foreground)]" />
                    </button>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Skill Detail */}
        <div className="flex-1 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-6">
          {selected ? (
            <div>
              <h2 className="text-xl font-bold">{selected.name}</h2>
              <span className="mt-1 inline-block rounded bg-[var(--color-muted)] px-2 py-0.5 text-xs">{selected.category}</span>
              <div className="mt-4 whitespace-pre-wrap text-sm text-[var(--color-muted-foreground)] font-mono leading-relaxed">
                {selected.content || "No content available"}
              </div>
            </div>
          ) : (
            <div className="flex h-64 items-center justify-center text-[var(--color-muted-foreground)]">
              Select a skill to view its content
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
