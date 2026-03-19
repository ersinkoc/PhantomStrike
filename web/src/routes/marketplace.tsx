import { useQuery } from "@tanstack/react-query";
import { Store, Wrench, Zap, CheckCircle } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useState } from "react";

type Tab = "tools" | "skills";

interface MarketplaceTool {
  name: string;
  category: string;
  description?: string;
  enabled?: boolean;
}

interface MarketplaceSkill {
  name: string;
  category: string;
  description?: string;
  installed?: boolean;
}

export default function Marketplace() {
  const [activeTab, setActiveTab] = useState<Tab>("tools");

  const { data: toolsData, isLoading: toolsLoading } = useQuery({
    queryKey: ["marketplace-tools"],
    queryFn: () => api.get<{ tools: MarketplaceTool[] }>("/marketplace/tools"),
  });

  const { data: skillsData, isLoading: skillsLoading } = useQuery({
    queryKey: ["marketplace-skills"],
    queryFn: () => api.get<{ skills: MarketplaceSkill[] }>("/marketplace/skills"),
  });

  const tools = toolsData?.tools || [];
  const skills = skillsData?.skills || [];

  const isLoading = activeTab === "tools" ? toolsLoading : skillsLoading;

  // Group tools by category
  const toolsByCategory = new Map<string, MarketplaceTool[]>();
  tools.forEach((t) => {
    const cat = t.category || "other";
    if (!toolsByCategory.has(cat)) toolsByCategory.set(cat, []);
    toolsByCategory.get(cat)!.push(t);
  });

  // Group skills by category
  const skillsByCategory = new Map<string, MarketplaceSkill[]>();
  skills.forEach((s) => {
    const cat = s.category || "general";
    if (!skillsByCategory.has(cat)) skillsByCategory.set(cat, []);
    skillsByCategory.get(cat)!.push(s);
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Marketplace</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">Browse and manage tools and skills</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        <button
          onClick={() => setActiveTab("tools")}
          className={cn(
            "flex items-center gap-1.5 border-b-2 px-4 py-2 text-sm transition-colors",
            activeTab === "tools"
              ? "border-[var(--color-primary)] text-[var(--color-primary)]"
              : "border-transparent text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
          )}
        >
          <Wrench className="h-4 w-4" /> Tools ({tools.length})
        </button>
        <button
          onClick={() => setActiveTab("skills")}
          className={cn(
            "flex items-center gap-1.5 border-b-2 px-4 py-2 text-sm transition-colors",
            activeTab === "skills"
              ? "border-[var(--color-primary)] text-[var(--color-primary)]"
              : "border-transparent text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
          )}
        >
          <Zap className="h-4 w-4" /> Skills ({skills.length})
        </button>
      </div>

      {isLoading ? (
        <div className="p-8 text-center text-[var(--color-muted-foreground)]">Loading...</div>
      ) : activeTab === "tools" ? (
        tools.length === 0 ? (
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-12 text-center text-[var(--color-muted-foreground)]">
            <Store className="mx-auto h-10 w-10 opacity-30" />
            <p className="mt-3">No tools available</p>
          </div>
        ) : (
          <div className="space-y-6">
            {Array.from(toolsByCategory.entries()).map(([category, categoryTools]) => (
              <div key={category}>
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-[var(--color-muted-foreground)]">
                  {category}
                </h3>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {categoryTools.map((tool) => (
                    <div
                      key={tool.name}
                      className="relative rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-4 transition-colors hover:border-[var(--color-primary)]/30"
                    >
                      {tool.enabled && (
                        <span className="absolute right-3 top-3 flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-400">
                          <CheckCircle className="h-3 w-3" /> Installed
                        </span>
                      )}
                      <div className="flex items-start gap-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--color-primary)]/10">
                          <Wrench className="h-4 w-4 text-[var(--color-primary)]" />
                        </div>
                        <div className="min-w-0">
                          <h4 className="font-medium">{tool.name}</h4>
                          <p className="mt-1 text-xs text-[var(--color-muted-foreground)] line-clamp-2">
                            {tool.description || "No description available"}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )
      ) : skills.length === 0 ? (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-12 text-center text-[var(--color-muted-foreground)]">
          <Store className="mx-auto h-10 w-10 opacity-30" />
          <p className="mt-3">No skills available</p>
        </div>
      ) : (
        <div className="space-y-6">
          {Array.from(skillsByCategory.entries()).map(([category, categorySkills]) => (
            <div key={category}>
              <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-[var(--color-muted-foreground)]">
                {category}
              </h3>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {categorySkills.map((skill) => (
                  <div
                    key={skill.name}
                    className="relative rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-4 transition-colors hover:border-[var(--color-primary)]/30"
                  >
                    {skill.installed && (
                      <span className="absolute right-3 top-3 flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-400">
                        <CheckCircle className="h-3 w-3" /> Installed
                      </span>
                    )}
                    <div className="flex items-start gap-3">
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-amber-500/10">
                        <Zap className="h-4 w-4 text-amber-400" />
                      </div>
                      <div className="min-w-0">
                        <h4 className="font-medium">{skill.name}</h4>
                        <p className="mt-1 text-xs text-[var(--color-muted-foreground)] line-clamp-2">
                          {skill.description || "No description available"}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
