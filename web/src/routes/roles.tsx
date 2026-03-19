import { useQuery } from "@tanstack/react-query";
import { UserCog } from "lucide-react";
import { api } from "@/lib/api";

export default function Roles() {
  const { data, isLoading } = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.get<{ roles: any[] }>("/roles"),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Roles</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">Security testing role presets</p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {isLoading ? (
          <div className="col-span-3 text-center text-[var(--color-muted-foreground)]">Loading...</div>
        ) : data?.roles?.length ? (
          data.roles.map((role: any) => (
            <div key={role.name} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-5 hover:border-[var(--color-primary)]/30 transition-colors">
              <div className="flex items-center gap-3">
                <span className="text-2xl">{role.icon || "🎯"}</span>
                <div>
                  <h3 className="font-semibold">{role.name}</h3>
                  <p className="text-xs text-[var(--color-muted-foreground)]">{role.phases?.join(" → ")}</p>
                </div>
              </div>
              <p className="mt-3 text-sm text-[var(--color-muted-foreground)] line-clamp-2">{role.description}</p>
              {role.skills?.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {role.skills.slice(0, 4).map((s: string) => (
                    <span key={s} className="rounded bg-[var(--color-muted)] px-1.5 py-0.5 text-xs">{s}</span>
                  ))}
                  {role.skills.length > 4 && <span className="text-xs text-[var(--color-muted-foreground)]">+{role.skills.length - 4}</span>}
                </div>
              )}
            </div>
          ))
        ) : (
          <div className="col-span-3 p-12 text-center text-[var(--color-muted-foreground)]">
            <UserCog className="mx-auto h-10 w-10 opacity-30" />
            <p className="mt-3">No roles configured</p>
          </div>
        )}
      </div>
    </div>
  );
}
