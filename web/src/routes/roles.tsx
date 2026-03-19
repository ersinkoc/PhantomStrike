import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { UserCog, Plus, Trash2, Pencil, X, Loader2, Save } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";

interface RoleForm {
  name: string;
  description: string;
  icon: string;
  system_prompt: string;
}

const emptyForm: RoleForm = { name: "", description: "", icon: "", system_prompt: "" };

export default function Roles() {
  const queryClient = useQueryClient();
  const [showDialog, setShowDialog] = useState(false);
  const [editingRole, setEditingRole] = useState<string | null>(null);
  const [form, setForm] = useState<RoleForm>(emptyForm);

  const { data, isLoading } = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.get<{ roles: any[] }>("/roles"),
  });

  const createMutation = useMutation({
    mutationFn: (payload: RoleForm) => api.post("/roles", payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["roles"] });
      toast.success("Role created");
      closeDialog();
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to create role");
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ name, payload }: { name: string; payload: RoleForm }) =>
      api.put(`/roles/${name}`, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["roles"] });
      toast.success("Role updated");
      closeDialog();
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to update role");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (name: string) => api.delete(`/roles/${name}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["roles"] });
      toast.success("Role deleted");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to delete role");
    },
  });

  const closeDialog = () => {
    setShowDialog(false);
    setEditingRole(null);
    setForm(emptyForm);
  };

  const openCreate = () => {
    setForm(emptyForm);
    setEditingRole(null);
    setShowDialog(true);
  };

  const openEdit = (role: any) => {
    setForm({
      name: role.name || "",
      description: role.description || "",
      icon: role.icon || "",
      system_prompt: role.system_prompt || "",
    });
    setEditingRole(role.name);
    setShowDialog(true);
  };

  const handleSubmit = () => {
    if (!form.name.trim()) {
      toast.error("Name is required");
      return;
    }
    if (editingRole) {
      updateMutation.mutate({ name: editingRole, payload: form });
    } else {
      createMutation.mutate(form);
    }
  };

  const isPending = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Roles</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">Security testing role presets</p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90"
        >
          <Plus className="h-4 w-4" /> Create Role
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {isLoading ? (
          <div className="col-span-3 text-center text-[var(--color-muted-foreground)]">Loading...</div>
        ) : data?.roles?.length ? (
          data.roles.map((role: any) => (
            <div key={role.name} className="group relative rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-5 hover:border-[var(--color-primary)]/30 transition-colors">
              <div className="absolute right-3 top-3 flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                <button
                  onClick={() => openEdit(role)}
                  className="rounded p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-primary)]"
                  title="Edit"
                >
                  <Pencil className="h-3.5 w-3.5" />
                </button>
                <button
                  onClick={() => deleteMutation.mutate(role.name)}
                  disabled={deleteMutation.isPending}
                  className="rounded p-1.5 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)] hover:text-[var(--color-destructive)]"
                  title="Delete"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
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

      {/* Create / Edit Dialog */}
      {showDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
              <h2 className="font-semibold">{editingRole ? "Edit Role" : "Create Role"}</h2>
              <button
                onClick={closeDialog}
                className="rounded p-1 text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="space-y-4 p-5">
              {/* Name */}
              <div>
                <label className="mb-1.5 block text-sm font-medium">Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  disabled={!!editingRole}
                  placeholder="e.g. web-pentester"
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none disabled:opacity-50"
                />
              </div>

              {/* Icon */}
              <div>
                <label className="mb-1.5 block text-sm font-medium">Icon (emoji)</label>
                <input
                  type="text"
                  value={form.icon}
                  onChange={(e) => setForm({ ...form, icon: e.target.value })}
                  placeholder="🎯"
                  className="w-20 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>

              {/* Description */}
              <div>
                <label className="mb-1.5 block text-sm font-medium">Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="A brief description of the role"
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>

              {/* System Prompt */}
              <div>
                <label className="mb-1.5 block text-sm font-medium">System Prompt</label>
                <textarea
                  value={form.system_prompt}
                  onChange={(e) => setForm({ ...form, system_prompt: e.target.value })}
                  placeholder="You are a security testing agent specialized in..."
                  rows={5}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm font-mono focus:border-[var(--color-primary)] focus:outline-none"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
              <button
                onClick={closeDialog}
                className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted-foreground)] hover:bg-[var(--color-accent)]"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={isPending}
                className="flex items-center gap-1.5 rounded-lg bg-[var(--color-primary)] px-3 py-1.5 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90 disabled:opacity-50"
              >
                {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {editingRole ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
