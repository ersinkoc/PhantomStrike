import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import { toast } from "sonner";
import { useAuthStore } from "@/stores/auth";

export default function Login() {
  const [password, setPassword] = useState("");
  const { login, isLoading } = useAuthStore();
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    try {
      await login("admin@phantomstrike.local", password);
      navigate("/");
    } catch {
      toast.error("Invalid password");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--color-background)]">
      <div className="w-full max-w-sm space-y-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-8">
        {/* Logo */}
        <div className="text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl bg-[var(--color-primary)]/10">
            <Shield className="h-8 w-8 text-[var(--color-primary)]" />
          </div>
          <h1 className="mt-4 text-2xl font-bold">
            Phantom<span className="text-[var(--color-primary)]">Strike</span>
          </h1>
          <p className="mt-1 text-sm text-[var(--color-muted-foreground)]">
            You point. It hunts.
          </p>
        </div>

        {/* Password only */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm text-[var(--color-muted-foreground)]">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoFocus
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2.5 text-sm outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
              placeholder="Enter admin password"
            />
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full rounded-lg bg-[var(--color-primary)] px-4 py-2.5 text-sm font-semibold text-[var(--color-primary-foreground)] transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {isLoading ? "Authenticating..." : "Unlock"}
          </button>
        </form>

        <p className="text-center text-xs text-[var(--color-muted-foreground)]">
          Set password via ADMIN_PASSWORD in .env
        </p>
      </div>
    </div>
  );
}
