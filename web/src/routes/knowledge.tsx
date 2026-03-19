import { useQuery } from "@tanstack/react-query";
import { BookOpen, Search } from "lucide-react";
import { api } from "@/lib/api";
import { useState } from "react";

export default function Knowledge() {
  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searching, setSearching] = useState(false);

  const { data } = useQuery({
    queryKey: ["knowledge"],
    queryFn: () => api.get<{ items: any[] }>("/knowledge?limit=50"),
  });

  async function handleSearch() {
    if (!query.trim()) return;
    setSearching(true);
    try {
      const res = await api.post<{ results: any[] }>("/knowledge/search", { query });
      setSearchResults(res.results ?? []);
    } catch {
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }

  const items = searchResults.length > 0 ? searchResults : (data?.items ?? []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Knowledge Base</h1>
        <p className="text-sm text-[var(--color-muted-foreground)]">Security knowledge and reference materials</p>
      </div>

      {/* Search */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-muted-foreground)]" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder="Search knowledge base..."
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] py-2 pl-10 pr-4 text-sm outline-none focus:border-[var(--color-primary)]"
          />
        </div>
        <button onClick={handleSearch} disabled={searching} className="rounded-lg bg-[var(--color-primary)] px-4 py-2 text-sm font-semibold text-[var(--color-primary-foreground)] hover:opacity-90">
          {searching ? "..." : "Search"}
        </button>
      </div>

      {/* Results */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
        {items.length > 0 ? (
          <div className="divide-y divide-[var(--color-border)]">
            {items.map((item: any, i: number) => (
              <div key={item.id ?? i} className="px-5 py-4">
                <div className="flex items-center gap-2">
                  <BookOpen className="h-4 w-4 text-[var(--color-primary)]" />
                  <h3 className="font-medium">{item.title}</h3>
                  <span className="rounded bg-[var(--color-muted)] px-2 py-0.5 text-xs">{item.category}</span>
                  {item.score && <span className="text-xs text-[var(--color-muted-foreground)]">score: {item.score.toFixed(2)}</span>}
                </div>
                <p className="mt-2 text-sm text-[var(--color-muted-foreground)] line-clamp-3">{item.content}</p>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center text-[var(--color-muted-foreground)]">
            <BookOpen className="mx-auto h-10 w-10 opacity-30" />
            <p className="mt-3">{query ? "No results found" : "Knowledge base is empty"}</p>
          </div>
        )}
      </div>
    </div>
  );
}
