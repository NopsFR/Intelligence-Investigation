"use client";

import { Loader2, Search } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

interface Hit {
  id: string;
  kind: string;
  name: string;
  detail: string;
}

export function AttackSearch() {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (q.trim().length < 2) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- clear results for short queries
      setHits([]);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/attack/search?q=${encodeURIComponent(q.trim())}`, { signal: controller.signal });
        if (res.ok) setHits(((await res.json()) as { results: Hit[] }).results);
      } catch {
        /* aborted */
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 150);
    return () => {
      clearTimeout(t);
      controller.abort();
    };
  }, [q]);
  return (
    <div className="relative">
      <label className="relative block">
        <span className="sr-only">Search ATT&CK</span>
        <Search size={14} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-fg-4" />
        <input className="input h-[36px] pl-9" placeholder="Search techniques, groups, software, campaigns, mitigations — by name, alias or ID" value={q} onChange={(e) => setQ(e.target.value)} />
        {loading && <Loader2 size={13} className="absolute top-1/2 right-3 -translate-y-1/2 animate-spin text-fg-4" />}
      </label>
      {hits.length > 0 && (
        <ul className="panel absolute inset-x-0 top-[calc(100%+4px)] z-20 max-h-[360px] animate-rise overflow-y-auto p-1 shadow-[0_16px_48px_rgba(0,0,0,0.55)]">
          {hits.map((h) => (
            <li key={h.id}>
              <Link href={`/attack/${h.id}`} className="flex items-center gap-3 rounded-[2px] px-3 py-2 hover:bg-ink-2">
                <span className="mono w-[72px] shrink-0 text-[11px] text-fg-3">{h.id}</span>
                <span className="min-w-0 flex-1 truncate text-sm text-fg-1">{h.name}</span>
                <span className="truncate text-xs text-fg-4">{h.detail}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
