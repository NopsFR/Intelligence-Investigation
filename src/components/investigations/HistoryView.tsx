"use client";

import { GitCompareArrows, ListTree, Loader2, Search, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { OBSERVABLE_LABELS, OBSERVABLE_TYPES, SEVERITIES, type InvestigationSummary } from "@/lib/core/types";
import { api } from "@/lib/client/api";
import { cx } from "@/lib/client/cx";
import { EmptyState, ErrorNote } from "@/components/ui/primitives";
import { InvestigationsTable } from "./InvestigationsTable";

interface ListResponse {
  items: InvestigationSummary[];
  nextCursor?: string;
}

export function HistoryView({ initial }: { initial: ListResponse }) {
  const router = useRouter();
  const path = usePathname();
  const params = useSearchParams();
  const [items, setItems] = useState(initial.items);
  const [cursor, setCursor] = useState(initial.nextCursor);
  const [q, setQ] = useState(params.get("q") ?? "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const first = useRef(true);

  const type = params.get("type") ?? "";
  const status = params.get("status") ?? "";
  const severity = params.get("severity") ?? "";

  const setParam = (key: string, value: string) => {
    const sp = new URLSearchParams(params.toString());
    if (value) sp.set(key, value);
    else sp.delete(key);
    router.replace(`${path}${sp.size ? `?${sp}` : ""}`, { scroll: false });
  };

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    const controller = new AbortController();
    const t = setTimeout(async () => {
      setLoading(true);
      try {
        const sp = new URLSearchParams({ limit: "40" });
        if (q.trim()) sp.set("q", q.trim());
        for (const [k, v] of [["type", type], ["status", status], ["severity", severity]]) if (v) sp.set(k, v);
        const res = await api<ListResponse>(`/api/investigations?${sp}`, { signal: controller.signal });
        setItems(res.items);
        setCursor(res.nextCursor);
        setError(null);
      } catch (e) {
        if (!controller.signal.aborted) setError((e as Error).message);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 180);
    return () => {
      clearTimeout(t);
      controller.abort();
    };
  }, [q, type, status, severity]);

  const more = async () => {
    if (!cursor) return;
    setLoading(true);
    try {
      const sp = new URLSearchParams(params.toString());
      sp.set("limit", "40");
      sp.set("cursor", cursor);
      if (q.trim()) sp.set("q", q.trim());
      const res = await api<ListResponse>(`/api/investigations?${sp}`);
      setItems((prev) => [...prev, ...res.items]);
      setCursor(res.nextCursor);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else if (next.size < 2) next.add(id);
      else {
        const [firstId] = next;
        next.delete(firstId);
        next.add(id);
      }
      return next;
    });

  const filtered = Boolean(q || type || status || severity);
  const pair = [...selected];

  return (
    <div className="panel panel-ticks">
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <label className="relative min-w-[220px] flex-1 sm:max-w-[340px]">
          <span className="sr-only">Search investigations</span>
          <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-fg-4" />
          <input className="input mono h-[30px] pl-8 text-[12px]" placeholder="Filter by observable" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <select className="input h-[30px] w-auto text-xs" value={type} onChange={(e) => setParam("type", e.target.value)} aria-label="Observable type">
          <option value="">All types</option>
          {OBSERVABLE_TYPES.map((t) => (
            <option key={t} value={t}>
              {OBSERVABLE_LABELS[t]}
            </option>
          ))}
        </select>
        <select className="input h-[30px] w-auto text-xs" value={status} onChange={(e) => setParam("status", e.target.value)} aria-label="Status">
          <option value="">Any status</option>
          {["RUNNING", "COMPLETE", "PARTIAL", "FAILED"].map((s) => (
            <option key={s} value={s}>
              {s.charAt(0) + s.slice(1).toLowerCase()}
            </option>
          ))}
        </select>
        <select className="input h-[30px] w-auto text-xs" value={severity} onChange={(e) => setParam("severity", e.target.value)} aria-label="Has finding of severity">
          <option value="">Any findings</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              Has {s.toLowerCase()}
            </option>
          ))}
        </select>
        {filtered && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => (setQ(""), router.replace(path, { scroll: false }))}>
            <X size={12} /> Clear
          </button>
        )}
        {loading && <Loader2 size={14} className="animate-spin text-fg-4" aria-label="Loading" />}
        <div className="ml-auto flex items-center gap-2">
          <span className="hidden text-xs text-fg-4 md:inline">{selected.size ? `${selected.size}/2 selected` : "Select two to compare"}</span>
          <Link
            href={pair.length === 2 ? `/investigations/compare?a=${pair[0]}&b=${pair[1]}` : "#"}
            aria-disabled={pair.length !== 2}
            className={cx("btn btn-sm", pair.length !== 2 && "pointer-events-none opacity-40")}
          >
            <GitCompareArrows size={13} /> Compare
          </Link>
        </div>
      </div>
      {error && (
        <div className="p-3">
          <ErrorNote title="Could not load investigations">{error}</ErrorNote>
        </div>
      )}
      {items.length ? (
        <>
          <InvestigationsTable items={items} selectable selected={selected} onToggle={toggle} />
          {cursor && (
            <div className="flex justify-center border-t border-line-1 p-3">
              <button type="button" className="btn btn-sm" onClick={() => void more()} disabled={loading}>
                {loading ? <Loader2 size={12} className="animate-spin" /> : null} Load older investigations
              </button>
            </div>
          )}
        </>
      ) : (
        <EmptyState icon={<ListTree size={16} />} title={filtered ? "No investigations match these filters" : "No investigations yet"}>
          {filtered ? "Try a broader filter, or clear it." : "Paste an observable into the command bar (press / to focus it) to start one."}
        </EmptyState>
      )}
    </div>
  );
}
