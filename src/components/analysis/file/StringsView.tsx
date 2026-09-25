"use client";

import { useDeferredValue, useMemo, useState } from "react";
import type { ExtractedString, StringTag } from "@/lib/analysis/strings";
import { cx } from "@/lib/client/cx";
import { useVirtual } from "@/components/ui/workbench";
import { Chip } from "../common";

const TAGS: StringTag[] = ["url", "ip", "domain", "email", "path", "registry", "command", "api", "user-agent", "crypto", "base64", "pdb"];

/** Virtualised strings table with search, encoding and tag filters. */
export function StringsView({ strings, truncated, onOffset }: { strings: ExtractedString[]; truncated: boolean; onOffset?: (offset: number) => void }) {
  const [q, setQ] = useState("");
  const [tag, setTag] = useState<StringTag | "tagged" | "all">("all");
  const [enc, setEnc] = useState<"all" | "ascii" | "utf16le">("all");
  const [minLen, setMinLen] = useState(5);
  const dq = useDeferredValue(q);

  const tagCounts = useMemo(() => {
    const m = new Map<StringTag, number>();
    for (const s of strings) for (const t of s.tags) m.set(t, (m.get(t) ?? 0) + 1);
    return m;
  }, [strings]);

  const filtered = useMemo(() => {
    let re: RegExp | null = null;
    const needle = dq.trim();
    if (needle.startsWith("/") && needle.length > 2 && needle.endsWith("/")) {
      try {
        re = new RegExp(needle.slice(1, -1), "i");
      } catch {
        re = null;
      }
    }
    const lower = needle.toLowerCase();
    return strings.filter((s) => {
      if (s.value.length < minLen) return false;
      if (enc !== "all" && s.encoding !== enc) return false;
      if (tag === "tagged" && !s.tags.length) return false;
      if (tag !== "all" && tag !== "tagged" && !s.tags.includes(tag)) return false;
      if (!needle) return true;
      return re ? re.test(s.value) : s.value.toLowerCase().includes(lower);
    });
  }, [strings, dq, tag, enc, minLen]);

  const { ref: listRef, start, end, total } = useVirtual(filtered.length, 26, 16);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-3 py-2">
        <input className="input h-8 w-full max-w-xs text-sm" placeholder="Search strings, or /regex/" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search strings" />
        <select className="input h-8 w-auto text-xs" value={enc} onChange={(e) => setEnc(e.target.value as typeof enc)} aria-label="Encoding">
          <option value="all">ASCII + UTF-16</option>
          <option value="ascii">ASCII only</option>
          <option value="utf16le">UTF-16LE only</option>
        </select>
        <label className="flex items-center gap-1.5 text-xs text-fg-3">
          Min length
          <input type="number" min={4} max={64} className="input mono h-8 w-16 text-xs" value={minLen} onChange={(e) => setMinLen(Math.max(4, Math.min(64, Number(e.target.value) || 5)))} />
        </label>
        <span className="mono ml-auto text-[11px] text-fg-3 tabular">
          {filtered.length.toLocaleString()} / {strings.length.toLocaleString()}
          {truncated && " (first 20,000 extracted)"}
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5 border-b border-line-1 px-3 py-2" role="group" aria-label="Filter by tag">
        {(["all", "tagged", ...TAGS.filter((t) => tagCounts.has(t))] as const).map((t) => (
          <button key={t} type="button" onClick={() => setTag(t)} className={cx("btn btn-sm", tag === t ? "btn-primary" : "btn-ghost")}>
            {t === "all" ? "All" : t === "tagged" ? "Interesting" : t}
            {t !== "all" && t !== "tagged" && <span className="mono text-[10.5px] opacity-70">{tagCounts.get(t)}</span>}
          </button>
        ))}
      </div>
      <div ref={listRef} className="relative overflow-auto" style={{ height: 520 }}>
        <div style={{ height: total, position: "relative" }}>
          {filtered.slice(start, end).map((s, k) => {
            const i = start + k;
            return (
              <button
                key={`${s.offset}-${s.encoding}`}
                type="button"
                onClick={() => onOffset?.(s.offset)}
                title="Show in hex view"
                className="absolute right-0 left-0 flex items-center gap-3 px-3 text-left hover:bg-ink-2"
                style={{ top: i * 26, height: 26 }}
              >
                <span className="mono w-[84px] shrink-0 text-[11px] text-fg-4 tabular">0x{s.offset.toString(16).padStart(6, "0")}</span>
                <span className="mono w-[34px] shrink-0 text-[10px] text-fg-4">{s.encoding === "ascii" ? "A" : "U16"}</span>
                <span className="mono min-w-0 flex-1 truncate text-[12px] text-fg-1">{s.value}</span>
                <span className="hidden shrink-0 gap-1 md:flex">
                  {s.tags.map((t) => (
                    <Chip key={t} tone={t === "command" || t === "registry" ? "warn" : t === "url" || t === "ip" || t === "domain" ? "ice" : "neutral"}>
                      {t}
                    </Chip>
                  ))}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
