"use client";

import { ExternalLink } from "lucide-react";
import type { Fact, FactValue } from "@/lib/core/types";
import { cx } from "@/lib/client/cx";
import { usePrefs } from "@/lib/client/prefs";
import { dateTime, dateOnly } from "@/lib/client/format";
import { CopyButton } from "@/components/ui/primitives";

function isUrl(v: string) {
  return /^https?:\/\//i.test(v);
}

export function FactValueView({ fact, max = 12 }: { fact: Pick<Fact, "value" | "format">; max?: number }) {
  const { prefs } = usePrefs();
  const v = fact.value;
  if (v === null || v === undefined) return <span className="text-fg-4">—</span>;
  if (typeof v === "boolean") {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span aria-hidden className="h-[6px] w-[6px] rotate-45" style={{ background: v ? "var(--color-fg-2)" : "transparent", boxShadow: v ? undefined : "inset 0 0 0 1px var(--color-fg-4)" }} />
        {v ? "Yes" : "No"}
      </span>
    );
  }
  if (Array.isArray(v)) {
    if (!v.length) return <span className="text-fg-4">—</span>;
    const shown = v.slice(0, max);
    return (
      <span className="flex flex-wrap gap-1">
        {shown.map((item, i) => (
          <span key={`${item}-${i}`} className={cx("inline-block max-w-full truncate rounded-[2px] bg-ink-2 px-1.5 py-px text-xs text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]", fact.format !== "text" && "mono text-[11.5px]")} title={item}>
            {item}
          </span>
        ))}
        {v.length > max && <span className="self-center text-xs text-fg-3">+{v.length - max} more</span>}
      </span>
    );
  }
  const s = String(v);
  switch (fact.format) {
    case "datetime":
      return <time dateTime={s} className="mono tabular text-[12px]">{dateTime(s, prefs.tz)}</time>;
    case "date":
      return <time dateTime={s} className="mono tabular text-[12px]">{dateOnly(s, prefs.tz)}</time>;
    case "number":
      return <span className="mono tabular">{typeof v === "number" ? v.toLocaleString("en-GB") : s}</span>;
    case "percent":
      return <span className="mono tabular">{typeof v === "number" ? `${(v * 100).toFixed(v < 0.01 ? 2 : 1)}%` : s}</span>;
    case "url":
      return isUrl(s) ? (
        <a href={s} target="_blank" rel="noopener noreferrer nofollow" className="link mono inline-flex max-w-full items-center gap-1 text-[12px]">
          <span className="truncate">{s}</span>
          <ExternalLink size={11} className="shrink-0 text-fg-3" />
        </a>
      ) : (
        <span className="mono break-all text-[12px]">{s}</span>
      );
    case "mono":
      return <span className="mono break-all text-[12px]">{s}</span>;
    case "code":
      return <code className="mono block rounded-[2px] bg-ink-0 px-2 py-1.5 text-[11.5px] break-all text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{s}</code>;
    default:
      return <span className="break-words">{s}</span>;
  }
}

export function valueText(v: FactValue): string {
  if (Array.isArray(v)) return v.join("\n");
  return v === null ? "" : String(v);
}

/** Two-column definition grid for provider facts. */
export function FactsGrid({ facts, columns = 2, className }: { facts: Fact[]; columns?: 1 | 2 | 3; className?: string }) {
  if (!facts.length) return null;
  return (
    <dl className={cx("grid gap-x-6", columns === 3 ? "sm:grid-cols-2 xl:grid-cols-3" : columns === 2 ? "sm:grid-cols-2" : "", className)}>
      {facts.map((f) => (
        <div key={f.key} className="group grid grid-cols-[minmax(0,140px)_minmax(0,1fr)] items-start gap-3 border-b border-line-1 py-2 last:border-0 sm:[&:nth-last-child(2)]:border-0">
          <dt className="pt-px text-xs text-fg-3">{f.label}</dt>
          <dd className="flex min-w-0 items-start gap-1 text-sm text-fg-1">
            <div className="min-w-0 flex-1">
              <FactValueView fact={f} />
            </div>
            {(f.format === "mono" || f.format === "list" || f.format === "code") && valueText(f.value) && (
              <span className="opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
                <CopyButton value={valueText(f.value)} label={`Copy ${f.label}`} />
              </span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
