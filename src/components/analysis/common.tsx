"use client";

import { ChevronRight } from "lucide-react";
import Link from "next/link";
import { useMemo, useState, type ReactNode } from "react";
import { SEVERITIES, type Severity } from "@/lib/core/types";
import { cx } from "@/lib/client/cx";
import { SEVERITY_COLOR, SeverityBadge } from "@/components/ui/badges";
import { CopyButton, EmptyState } from "@/components/ui/primitives";

// Shared building blocks for the local analysis workspaces (file, packet
// capture, code, detection): findings produced in the browser, key/value
// grids, entropy strips, tag chips.

export interface LocalFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: string[];
  attack?: string[];
  basis: string;
}

const BASIS_LABEL: Record<string, string> = {
  structure: "Observed in structure",
  capability: "Capability (imports)",
  heuristic: "Heuristic",
  signature: "Signature",
  rule: "Rule match",
  traffic: "Observed in traffic",
};

export function AttackChip({ id }: { id: string }) {
  return (
    <Link href={`/attack/${id}`} className="mono inline-flex h-[18px] items-center rounded-[2px] border border-line-2 px-1.5 text-[10.5px] text-fg-2 transition-colors hover:border-fg-4 hover:text-fg-1" title={`MITRE ATT&CK ${id}`}>
      {id}
    </Link>
  );
}

export function Chip({ children, tone = "neutral", title }: { children: ReactNode; tone?: "neutral" | "warn" | "err" | "ok" | "ice"; title?: string }) {
  const color = tone === "warn" ? "var(--color-warn)" : tone === "err" ? "var(--color-err)" : tone === "ok" ? "var(--color-ok)" : tone === "ice" ? "var(--color-ice)" : "var(--color-fg-3)";
  return (
    <span title={title} className="mono inline-flex h-[18px] shrink-0 items-center rounded-[2px] px-1.5 text-[10.5px] whitespace-nowrap" style={{ color, background: `color-mix(in srgb, ${color} 11%, transparent)`, boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${color} 28%, transparent)` }}>
      {children}
    </span>
  );
}

function LocalFindingItem({ finding }: { finding: LocalFinding }) {
  const [open, setOpen] = useState(false);
  const color = SEVERITY_COLOR[finding.severity];
  return (
    <li className="relative" data-severity={finding.severity}>
      <span aria-hidden className="absolute top-0 bottom-0 left-0 w-[2px]" style={{ background: color, opacity: open ? 1 : finding.severity === "INFO" ? 0.35 : 0.8 }} />
      <button type="button" aria-expanded={open} onClick={() => setOpen((o) => !o)} className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 py-3 pr-3 pl-4 text-left transition-colors hover:bg-ink-2">
        <SeverityBadge severity={finding.severity} className="mt-px" />
        <span className="min-w-0">
          <span className="block text-sm font-medium text-fg-1">{finding.title}</span>
          <span className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-fg-3">
            <span>{BASIS_LABEL[finding.basis] ?? finding.basis}</span>
            {finding.attack?.map((a) => (
              <span key={a} onClick={(e) => e.stopPropagation()}>
                <AttackChip id={a} />
              </span>
            ))}
          </span>
        </span>
        <ChevronRight size={14} className={cx("mt-1 text-fg-4 transition-transform duration-200", open && "rotate-90 text-fg-2")} aria-hidden />
      </button>
      <div className="grid transition-[grid-template-rows] duration-300 ease-[var(--ease-out-quint)]" style={{ gridTemplateRows: open ? "1fr" : "0fr" }}>
        <div className="overflow-hidden">
          <div className={cx("flex flex-col gap-3 pr-4 pb-4 pl-4 transition-opacity duration-300", open ? "opacity-100" : "opacity-0")} inert={!open}>
            <p className="max-w-3xl text-sm text-fg-2">{finding.detail}</p>
            {finding.evidence.length > 0 && (
              <div className="rounded-[2px] bg-ink-0 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
                <div className="flex items-center border-b border-line-1 px-3 py-1.5">
                  <span className="label">Evidence</span>
                  <CopyButton value={finding.evidence.join("\n")} label="Copy evidence" className="ml-auto" />
                </div>
                <ul className="px-3 py-2">
                  {finding.evidence.map((e, i) => (
                    <li key={i} className="mono py-0.5 text-[11.5px] break-all text-fg-1">
                      {e}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      </div>
    </li>
  );
}

/** Findings produced by a local analyser, with a severity filter. */
export function LocalFindings({ findings, empty }: { findings: LocalFinding[]; empty?: ReactNode }) {
  const [filter, setFilter] = useState<Severity | "ALL">("ALL");
  const counts = useMemo(() => Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<Severity, number>, [findings]);
  const shown = filter === "ALL" ? findings : findings.filter((f) => f.severity === filter);
  if (!findings.length) return <EmptyState title="No findings">{empty ?? "Nothing in the structure or content matched a rule. That is an absence of evidence, not a clean bill of health."}</EmptyState>;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-1.5 border-b border-line-1 px-3 py-2" role="group" aria-label="Filter by severity">
        <button type="button" onClick={() => setFilter("ALL")} className={cx("btn btn-sm", filter === "ALL" ? "btn-primary" : "btn-ghost")}>
          All <span className="mono tabular text-[10.5px] opacity-70">{findings.length}</span>
        </button>
        {SEVERITIES.filter((s) => counts[s]).map((s) => (
          <button key={s} type="button" onClick={() => setFilter(s)} className={cx("btn btn-sm", filter === s ? "btn-primary" : "btn-ghost")}>
            <span aria-hidden className="h-2 w-2 rounded-[1px]" style={{ background: SEVERITY_COLOR[s] }} />
            {s[0] + s.slice(1).toLowerCase()} <span className="mono tabular text-[10.5px] opacity-70">{counts[s]}</span>
          </button>
        ))}
      </div>
      <ul className="divide-y divide-line-1">
        {shown.map((f, i) => (
          <LocalFindingItem key={`${f.id}-${i}`} finding={f} />
        ))}
      </ul>
    </div>
  );
}

/** Label / value grid for headers and metadata. */
export function KV({ rows, className }: { rows: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cx("grid grid-cols-[minmax(120px,auto)_minmax(0,1fr)] gap-x-5 text-sm", className)}>
      {rows
        .filter(([, v]) => v !== undefined && v !== null && v !== "")
        .map(([k, v], i) => (
          <div key={i} className="contents">
            <dt className="border-b border-line-1 py-1.5 text-xs text-fg-3">{k}</dt>
            <dd className="min-w-0 border-b border-line-1 py-1.5 break-words text-fg-1">{v}</dd>
          </div>
        ))}
    </dl>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("mono text-[12px]", className)}>{children}</span>;
}

export const entropyColor = (e: number) => (e >= 7.2 ? "var(--color-sev-high)" : e >= 6.5 ? "var(--color-sev-medium)" : e >= 4 ? "var(--color-ice)" : "var(--color-fg-4)");

/** Entropy bar with its value, 0 – 8 bits per byte. */
export function EntropyMeter({ value, width = 64 }: { value: number; width?: number }) {
  return (
    <span className="inline-flex items-center gap-2" title={`${value.toFixed(3)} bits per byte`}>
      <span className="relative h-[5px] overflow-hidden rounded-[1px] bg-ink-3" style={{ width }}>
        <span className="absolute inset-y-0 left-0" style={{ width: `${(value / 8) * 100}%`, background: entropyColor(value) }} />
      </span>
      <span className="mono tabular text-[11.5px] text-fg-2">{value.toFixed(2)}</span>
    </span>
  );
}

/**
 * Entropy across the file as a strip chart, with labelled regions (sections,
 * overlay). Clicking a point reports its offset.
 */
export function EntropyProfile({ profile, size, regions = [], onSelect, height = 88 }: { profile: { offset: number; size: number; entropy: number }[]; size: number; regions?: { start: number; end: number; label: string }[]; onSelect?: (offset: number) => void; height?: number }) {
  const [hover, setHover] = useState<number | null>(null);
  if (!profile.length || !size) return null;
  const W = 1000;
  const pts = profile.map((p) => [((p.offset + p.size / 2) / size) * W, height - (p.entropy / 8) * (height - 6)] as const);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  const area = `${line}L${pts[pts.length - 1][0].toFixed(1)},${height}L${pts[0][0].toFixed(1)},${height}Z`;
  const hp = hover !== null ? profile[hover] : null;
  return (
    <figure className="m-0">
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" className="block h-[88px] w-full cursor-crosshair" role="img" aria-label="Entropy across the file"
          onMouseMove={(e) => {
            const r = e.currentTarget.getBoundingClientRect();
            const x = ((e.clientX - r.left) / r.width) * size;
            const idx = profile.findIndex((p) => x >= p.offset && x < p.offset + p.size);
            setHover(idx >= 0 ? idx : null);
          }}
          onMouseLeave={() => setHover(null)}
          onClick={() => hp && onSelect?.(hp.offset)}
        >
          {regions.map((r, i) => (
            <rect key={i} x={(r.start / size) * W} width={Math.max(1, ((r.end - r.start) / size) * W)} y={0} height={height} fill={i % 2 ? "var(--color-ink-2)" : "var(--color-ink-1)"} opacity={0.9} />
          ))}
          {[2, 4, 6].map((v) => (
            <line key={v} x1={0} x2={W} y1={height - (v / 8) * (height - 6)} y2={height - (v / 8) * (height - 6)} stroke="var(--color-line-1)" strokeDasharray="2 4" vectorEffect="non-scaling-stroke" />
          ))}
          <line x1={0} x2={W} y1={height - (7.2 / 8) * (height - 6)} y2={height - (7.2 / 8) * (height - 6)} stroke="var(--color-sev-high)" strokeOpacity={0.35} strokeDasharray="4 3" vectorEffect="non-scaling-stroke" />
          <path d={area} fill="color-mix(in srgb, var(--color-ice) 14%, transparent)" />
          <path d={line} fill="none" stroke="var(--color-ice)" strokeWidth={1.25} vectorEffect="non-scaling-stroke" />
          {hp && <line x1={((hp.offset + hp.size / 2) / size) * W} x2={((hp.offset + hp.size / 2) / size) * W} y1={0} y2={height} stroke="var(--color-fg-2)" vectorEffect="non-scaling-stroke" />}
        </svg>
        <div className="pointer-events-none absolute top-1 right-2 mono text-[11px] text-fg-2">
          {hp ? (
            <>
              0x{hp.offset.toString(16)} · {hp.entropy.toFixed(2)} bits/byte
              {regions.find((r) => hp.offset >= r.start && hp.offset < r.end) && <span className="text-fg-1"> · {regions.find((r) => hp.offset >= r.start && hp.offset < r.end)!.label}</span>}
            </>
          ) : (
            <span className="text-fg-4">hover for offset · click to open in hex</span>
          )}
        </div>
      </div>
      <figcaption className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-fg-4">
        <span>0 – 8 bits/byte</span>
        <span className="text-[color-mix(in_srgb,var(--color-sev-high)_80%,var(--color-fg-3))]">— — 7.2 packed / encrypted threshold</span>
        {regions.slice(0, 12).map((r, i) => (
          <button key={i} type="button" className="mono hover:text-fg-1" onClick={() => onSelect?.(r.start)}>
            {r.label}
          </button>
        ))}
      </figcaption>
    </figure>
  );
}

/** Filterable, sortable table for moderately sized lists. */
export function DataTable<T>({ rows, columns, empty = "Nothing to show.", max = 2000, rowKey }: { rows: T[]; columns: { key: string; label: ReactNode; render: (row: T) => ReactNode; className?: string; sort?: (row: T) => string | number }[]; empty?: ReactNode; max?: number; rowKey?: (row: T, i: number) => string }) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sort) return rows;
    return [...rows].sort((a, b) => {
      const x = col.sort!(a);
      const y = col.sort!(b);
      return (x < y ? -1 : x > y ? 1 : 0) * sort.dir;
    });
  }, [rows, sort, columns]);
  if (!rows.length) return <p className="px-1 py-4 text-sm text-fg-3">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.className} aria-sort={sort?.key === c.key ? (sort.dir === 1 ? "ascending" : "descending") : undefined}>
                {c.sort ? (
                  <button type="button" className="inline-flex items-center gap-1 hover:text-fg-1" onClick={() => setSort((s) => (s?.key === c.key ? { key: c.key, dir: s.dir === 1 ? -1 : 1 } : { key: c.key, dir: 1 }))}>
                    {c.label}
                    {sort?.key === c.key && <span aria-hidden>{sort.dir === 1 ? "↑" : "↓"}</span>}
                  </button>
                ) : (
                  c.label
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.slice(0, max).map((r, i) => (
            <tr key={rowKey ? rowKey(r, i) : i}>
              {columns.map((c) => (
                <td key={c.key} className={c.className}>
                  {c.render(r)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > max && <p className="px-3 py-2 text-xs text-fg-4">Showing {max.toLocaleString()} of {rows.length.toLocaleString()}.</p>}
    </div>
  );
}

export function downloadJson(name: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, (_k, v) => (v instanceof Uint8Array ? undefined : typeof v === "bigint" ? v.toString() : v), 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
