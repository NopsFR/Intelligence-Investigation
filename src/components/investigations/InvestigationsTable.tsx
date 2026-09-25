"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import type { InvestigationSummary, Severity } from "@/lib/core/types";
import { cx } from "@/lib/client/cx";
import { duration } from "@/lib/client/format";
import { InvestigationStatusBadge, ModeTag, SEVERITY_COLOR, TypeTag } from "@/components/ui/badges";
import { Time } from "@/components/ui/Time";

export function FindingCounts({ counts, showZero = false }: { counts: Record<Severity, number>; showZero?: boolean }) {
  const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const shown = order.filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="text-xs text-fg-4">{counts.INFO ? `${counts.INFO} info` : showZero ? "None" : "—"}</span>;
  return (
    <span className="flex items-center gap-1" aria-label={shown.map((s) => `${counts[s]} ${s.toLowerCase()}`).join(", ")}>
      {shown.map((s) => (
        <span key={s} className="mono tabular inline-flex h-[18px] min-w-[22px] items-center justify-center gap-1 rounded-[2px] px-1 text-[10.5px] font-semibold" style={{ color: SEVERITY_COLOR[s], background: `color-mix(in srgb, ${SEVERITY_COLOR[s]} 12%, transparent)` }} title={`${counts[s]} ${s.toLowerCase()}`}>
          {s[0]}
          <span>{counts[s]}</span>
        </span>
      ))}
    </span>
  );
}

export function SourceMeter({ answered, total, failed }: { answered: number; total: number; failed: number }) {
  return (
    <span className="flex items-center gap-2" title={`${answered} answered, ${failed} failed, ${total - answered - failed} not run or not configured`}>
      <span className="flex h-[5px] w-[54px] overflow-hidden rounded-[1px] bg-ink-3" aria-hidden>
        <span className="h-full bg-ok/70" style={{ width: `${(answered / Math.max(1, total)) * 100}%` }} />
        <span className="h-full bg-warn/80" style={{ width: `${(failed / Math.max(1, total)) * 100}%` }} />
      </span>
      <span className="mono tabular text-[11px] text-fg-3">
        {answered}/{total}
      </span>
    </span>
  );
}

export function InvestigationsTable({
  items,
  selectable = false,
  selected,
  onToggle,
  dense = false,
}: {
  items: InvestigationSummary[];
  selectable?: boolean;
  selected?: Set<string>;
  onToggle?: (id: string) => void;
  dense?: boolean;
}) {
  const router = useRouter();
  return (
    <div className="overflow-x-auto">
      <table className="table">
        <thead>
          <tr>
            {selectable && (
              <th className="w-[36px]">
                <span className="sr-only">Select for comparison</span>
              </th>
            )}
            <th>Observable</th>
            <th>Mode</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Sources</th>
            <th className="text-right">Started</th>
            {!dense && <th className="text-right">Duration</th>}
          </tr>
        </thead>
        <tbody>
          {items.map((inv) => (
            <tr key={inv.id} data-selected={selected?.has(inv.id) ? "true" : undefined} className="cursor-pointer" onClick={(e) => !(e.target as HTMLElement).closest("a,button,input") && router.push(`/investigations/${inv.id}`)}>
              {selectable && (
                <td className="align-middle">
                  <input
                    type="checkbox"
                    aria-label={`Select ${inv.normalizedObservable} for comparison`}
                    checked={selected?.has(inv.id) ?? false}
                    onChange={() => onToggle?.(inv.id)}
                    className="h-3.5 w-3.5 accent-[var(--color-fg-2)]"
                  />
                </td>
              )}
              <td className="max-w-[520px]">
                <div className="flex min-w-0 items-center gap-2">
                  <TypeTag type={inv.observableType} />
                  <Link href={`/investigations/${inv.id}`} className="mono truncate text-[12.5px] text-fg-1 hover:underline">
                    {inv.normalizedObservable}
                  </Link>
                </div>
                {!dense && inv.summary && <div className={cx("mt-1 truncate pl-[calc(38px+0.5rem)] text-xs text-fg-3")}>{inv.summary}</div>}
              </td>
              <td className="align-middle">
                <ModeTag mode={inv.mode} />
              </td>
              <td className="align-middle">
                <InvestigationStatusBadge status={inv.status} />
              </td>
              <td className="align-middle">
                <FindingCounts counts={inv.findingCounts} />
              </td>
              <td className="align-middle">
                <SourceMeter answered={inv.providerCounts.answered} total={inv.providerCounts.total} failed={inv.providerCounts.failed} />
              </td>
              <td className="text-right align-middle text-xs whitespace-nowrap text-fg-3">
                <Time iso={inv.createdAt} />
              </td>
              {!dense && <td className="mono tabular text-right align-middle text-[11px] text-fg-3">{inv.status === "RUNNING" ? "…" : duration(inv.durationMs)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
