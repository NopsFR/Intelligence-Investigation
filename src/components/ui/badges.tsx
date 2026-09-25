"use client";

import { OBSERVABLE_SHORT, OBSERVABLE_LABELS, STATUS_LABELS, type InvestigationStatus, type ObservableType, type Severity, type TaskState } from "@/lib/core/types";
import { useCatalog } from "@/lib/client/catalog";
import { cx } from "@/lib/client/cx";

export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "var(--color-sev-critical)",
  HIGH: "var(--color-sev-high)",
  MEDIUM: "var(--color-sev-medium)",
  LOW: "var(--color-sev-low)",
  INFO: "var(--color-sev-info)",
};

const SEVERITY_TEXT: Record<Severity, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info" };

/** Severity marker: filled bars encode rank so it reads without colour. */
export function SeverityBadge({ severity, compact = false, className }: { severity: Severity; compact?: boolean; className?: string }) {
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }[severity];
  const color = SEVERITY_COLOR[severity];
  return (
    <span
      className={cx("inline-flex h-[20px] shrink-0 items-center gap-1.5 rounded-[2px] border px-1.5 text-2xs font-semibold uppercase tracking-[0.07em]", className)}
      style={{ color, borderColor: `color-mix(in srgb, ${color} 38%, transparent)`, background: `color-mix(in srgb, ${color} ${severity === "CRITICAL" ? 16 : 9}%, transparent)`, fontStretch: "80%" }}
      title={`Severity: ${SEVERITY_TEXT[severity]}`}
    >
      <span aria-hidden className="flex items-end gap-[1.5px]">
        {[0, 1, 2, 3].map((i) => (
          <span key={i} className="w-[2px] rounded-[0.5px]" style={{ height: 4 + i * 2, background: i < rank ? color : `color-mix(in srgb, ${color} 25%, transparent)` }} />
        ))}
      </span>
      {!compact && SEVERITY_TEXT[severity]}
      {compact && <span className="sr-only">{SEVERITY_TEXT[severity]}</span>}
    </span>
  );
}

export function statusColor(state: TaskState): string {
  switch (state) {
    case "SUCCESS":
    case "PARTIAL":
      return "var(--color-ok)";
    case "EMPTY":
      return "var(--color-fg-2)";
    case "QUEUED":
    case "SKIPPED":
    case "NOT_CONFIGURED":
      return "var(--color-fg-4)";
    case "RUNNING":
      return "var(--color-ice)";
    case "RATE_LIMITED":
    case "TIMEOUT":
      return "var(--color-warn)";
    default:
      return "var(--color-err)";
  }
}

export function StatusDot({ state, className }: { state: TaskState; className?: string }) {
  const hollow = state === "QUEUED" || state === "NOT_CONFIGURED" || state === "SKIPPED" || state === "EMPTY";
  return <span aria-hidden className={cx("dot", hollow && "dot-hollow", state === "RUNNING" && "dot-live", className)} style={{ color: statusColor(state) }} />;
}

export function StatusLabel({ state, className }: { state: TaskState; className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-2 whitespace-nowrap text-xs", className)} style={{ color: state === "SUCCESS" ? "var(--color-fg-2)" : statusColor(state) }}>
      <StatusDot state={state} />
      {STATUS_LABELS[state]}
    </span>
  );
}

const INVESTIGATION_STATUS: Record<InvestigationStatus, { label: string; color: string }> = {
  PENDING: { label: "Queued", color: "var(--color-fg-3)" },
  RUNNING: { label: "Running", color: "var(--color-ice)" },
  COMPLETE: { label: "Complete", color: "var(--color-ok)" },
  PARTIAL: { label: "Partial", color: "var(--color-warn)" },
  FAILED: { label: "Failed", color: "var(--color-err)" },
};

export function InvestigationStatusBadge({ status }: { status: InvestigationStatus }) {
  const s = INVESTIGATION_STATUS[status];
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs" style={{ color: s.color }}>
      <span aria-hidden className={cx("dot", status === "RUNNING" && "dot-live")} />
      {s.label}
    </span>
  );
}

export function TypeTag({ type, long = false, className }: { type: ObservableType; long?: boolean; className?: string }) {
  return (
    <span
      className={cx("mono inline-flex h-[18px] shrink-0 items-center rounded-[2px] border border-line-2 bg-ink-2 px-1.5 text-[10px] font-medium uppercase tracking-wide text-fg-2", className)}
      title={OBSERVABLE_LABELS[type]}
    >
      {long ? OBSERVABLE_LABELS[type] : OBSERVABLE_SHORT[type]}
    </span>
  );
}

/** Provenance marker: which source said this. */
export function Prov({ id, className }: { id: string; className?: string }) {
  const { get } = useCatalog();
  const meta = get(id);
  return (
    <span className={cx("prov", className)} title={meta ? `${meta.name} · ${meta.vendor}` : id}>
      {meta?.code ?? id.slice(0, 4).toUpperCase()}
    </span>
  );
}

export function ModeTag({ mode }: { mode: "QUICK" | "DEEP" }) {
  return (
    <span className={cx("label inline-flex items-center gap-1", mode === "DEEP" ? "text-fg-1" : "text-fg-3")} style={{ letterSpacing: "0.08em" }}>
      <span aria-hidden className="inline-block h-[7px] w-[7px] rotate-45 border" style={{ borderColor: "currentColor", background: mode === "DEEP" ? "currentColor" : "transparent" }} />
      {mode === "DEEP" ? "Deep" : "Quick"}
    </span>
  );
}
