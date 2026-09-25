import type { FindingSeverity } from "@/types/finding";
import type { ProviderStatus } from "@/types/provider";
import { PROVIDER_STATUS_LABELS } from "@/types/provider";

const SEVERITY_STYLES: Record<FindingSeverity, string> = {
  CRITICAL: "text-[var(--nops-red)] border-[var(--nops-red-dim)] bg-[var(--nops-red-bg)]",
  HIGH: "text-[#e0713a] border-[#5a3620] bg-[rgba(224,113,58,0.08)]",
  MEDIUM: "text-[var(--nops-amber)] border-[#5a4620] bg-[rgba(201,138,44,0.08)]",
  LOW: "text-[var(--nops-blue)] border-[#2a4656] bg-[rgba(79,131,168,0.08)]",
  INFO: "text-[var(--nops-text-dim)] border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)]",
};

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

const STATUS_STYLES: Record<ProviderStatus, string> = {
  SUCCESS: "text-[var(--nops-green)] border-[#1f4a34] bg-[rgba(63,156,109,0.08)]",
  PARTIAL: "text-[var(--nops-amber)] border-[#5a4620] bg-[rgba(201,138,44,0.08)]",
  EMPTY: "text-[var(--nops-text-dim)] border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)]",
  NOT_CONFIGURED: "text-[var(--nops-text-faint)] border-[var(--nops-border)] bg-transparent",
  RATE_LIMITED: "text-[var(--nops-amber)] border-[#5a4620] bg-[rgba(201,138,44,0.08)]",
  AUTH_FAILED: "text-[var(--nops-red)] border-[var(--nops-red-dim)] bg-[var(--nops-red-bg)]",
  TIMEOUT: "text-[var(--nops-amber)] border-[#5a4620] bg-[rgba(201,138,44,0.08)]",
  NETWORK_ERROR: "text-[var(--nops-red)] border-[var(--nops-red-dim)] bg-[var(--nops-red-bg)]",
  INVALID_RESPONSE: "text-[var(--nops-red)] border-[var(--nops-red-dim)] bg-[var(--nops-red-bg)]",
  UNAVAILABLE: "text-[var(--nops-text-dim)] border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)]",
};

export function ProviderStatusBadge({ status }: { status: ProviderStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider ${STATUS_STYLES[status]}`}
    >
      {PROVIDER_STATUS_LABELS[status]}
    </span>
  );
}

export function InvestigationStatusBadge({ status }: { status: "PENDING" | "RUNNING" | "COMPLETE" | "PARTIAL" | "FAILED" }) {
  const styles: Record<string, string> = {
    COMPLETE: "text-[var(--nops-green)] border-[#1f4a34] bg-[rgba(63,156,109,0.08)]",
    PARTIAL: "text-[var(--nops-amber)] border-[#5a4620] bg-[rgba(201,138,44,0.08)]",
    FAILED: "text-[var(--nops-red)] border-[var(--nops-red-dim)] bg-[var(--nops-red-bg)]",
    PENDING: "text-[var(--nops-text-dim)] border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)]",
    RUNNING: "text-[var(--nops-blue)] border-[#2a4656] bg-[rgba(79,131,168,0.08)]",
  };
  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-xs uppercase tracking-wider ${styles[status]}`}>
      {status}
    </span>
  );
}
