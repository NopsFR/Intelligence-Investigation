import type { Finding } from "@/types/finding";
import { SeverityBadge } from "./Badges";
import { format } from "date-fns";

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] px-4 py-8 text-center font-mono text-sm text-[var(--nops-text-faint)]">
        No findings were generated. This does not guarantee the observable is safe — it reflects only what the
        configured providers returned.
      </div>
    );
  }

  return (
    <ul className="space-y-3">
      {findings.map((f) => (
        <li key={f.id} className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] p-4">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <SeverityBadge severity={f.severity} />
            <h3 className="font-medium text-[var(--nops-text)]">{f.title}</h3>
          </div>
          <p className="text-sm text-[var(--nops-text-dim)] mb-3">{f.description}</p>
          <dl className="grid sm:grid-cols-3 gap-x-4 gap-y-1 font-mono text-[11px]">
            <div className="sm:col-span-3">
              <dt className="text-[var(--nops-text-faint)] uppercase tracking-wider inline">Evidence </dt>
              <dd className="text-[var(--nops-text-dim)] inline">{f.evidence}</dd>
            </div>
            <div>
              <dt className="text-[var(--nops-text-faint)] uppercase tracking-wider inline">Source </dt>
              <dd className="text-[var(--nops-text-dim)] inline">{f.source}</dd>
            </div>
            <div>
              <dt className="text-[var(--nops-text-faint)] uppercase tracking-wider inline">Observed </dt>
              <dd className="text-[var(--nops-text-dim)] inline">{format(new Date(f.observedAt), "yyyy-MM-dd HH:mm 'UTC'")}</dd>
            </div>
            {f.confidence && (
              <div>
                <dt className="text-[var(--nops-text-faint)] uppercase tracking-wider inline">Confidence </dt>
                <dd className="text-[var(--nops-text-dim)] inline">{f.confidence}</dd>
              </div>
            )}
          </dl>
        </li>
      ))}
    </ul>
  );
}
