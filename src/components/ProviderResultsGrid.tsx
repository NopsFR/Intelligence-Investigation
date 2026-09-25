import type { ProviderOutcome } from "@/types/provider";
import { ProviderStatusBadge } from "./Badges";
import { format } from "date-fns";

function formatFieldValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "none";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

export function ProviderResultsGrid({ results }: { results: ProviderOutcome[] }) {
  if (results.length === 0) {
    return (
      <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] px-4 py-8 text-center font-mono text-sm text-[var(--nops-text-faint)]">
        No providers support this observable type.
      </div>
    );
  }

  return (
    <div className="grid md:grid-cols-2 gap-4">
      {results.map((r) => (
        <div key={r.provider} className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] flex flex-col">
          <div className="flex items-center justify-between gap-2 border-b border-[var(--nops-border)] px-4 py-3">
            <h3 className="font-mono text-sm text-[var(--nops-text)]">{r.provider}</h3>
            <ProviderStatusBadge status={r.status} />
          </div>

          <div className="px-4 py-3 flex-1 space-y-2">
            {r.normalized?.summary && (
              <p className="text-sm text-[var(--nops-text-dim)]">{r.normalized.summary}</p>
            )}
            {r.errorMessage && <p className="text-sm text-[var(--nops-red)]">{r.errorMessage}</p>}

            {r.normalized?.fields && Object.keys(r.normalized.fields).length > 0 && (
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[11px] pt-1">
                {Object.entries(r.normalized.fields)
                  .filter(([, v]) => v !== undefined)
                  .slice(0, 10)
                  .map(([key, val]) => (
                    <div key={key} className="contents">
                      <dt className="text-[var(--nops-text-faint)] uppercase tracking-wider">{key}</dt>
                      <dd className="text-[var(--nops-text-dim)] truncate">{formatFieldValue(val)}</dd>
                    </div>
                  ))}
              </dl>
            )}

            {r.raw !== undefined && (
              <details className="pt-1">
                <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-wider text-[var(--nops-text-faint)] hover:text-[var(--nops-text-dim)]">
                  Raw response
                </summary>
                <pre className="mt-2 max-h-64 overflow-auto rounded bg-[var(--nops-bg)] p-2 font-mono text-[10px] text-[var(--nops-text-dim)]">
                  {JSON.stringify(r.raw, null, 2)}
                </pre>
              </details>
            )}
          </div>

          <div className="flex items-center justify-between border-t border-[var(--nops-border)] px-4 py-2 font-mono text-[10px] text-[var(--nops-text-faint)]">
            <span>{r.latencyMs > 0 ? `${r.latencyMs}ms` : "—"}</span>
            <span>{format(new Date(r.retrievedAt), "HH:mm:ss")}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
