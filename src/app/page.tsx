import Link from "next/link";
import { dashboardStats } from "@/lib/db/investigations";
import { PROVIDERS } from "@/lib/providers/registry";
import { ObservableSearch } from "@/components/ObservableSearch";
import { InvestigationStatusBadge } from "@/components/Badges";
import { OBSERVABLE_LABELS } from "@/types/observable";
import { formatDistanceToNow } from "date-fns";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const stats = await dashboardStats();
  const configuredCount = PROVIDERS.filter((p) => p.isConfigured()).length;

  return (
    <div className="mx-auto max-w-[1400px] px-4 md:px-6 py-10 space-y-10">
      <section className="space-y-4 max-w-3xl">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)]">
          Investigation workspace
        </p>
        <h1 className="text-2xl md:text-[28px] font-medium leading-tight text-[var(--nops-text)]">
          Enter an observable. NOPS detects its type and gathers evidence from the sources configured below.
        </h1>
        <ObservableSearch autoFocus />
      </section>

      <section className="grid grid-cols-2 md:grid-cols-4 gap-px bg-[var(--nops-border)] border border-[var(--nops-border)]">
        <StatTile label="Investigations" value={stats.totalInvestigations} />
        <StatTile label="Findings recorded" value={stats.totalFindings} />
        <StatTile label="Providers configured" value={`${configuredCount} / ${PROVIDERS.length}`} />
        <StatTile label="Complete investigations" value={stats.byStatus.COMPLETE ?? 0} />
      </section>

      <section className="grid md:grid-cols-3 gap-6">
        <div className="md:col-span-2 border border-[var(--nops-border)] bg-[var(--nops-bg-panel)]">
          <div className="flex items-center justify-between border-b border-[var(--nops-border)] px-4 py-3">
            <h2 className="font-mono text-xs uppercase tracking-wider text-[var(--nops-text-dim)]">
              Recent investigations
            </h2>
            <Link href="/history" className="font-mono text-xs text-[var(--nops-text-faint)] hover:text-[var(--nops-text)]">
              View all →
            </Link>
          </div>
          {stats.recent.length === 0 ? (
            <div className="px-4 py-10 text-center font-mono text-sm text-[var(--nops-text-faint)]">
              No investigations yet. Run one above to see it here.
            </div>
          ) : (
            <ul>
              {stats.recent.map((r) => (
                <li key={r.id} className="border-b border-[var(--nops-border)] last:border-b-0">
                  <Link
                    href={`/investigations/${r.id}`}
                    className="flex items-center justify-between gap-3 px-4 py-3 hover:bg-[var(--nops-bg-raised)] transition-colors"
                  >
                    <div className="min-w-0">
                      <p className="font-mono text-sm text-[var(--nops-text)] truncate">{r.observable}</p>
                      <p className="font-mono text-[11px] text-[var(--nops-text-faint)]">
                        {OBSERVABLE_LABELS[r.observableType]} · {formatDistanceToNow(new Date(r.createdAt), { addSuffix: true })}
                      </p>
                    </div>
                    <InvestigationStatusBadge status={r.status} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)]">
          <div className="border-b border-[var(--nops-border)] px-4 py-3">
            <h2 className="font-mono text-xs uppercase tracking-wider text-[var(--nops-text-dim)]">Findings by severity</h2>
          </div>
          <ul className="p-4 space-y-2">
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map((sev) => (
              <li key={sev} className="flex items-center justify-between font-mono text-xs">
                <span className="text-[var(--nops-text-dim)]">{sev}</span>
                <span className="text-[var(--nops-text)]">{stats.findingsBySeverity[sev] ?? 0}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-[var(--nops-bg-panel)] px-4 py-5">
      <p className="font-mono text-[11px] uppercase tracking-wider text-[var(--nops-text-faint)]">{label}</p>
      <p className="mt-1 font-mono text-2xl text-[var(--nops-text)]">{value}</p>
    </div>
  );
}
