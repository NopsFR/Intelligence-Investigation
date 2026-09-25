import Link from "next/link";
import { listInvestigations } from "@/lib/db/investigations";
import { InvestigationStatusBadge } from "@/components/Badges";
import { DeleteInvestigationButton } from "@/components/DeleteInvestigationButton";
import { OBSERVABLE_LABELS, OBSERVABLE_TYPES } from "@/types/observable";
import { format } from "date-fns";

export default async function HistoryPage({
  searchParams,
}: {
  searchParams: Promise<{ search?: string; type?: string }>;
}) {
  const { search, type } = await searchParams;
  const { items, total } = await listInvestigations({ search, observableType: type, limit: 50 });

  return (
    <div className="mx-auto max-w-[1200px] px-4 md:px-6 py-10 space-y-6">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-1">
          {total} recorded
        </p>
        <h1 className="text-2xl font-medium text-[var(--nops-text)]">Investigation history</h1>
      </div>

      <form className="flex flex-wrap gap-2" method="get">
        <input
          name="search"
          defaultValue={search}
          placeholder="Search observable..."
          className="flex-1 min-w-[200px] rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)] px-3 py-2 font-mono text-sm text-[var(--nops-text)] outline-none focus:border-[var(--nops-red-dim)]"
        />
        <select
          name="type"
          defaultValue={type ?? ""}
          className="rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)] px-3 py-2 font-mono text-sm text-[var(--nops-text)]"
        >
          <option value="">All types</option>
          {OBSERVABLE_TYPES.map((t) => (
            <option key={t} value={t}>
              {OBSERVABLE_LABELS[t]}
            </option>
          ))}
        </select>
        <button className="rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-4 py-2 font-mono text-xs uppercase tracking-wider text-[var(--nops-text)]">
          Filter
        </button>
      </form>

      {items.length === 0 ? (
        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] px-4 py-10 text-center font-mono text-sm text-[var(--nops-text-faint)]">
          No investigations match this filter.
        </div>
      ) : (
        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)]">
          <ul>
            {items.map((r) => (
              <li key={r.id} className="border-b border-[var(--nops-border)] last:border-b-0">
                <div className="flex items-center gap-3 px-4 py-3 hover:bg-[var(--nops-bg-raised)] transition-colors">
                  <Link href={`/investigations/${r.id}`} className="min-w-0 flex-1">
                    <p className="font-mono text-sm text-[var(--nops-text)] truncate">{r.observable}</p>
                    <p className="font-mono text-[11px] text-[var(--nops-text-faint)]">
                      {OBSERVABLE_LABELS[r.observableType]} · {r.mode} · {format(new Date(r.createdAt), "yyyy-MM-dd HH:mm")} ·{" "}
                      {r.findings.length} finding(s)
                    </p>
                  </Link>
                  <InvestigationStatusBadge status={r.status} />
                  <DeleteInvestigationButton id={r.id} />
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
