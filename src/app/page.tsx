import { ArrowUpRight, Radar } from "lucide-react";
import Link from "next/link";
import { OBSERVABLE_LABELS, SEVERITIES, type Severity } from "@/lib/core/types";
import { dashboardData, type DashboardData } from "@/lib/db/dashboard";
import { Page } from "@/components/shell/Page";
import { ExampleObservables } from "@/components/dashboard/FirstRun";
import { InvestigationsTable } from "@/components/investigations/InvestigationsTable";
import { Prov, SEVERITY_COLOR, SeverityBadge, TypeTag } from "@/components/ui/badges";
import { Bars, EmptyState, ErrorNote, PageHeader, Panel, Stat } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";

export const metadata = { title: "Dashboard" };

const STATE_META: { key: string; label: string; color: string }[] = [
  { key: "CONNECTED", label: "Connected", color: "var(--color-ok)" },
  { key: "UNTESTED", label: "Not yet tested", color: "var(--color-fg-3)" },
  { key: "RATE_LIMITED", label: "Rate limited", color: "var(--color-warn)" },
  { key: "TIMEOUT", label: "Timing out", color: "var(--color-warn)" },
  { key: "AUTH_FAILED", label: "Auth failed", color: "var(--color-err)" },
  { key: "UNAVAILABLE", label: "Unavailable", color: "var(--color-err)" },
  { key: "ERROR", label: "Error", color: "var(--color-err)" },
  { key: "NOT_CONFIGURED", label: "Not configured", color: "var(--color-fg-4)" },
];

function SeverityDistribution({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((a, s) => a + counts[s], 0);
  return (
    <div>
      <div className="flex h-[8px] overflow-hidden rounded-[1px] bg-ink-3" role="img" aria-label={SEVERITIES.map((s) => `${counts[s]} ${s.toLowerCase()}`).join(", ")}>
        {SEVERITIES.map((s) => (counts[s] ? <div key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: SEVERITY_COLOR[s] }} className="h-full border-r border-ink-1 last:border-0" /> : null))}
      </div>
      <dl className="mt-3 grid grid-cols-5 gap-2">
        {SEVERITIES.map((s) => (
          <div key={s}>
            <dt className="label" style={{ color: counts[s] ? SEVERITY_COLOR[s] : undefined }}>
              {s === "CRITICAL" ? "Crit" : s === "MEDIUM" ? "Med" : s.toLowerCase()}
            </dt>
            <dd className="display tabular mt-0.5 text-lg text-fg-1">{counts[s]}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function Dashboard({ data }: { data: DashboardData }) {
  const empty = data.totals.investigations === 0;
  const findingsTotal = SEVERITIES.reduce((a, s) => a + data.severity30d[s], 0);
  return (
    <>
      <PageHeader
        eyebrow={
          <>
            <span className="h-[6px] w-[6px] bg-signal" aria-hidden /> Operations overview
          </>
        }
        title="Dashboard"
        description={empty ? "Nothing has been investigated yet. Everything here is computed from your own investigations and live source checks — nothing is simulated." : "What needs attention, what you have looked at, and whether your intelligence sources are healthy."}
      />

      {empty ? (
        <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
          <Panel title="Start an investigation" className="grid-canvas">
            <p className="mb-4 max-w-xl text-sm text-fg-2">
              Paste any observable into the bar above — or press <kbd className="kbd">/</kbd> to focus it. A <span className="text-fg-1">quick scan</span> queries passive sources only; a <span className="text-fg-1">deep investigation</span> also probes the target directly.
            </p>
            <div className="label mb-2">Try a real observable</div>
            <ExampleObservables />
          </Panel>
          <SourcesPanel data={data} />
        </div>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
          <div className="flex min-w-0 flex-col gap-4">
            <Panel title="Needs attention" meta="Critical and high findings · last 30 days" bodyClassName="p-0">
              {data.attention.length ? (
                <ul className="divide-y divide-line-1">
                  {data.attention.map((f) => (
                    <li key={f.id}>
                      <Link href={`/investigations/${f.investigationId}?finding=${f.id}`} className="group grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1 px-[var(--panel-pad)] py-3 transition-colors hover:bg-ink-2">
                        <SeverityBadge severity={f.severity} compact className="mt-0.5" />
                        <div className="min-w-0">
                          <div className="truncate text-sm font-medium text-fg-1 group-hover:underline">{f.title}</div>
                          <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-fg-3">
                            <span className="mono truncate text-fg-2">{f.observable}</span>
                            <Prov id={f.source} />
                          </div>
                        </div>
                        <Time iso={f.observedAt} className="text-xs whitespace-nowrap text-fg-4" />
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No critical or high findings in the last 30 days">Lower-severity findings are still recorded on each investigation.</EmptyState>
              )}
            </Panel>

            <Panel
              title="Recent investigations"
              actions={
                <Link href="/investigations" className="btn btn-ghost btn-sm">
                  All investigations <ArrowUpRight size={12} />
                </Link>
              }
              bodyClassName="p-0"
            >
              <InvestigationsTable items={data.recent} dense />
            </Panel>
          </div>

          <div className="flex min-w-0 flex-col gap-4">
            <Panel title="Activity" meta="Investigations per day · 14 days">
              <div className="mb-4 grid grid-cols-3 gap-4">
                <Stat label="Total" value={data.totals.investigations.toLocaleString("en-GB")} />
                <Stat label="Last 7 days" value={data.totals.last7d.toLocaleString("en-GB")} />
                <Stat label="Running" value={data.totals.running} sub={data.totals.running ? "in progress now" : undefined} />
              </div>
              <Bars values={data.activity.map((a) => a.count)} labels={data.activity.map((a) => a.day)} height={44} />
              <div className="mono mt-1.5 flex justify-between text-[10px] text-fg-4">
                <span>{data.activity[0]?.day}</span>
                <span>today</span>
              </div>
            </Panel>

            <Panel title="Findings" meta={`${findingsTotal.toLocaleString("en-GB")} in the last 30 days`}>
              <SeverityDistribution counts={data.severity30d} />
            </Panel>

            <SourcesPanel data={data} />

            {data.recurring.length > 0 && (
              <Panel title="Recurring observables" meta="Investigated more than once" bodyClassName="p-0">
                <ul className="divide-y divide-line-1">
                  {data.recurring.map((r) => (
                    <li key={`${r.type}:${r.value}`}>
                      <Link href={`/investigations/${r.lastId}`} className="flex items-center gap-3 px-[var(--panel-pad)] py-2.5 hover:bg-ink-2">
                        <TypeTag type={r.type} />
                        <span className="mono min-w-0 flex-1 truncate text-[12.5px] text-fg-1">{r.value}</span>
                        <span className="mono tabular text-xs text-fg-2">×{r.count}</span>
                        <Time iso={r.lastAt} className="w-[90px] text-right text-xs text-fg-4" />
                      </Link>
                    </li>
                  ))}
                </ul>
              </Panel>
            )}

            <Panel title="Observable mix">
              <ul className="flex flex-col gap-2">
                {data.byType.map((t) => (
                  <li key={t.type} className="grid grid-cols-[110px_1fr_40px] items-center gap-3 text-xs">
                    <span className="truncate text-fg-2">{OBSERVABLE_LABELS[t.type]}</span>
                    <span className="h-[5px] rounded-[1px] bg-ink-3">
                      <span className="block h-full rounded-[1px] bg-fg-3" style={{ width: `${(t.count / Math.max(...data.byType.map((x) => x.count))) * 100}%` }} />
                    </span>
                    <span className="mono tabular text-right text-fg-3">{t.count}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}

function SourcesPanel({ data }: { data: DashboardData }) {
  const s = data.sources;
  return (
    <Panel
      title="Intelligence sources"
      meta={s.lastCheckedAt ? <>Last connection test <Time iso={s.lastCheckedAt} /></> : "No connection tests run yet"}
      actions={
        <Link href="/observatory" className="btn btn-ghost btn-sm">
          Observatory <ArrowUpRight size={12} />
        </Link>
      }
    >
      <div className="mb-3 flex items-baseline gap-2">
        <span className="display tabular text-2xl text-fg-1">{s.configured}</span>
        <span className="text-sm text-fg-3">of {s.external} external sources configured · {s.total - s.external} native & derived analysers</span>
      </div>
      <div className="mb-3 flex h-[6px] overflow-hidden rounded-[1px] bg-ink-3" aria-hidden>
        {STATE_META.map((m) => (s.states[m.key as keyof typeof s.states] ? <div key={m.key} style={{ width: `${((s.states[m.key as keyof typeof s.states] ?? 0) / s.external) * 100}%`, background: m.color }} className="h-full border-r border-ink-1" /> : null))}
      </div>
      <ul className="grid grid-cols-2 gap-x-4 gap-y-1.5">
        {STATE_META.filter((m) => s.states[m.key as keyof typeof s.states]).map((m) => (
          <li key={m.key} className="flex items-center gap-2 text-xs">
            <span className="dot" style={{ color: m.color }} aria-hidden />
            <span className="text-fg-2">{m.label}</span>
            <span className="mono tabular ml-auto text-fg-3">{s.states[m.key as keyof typeof s.states]}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export default async function DashboardPage() {
  let data: DashboardData | null = null;
  let error: string | null = null;
  try {
    data = await dashboardData();
  } catch (err) {
    error = (err as Error).message.split("\n")[0];
  }
  return (
    <Page>
      {data ? (
        <Dashboard data={data} />
      ) : (
        <>
          <PageHeader title="Dashboard" />
          <ErrorNote title="The database is not reachable">
            {error} — investigations, history and the IOC library need the database. Check <code className="mono">DATABASE_URL</code> and the <Link className="link" href="/settings?section=database">database settings</Link>.
          </ErrorNote>
          <div className="mt-6">
            <EmptyState icon={<Radar size={18} />} title="Live analysis still works once the database is back" />
          </div>
        </>
      )}
    </Page>
  );
}
