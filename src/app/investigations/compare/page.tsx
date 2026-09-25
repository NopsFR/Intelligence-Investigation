import { ArrowRight, ChevronRight } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { SEVERITY_RANK, type FactValue, type InvestigationRecord } from "@/lib/core/types";
import { getInvestigation } from "@/lib/db/investigations";
import { PROVIDERS } from "@/lib/providers/registry";
import { Page } from "@/components/shell/Page";
import { ModeTag, Prov, SeverityBadge, StatusLabel, TypeTag } from "@/components/ui/badges";
import { EmptyState, ErrorNote, Panel } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";

export const metadata = { title: "Compare investigations" };

const NAMES = Object.fromEntries(PROVIDERS.map((p) => [p.id, p.name]));

function text(v: FactValue): string {
  return Array.isArray(v) ? [...v].sort().join(", ") : v === null ? "—" : String(v);
}

function diff(a: InvestigationRecord, b: InvestigationRecord) {
  const key = (f: { rule: string; title: string; source: string }) => `${f.source}|${f.rule}|${f.title}`;
  const aKeys = new Map(a.findings.map((f) => [key(f), f]));
  const bKeys = new Map(b.findings.map((f) => [key(f), f]));
  const added = b.findings.filter((f) => !aKeys.has(key(f)));
  const resolved = a.findings.filter((f) => !bKeys.has(key(f)));
  const persisting = b.findings.filter((f) => aKeys.has(key(f)));

  const factChanges: { provider: string; label: string; before: string; after: string }[] = [];
  for (const ob of b.providerResults) {
    const oa = a.providerResults.find((x) => x.provider === ob.provider);
    if (!oa?.result || !ob.result) continue;
    for (const fb of ob.result.facts) {
      const fa = oa.result.facts.find((x) => x.key === fb.key);
      if (fa && text(fa.value) !== text(fb.value)) factChanges.push({ provider: ob.provider, label: fb.label, before: text(fa.value), after: text(fb.value) });
    }
  }

  const statusChanges = b.providerResults
    .map((ob) => ({ provider: ob.provider, before: a.providerResults.find((x) => x.provider === ob.provider)?.status, after: ob.status }))
    .filter((s) => s.before && s.before !== s.after);

  const edge = (r: InvestigationRecord["relationships"][number]) => `${r.source.type}:${r.source.value}|${r.type}|${r.target.type}:${r.target.value}`.toLowerCase();
  const aEdges = new Set(a.relationships.map(edge));
  const bEdges = new Set(b.relationships.map(edge));
  const newEdges = b.relationships.filter((r) => !aEdges.has(edge(r)));
  const goneEdges = a.relationships.filter((r) => !bEdges.has(edge(r)));
  return { added, resolved, persisting, factChanges, statusChanges, newEdges, goneEdges };
}

function Side({ inv, label }: { inv: InvestigationRecord; label: string }) {
  return (
    <Link href={`/investigations/${inv.id}`} className="panel panel-ticks block p-[var(--panel-pad)] transition-colors hover:border-line-3">
      <div className="label mb-1.5">{label}</div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-fg-3">
        <Time iso={inv.createdAt} mode="absolute" className="mono text-fg-1" />
        <ModeTag mode={inv.mode} />
        <span>{inv.findings.length} findings</span>
        <span>{inv.relationships.length} relationships</span>
      </div>
      <p className="mt-2 line-clamp-2 text-xs text-fg-3">{inv.summary}</p>
    </Link>
  );
}

export default async function ComparePage({ searchParams }: { searchParams: Promise<{ a?: string; b?: string }> }) {
  const { a: aId, b: bId } = await searchParams;
  if (!aId || !bId || !/^[a-z0-9]{8,40}$/i.test(aId) || !/^[a-z0-9]{8,40}$/i.test(bId)) notFound();
  const [x, y] = await Promise.all([getInvestigation(aId), getInvestigation(bId)]);
  if (!x || !y) notFound();
  // Always read left → right as older → newer.
  const [a, b] = new Date(x.createdAt) <= new Date(y.createdAt) ? [x, y] : [y, x];
  const d = diff(a, b);
  const sameObservable = a.normalizedObservable === b.normalizedObservable && a.observableType === b.observableType;

  return (
    <Page>
      <nav aria-label="Breadcrumb" className="mb-3 flex items-center gap-1.5 text-xs text-fg-3">
        <Link href="/investigations" className="hover:text-fg-1">
          Investigations
        </Link>
        <ChevronRight size={12} className="text-fg-4" />
        <span>Compare</span>
      </nav>
      <header className="mb-5">
        <div className="flex flex-wrap items-center gap-3">
          <TypeTag type={b.observableType} />
          <h1 className="mono text-[22px] break-all text-fg-1">{b.normalizedObservable}</h1>
        </div>
        {!sameObservable && (
          <div className="mt-3">
            <ErrorNote title="Different observables">
              You are comparing <span className="mono">{a.normalizedObservable}</span> with <span className="mono">{b.normalizedObservable}</span>. Differences below reflect both change over time and the different subject.
            </ErrorNote>
          </div>
        )}
      </header>

      <div className="mb-5 grid items-center gap-3 md:grid-cols-[1fr_auto_1fr]">
        <Side inv={a} label="Before" />
        <ArrowRight size={16} className="mx-auto hidden text-fg-4 md:block" aria-hidden />
        <Side inv={b} label="After" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="New findings" meta={`${d.added.length}`} bodyClassName="p-0">
          {d.added.length ? (
            <ul className="divide-y divide-line-1">
              {[...d.added].sort((p, q) => SEVERITY_RANK[p.severity] - SEVERITY_RANK[q.severity]).map((f) => (
                <li key={f.id} className="flex items-start gap-3 px-[var(--panel-pad)] py-2.5">
                  <SeverityBadge severity={f.severity} compact />
                  <span className="min-w-0 flex-1 text-sm text-fg-1">{f.title}</span>
                  <Prov id={f.source} />
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="Nothing new" />
          )}
        </Panel>
        <Panel title="No longer reported" meta={`${d.resolved.length}`} bodyClassName="p-0">
          {d.resolved.length ? (
            <ul className="divide-y divide-line-1">
              {d.resolved.map((f) => (
                <li key={f.id} className="flex items-start gap-3 px-[var(--panel-pad)] py-2.5 opacity-80">
                  <SeverityBadge severity={f.severity} compact />
                  <span className="min-w-0 flex-1 text-sm text-fg-2 line-through decoration-fg-4">{f.title}</span>
                  <Prov id={f.source} />
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="Nothing dropped" />
          )}
        </Panel>

        <Panel title="Changed facts" meta={`${d.factChanges.length}`} bodyClassName="p-0" className="xl:col-span-2">
          {d.factChanges.length ? (
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Fact</th>
                    <th>Before</th>
                    <th>After</th>
                  </tr>
                </thead>
                <tbody>
                  {d.factChanges.map((c, i) => (
                    <tr key={i}>
                      <td className="whitespace-nowrap">
                        <span className="flex items-center gap-2">
                          <Prov id={c.provider} /> <span className="text-xs text-fg-2">{NAMES[c.provider] ?? c.provider}</span>
                        </span>
                      </td>
                      <td className="text-xs text-fg-2">{c.label}</td>
                      <td className="mono max-w-[360px] text-[11.5px] break-words text-fg-3">{c.before}</td>
                      <td className="mono max-w-[360px] text-[11.5px] break-words text-fg-1">{c.after}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No fact changed between the two runs" />
          )}
        </Panel>

        <Panel title="Relationships" meta={`+${d.newEdges.length} / −${d.goneEdges.length}`} bodyClassName="p-0">
          {d.newEdges.length + d.goneEdges.length ? (
            <ul className="divide-y divide-line-1 text-xs">
              {d.newEdges.slice(0, 60).map((r) => (
                <li key={`n-${r.id}`} className="mono flex gap-2 px-[var(--panel-pad)] py-2 text-[11.5px] text-fg-1">
                  <span className="text-ok">+</span>
                  <span className="truncate">
                    {r.source.value} —{r.type}→ {r.target.value}
                  </span>
                </li>
              ))}
              {d.goneEdges.slice(0, 60).map((r) => (
                <li key={`g-${r.id}`} className="mono flex gap-2 px-[var(--panel-pad)] py-2 text-[11.5px] text-fg-3">
                  <span className="text-err">−</span>
                  <span className="truncate">
                    {r.source.value} —{r.type}→ {r.target.value}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="Same relationships" />
          )}
        </Panel>

        <Panel title="Source state changes" meta={`${d.statusChanges.length}`} bodyClassName="p-0">
          {d.statusChanges.length ? (
            <ul className="divide-y divide-line-1">
              {d.statusChanges.map((s) => (
                <li key={s.provider} className="flex flex-wrap items-center gap-3 px-[var(--panel-pad)] py-2 text-xs">
                  <Prov id={s.provider} />
                  <span className="min-w-[140px] text-fg-2">{NAMES[s.provider] ?? s.provider}</span>
                  <StatusLabel state={s.before!} />
                  <ArrowRight size={12} className="text-fg-4" />
                  <StatusLabel state={s.after} />
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="Every source behaved the same way" />
          )}
        </Panel>
      </div>
      <p className="mt-4 text-2xs text-fg-4">
        {d.persisting.length} findings present in both runs.
      </p>
    </Page>
  );
}
