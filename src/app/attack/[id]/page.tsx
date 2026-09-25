import { ArrowUpRight, ChevronRight } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { attackDetails, loadAttack, type AttackReference, type RelatedEntity } from "@/lib/intel/attack";
import { AttackText } from "@/components/attack/AttackText";
import { Page } from "@/components/shell/Page";
import { Panel } from "@/components/ui/primitives";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props) {
  const id = (await params).id.toUpperCase();
  const index = await loadAttack();
  const d = attackDetails(index, id);
  return { title: d ? `${id} ${d.entity.name}` : "ATT&CK" };
}

const KIND_LABEL: Record<string, string> = { tactic: "Tactic", technique: "Technique", group: "Group", software: "Software", campaign: "Campaign", mitigation: "Mitigation" };

function Related({ title, items, procedures = false }: { title: string; items?: RelatedEntity[]; procedures?: boolean }) {
  if (!items?.length) return null;
  return (
    <Panel title={title} meta={`${items.length}`} bodyClassName="p-0">
      <ul className="max-h-[520px] divide-y divide-line-1 overflow-y-auto">
        {items.map((r) => (
          <li key={r.id} className="px-[var(--panel-pad)] py-2.5">
            <Link href={`/attack/${r.id}`} className="group flex items-baseline gap-3">
              <span className="mono w-[70px] shrink-0 text-[11px] text-fg-3">{r.id}</span>
              <span className="text-sm text-fg-1 group-hover:underline">{r.name}</span>
            </Link>
            {procedures && r.procedure && <AttackText text={r.procedure} className="mt-1 pl-[82px] text-xs text-fg-3" />}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export default async function AttackEntityPage({ params }: Props) {
  const id = (await params).id.toUpperCase();
  if (!/^(TA|T|G|S|C|M)\d{4}(\.\d{3})?$/.test(id)) notFound();
  const index = await loadAttack();
  const d = attackDetails(index, id);
  if (!d) notFound();
  const e = d.entity as { name: string; description: string; url: string; aliases?: string[]; platforms?: string[]; references?: AttackReference[]; modified?: string; kind?: string };
  const refs = (e.references ?? []).filter((r) => r.url && r.source !== "mitre-attack").slice(0, 30);
  return (
    <Page>
      <nav aria-label="Breadcrumb" className="mb-3 flex items-center gap-1.5 text-xs text-fg-3">
        <Link href="/attack" className="hover:text-fg-1">
          ATT&CK
        </Link>
        <ChevronRight size={12} className="text-fg-4" />
        <span>{KIND_LABEL[d.kind]}</span>
        {d.parent && (
          <>
            <ChevronRight size={12} className="text-fg-4" />
            <Link href={`/attack/${d.parent.id}`} className="hover:text-fg-1">
              {d.parent.name}
            </Link>
          </>
        )}
      </nav>
      <header className="mb-5">
        <div className="mono mb-1 text-[12px] text-fg-3">
          {id} · {KIND_LABEL[d.kind]}
          {e.kind ? ` · ${e.kind}` : ""}
        </div>
        <h1 className="display text-2xl text-fg-1">{e.name}</h1>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-3">
          {!!e.aliases?.length && <span>Also known as {e.aliases.join(", ")}</span>}
          {!!e.platforms?.length && <span>Platforms: {e.platforms.join(", ")}</span>}
          {d.tactics?.length ? (
            <span>
              Tactics:{" "}
              {d.tactics.map((t, i) => (
                <span key={t.id}>
                  {i > 0 && ", "}
                  <Link className="link" href={`/attack/${t.id}`}>
                    {t.name}
                  </Link>
                </span>
              ))}
            </span>
          ) : null}
          <a href={e.url} target="_blank" rel="noopener noreferrer" className="link inline-flex items-center gap-1">
            attack.mitre.org <ArrowUpRight size={11} />
          </a>
        </div>
      </header>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel title="Description">
            <AttackText text={e.description} className="max-w-3xl text-sm leading-relaxed text-fg-2" />
          </Panel>
          <Related title="Sub-techniques" items={d.subtechniques} />
          <Related title={d.kind === "tactic" ? "Techniques" : "Techniques used"} items={d.techniques} procedures={d.kind !== "tactic" && d.kind !== "mitigation"} />
          <Related title="Mitigations" items={d.mitigations} />
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          <Related title={d.kind === "campaign" ? "Attributed to" : "Groups"} items={d.groups} procedures={d.kind === "technique"} />
          <Related title="Software" items={d.software} procedures={d.kind === "technique"} />
          <Related title="Campaigns" items={d.campaigns} />
          {refs.length > 0 && (
            <Panel title="References" meta={`${refs.length}`} bodyClassName="p-0">
              <ul className="max-h-[360px] divide-y divide-line-1 overflow-y-auto">
                {refs.map((r, i) => (
                  <li key={i} className="px-[var(--panel-pad)] py-2 text-xs">
                    <a href={r.url} target="_blank" rel="noopener noreferrer nofollow" className="link">
                      {r.source}
                    </a>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      </div>
      <p className="mt-4 text-2xs text-fg-4">{index.meta.attribution}</p>
    </Page>
  );
}
