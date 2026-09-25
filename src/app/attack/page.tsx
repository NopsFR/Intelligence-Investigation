import Link from "next/link";
import { attackMatrix, loadAttack } from "@/lib/intel/attack";
import { AttackSearch } from "@/components/attack/AttackSearch";
import { Page } from "@/components/shell/Page";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "MITRE ATT&CK" };

export default async function AttackPage() {
  const index = await loadAttack();
  const matrix = attackMatrix(index);
  const total = [...index.techniques.values()];
  return (
    <Page width="full">
      <PageHeader
        eyebrow="Intelligence"
        title="MITRE ATT&CK"
        description={`Enterprise ATT&CK ${index.meta.version} — ${total.filter((t) => !t.isSubtechnique).length} techniques, ${total.filter((t) => t.isSubtechnique).length} sub-techniques, ${index.groups.size} groups, ${index.software.size} software entries, ${index.campaigns.size} campaigns. Investigations map malware families and tagged techniques onto this dataset.`}
      />
      <div className="mb-4 max-w-[760px]">
        <AttackSearch />
      </div>
      <div className="panel panel-ticks overflow-hidden">
        <div className="flex gap-px overflow-x-auto bg-line-1">
          {matrix.map((col) => (
            <section key={col.tactic.id} className="w-[176px] shrink-0 bg-ink-1" aria-label={col.tactic.name}>
              <Link href={`/attack/${col.tactic.id}`} className="sticky top-0 block border-b border-line-2 bg-ink-2 px-2.5 py-2 hover:bg-ink-3">
                <span className="block text-[12.5px] leading-tight font-semibold text-fg-1">{col.tactic.name}</span>
                <span className="mono text-[10px] text-fg-4">
                  {col.tactic.id} · {col.techniques.length}
                </span>
              </Link>
              <ul className="flex flex-col gap-px p-1">
                {col.techniques.map((t) => (
                  <li key={t.id}>
                    <Link href={`/attack/${t.id}`} className="group block rounded-[2px] px-2 py-1.5 transition-colors hover:bg-ink-3">
                      <span className="block text-[11.5px] leading-snug text-fg-2 group-hover:text-fg-1">{t.name}</span>
                      <span className="mono text-[9.5px] text-fg-4">
                        {t.id}
                        {t.subtechniques > 0 && ` · ${t.subtechniques} sub`}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </div>
      <p className="mt-3 text-2xs text-fg-4">{index.meta.attribution}</p>
    </Page>
  );
}
