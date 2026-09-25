import { ChevronRight } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ARTICLES, CATEGORY_LABEL, getArticle, relatedArticles } from "@/lib/knowledge/articles";
import { Page } from "@/components/shell/Page";
import { Panel } from "@/components/ui/primitives";
import { Chip } from "@/components/analysis/common";

type Props = { params: Promise<{ slug: string }> };

export function generateStaticParams() {
  return ARTICLES.map((a) => ({ slug: a.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const a = getArticle(slug);
  return { title: a ? a.title : "Not found" };
}

function Section({ label, children }: { label: string; children: string }) {
  return (
    <div className="border-b border-line-1 px-[var(--panel-pad)] py-3.5 last:border-0">
      <h3 className="label mb-1.5 text-fg-3">{label}</h3>
      <p className="max-w-3xl text-sm leading-relaxed text-fg-2">{children}</p>
    </div>
  );
}

export default async function TopicPage({ params }: Props) {
  const { slug } = await params;
  const a = getArticle(slug);
  if (!a) notFound();
  const related = relatedArticles(a);

  return (
    <Page>
      <nav aria-label="Breadcrumb" className="mb-3 flex items-center gap-1.5 text-xs text-fg-3">
        <Link href="/knowledge" className="hover:text-fg-1">
          Encyclopedia
        </Link>
        <ChevronRight size={12} className="text-fg-4" />
        <span>{CATEGORY_LABEL[a.category]}</span>
      </nav>
      <header className="mb-5">
        <div className="mono mb-1 text-[12px] text-fg-3">{CATEGORY_LABEL[a.category]}</div>
        <h1 className="display text-2xl text-fg-1">{a.title}</h1>
        <p className="mt-1.5 max-w-3xl text-sm text-fg-3">{a.summary}</p>
      </header>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel bodyClassName="p-0">
            <Section label="What">{a.what}</Section>
            <Section label="Why it matters">{a.why}</Section>
            <Section label="How it works">{a.how}</Section>
            <Section label="Detection">{a.detection}</Section>
            <Section label="Defence">{a.defence}</Section>
          </Panel>
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          {related.length > 0 && (
            <Panel title="Related" meta={`${related.length}`} bodyClassName="p-0">
              <ul className="divide-y divide-line-1">
                {related.map((r) => (
                  <li key={r.slug}>
                    <Link href={`/knowledge/topic/${r.slug}`} className="group flex items-center gap-2 px-[var(--panel-pad)] py-2.5">
                      <span className="min-w-0 flex-1 text-sm text-fg-1 group-hover:underline">{r.title}</span>
                      <Chip>{CATEGORY_LABEL[r.category]}</Chip>
                    </Link>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
          <Panel title="References" meta={`${a.references.length}`} bodyClassName="p-0">
            <ul className="divide-y divide-line-1">
              {a.references.map((r, i) => (
                <li key={i} className="px-[var(--panel-pad)] py-2.5 text-sm text-fg-2">
                  {r.label}
                  {r.note && <span className="block text-xs text-fg-4">{r.note}</span>}
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
    </Page>
  );
}
