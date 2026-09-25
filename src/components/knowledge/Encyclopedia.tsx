"use client";

import { BookOpen, Search } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { ARTICLES, CATEGORY_LABEL, type Article, type ArticleCategory } from "@/lib/knowledge/articles";
import { EmptyState } from "@/components/ui/primitives";

const CATEGORIES = Object.keys(CATEGORY_LABEL) as ArticleCategory[];

function matches(a: Article, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return a.title.toLowerCase().includes(q) || a.summary.toLowerCase().includes(q) || a.what.toLowerCase().includes(q);
}

export function Encyclopedia() {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<ArticleCategory | null>(null);

  const filtered = useMemo(() => ARTICLES.filter((a) => (!category || a.category === category) && matches(a, query)), [query, category]);
  const byCategory = useMemo(() => {
    const groups = new Map<ArticleCategory, Article[]>();
    for (const a of filtered) {
      const list = groups.get(a.category) ?? [];
      list.push(a);
      groups.set(a.category, list);
    }
    return groups;
  }, [filtered]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-fg-4" />
          <input className="input h-9 w-full pl-8" placeholder="Search articles…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search encyclopedia" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            aria-pressed={category === null}
            onClick={() => setCategory(null)}
            className={`rounded-[2px] border px-2 py-1 text-xs transition-colors ${category === null ? "border-fg-3 bg-ink-2 text-fg-1" : "border-line-2 text-fg-3 hover:text-fg-1"}`}
          >
            All
          </button>
          {CATEGORIES.map((c) => (
            <button
              key={c}
              type="button"
              aria-pressed={category === c}
              onClick={() => setCategory(c === category ? null : c)}
              className={`rounded-[2px] border px-2 py-1 text-xs transition-colors ${category === c ? "border-fg-3 bg-ink-2 text-fg-1" : "border-line-2 text-fg-3 hover:text-fg-1"}`}
            >
              {CATEGORY_LABEL[c]}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-fg-4">
          {filtered.length} of {ARTICLES.length} articles
        </span>
      </div>

      {!filtered.length ? (
        <EmptyState icon={<Search size={17} />} title="No articles match">
          Try a different search term or category.
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-6">
          {[...byCategory.entries()].map(([cat, articles]) => (
            <section key={cat}>
              <h2 className="label mb-2 text-fg-3">{CATEGORY_LABEL[cat]}</h2>
              <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
                {articles.map((a) => (
                  <Link key={a.slug} href={`/knowledge/topic/${a.slug}`} className="panel panel-ticks group flex flex-col gap-1.5 p-4 transition-colors hover:bg-ink-2">
                    <div className="flex items-center gap-2">
                      <BookOpen size={13} className="shrink-0 text-fg-4" />
                      <h3 className="text-sm font-medium text-fg-1 group-hover:underline">{a.title}</h3>
                    </div>
                    <p className="text-xs text-fg-3">{a.summary}</p>
                  </Link>
                ))}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
