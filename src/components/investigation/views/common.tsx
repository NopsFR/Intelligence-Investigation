"use client";

import { ArrowUpRight, FileSearch } from "lucide-react";
import type { ReactNode } from "react";
import { CATEGORY_LABELS, type ProviderOutcome } from "@/lib/core/types";
import { useCatalog } from "@/lib/client/catalog";
import { cx } from "@/lib/client/cx";
import { Prov, StatusLabel } from "@/components/ui/badges";
import { Skeleton } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";
import { FactsGrid } from "../Facts";
import { useWorkspace } from "../context";

export function useOutcome(provider: string): { planned: boolean; outcome?: ProviderOutcome } {
  const { inv } = useWorkspace();
  return { planned: inv.plan.some((s) => s.id === provider) || inv.providerResults.some((o) => o.provider === provider), outcome: inv.providerResults.find((o) => o.provider === provider) };
}

export function useData<T>(provider: string, kind?: string | string[]): T | undefined {
  const { outcome } = useOutcome(provider);
  const d = outcome?.result?.data;
  if (!d) return undefined;
  if (kind && !(Array.isArray(kind) ? kind : [kind]).includes(d.kind)) return undefined;
  return d as T;
}

/**
 * Frame for one source's contribution: provenance, state and timestamp in the
 * header, then either a specialised view, the normalised facts, or the reason
 * the source has nothing to show.
 */
export function SourceBlock({ provider, children, showFacts = true, className, title }: { provider: string; children?: ReactNode; showFacts?: boolean; className?: string; title?: ReactNode }) {
  const { planned, outcome } = useOutcome(provider);
  const { get } = useCatalog();
  const { openSource, inv } = useWorkspace();
  if (!planned) return null;
  const meta = get(provider);
  const pending = !outcome;
  const hasResult = outcome?.result && (outcome.status === "SUCCESS" || outcome.status === "PARTIAL");

  return (
    <section className={cx("panel panel-ticks", className)} aria-label={meta?.name ?? provider}>
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <Prov id={provider} />
        <h3 className="text-sm font-semibold text-fg-1">{title ?? meta?.name ?? provider}</h3>
        <span className="hidden text-xs text-fg-4 sm:inline">{meta ? `${meta.vendor} · ${CATEGORY_LABELS[meta.category]}` : null}</span>
        <span className="ml-auto flex items-center gap-3">
          {pending ? <StatusLabel state={inv.status === "RUNNING" ? "RUNNING" : "QUEUED"} /> : <StatusLabel state={outcome.status} />}
          {outcome && <Time iso={outcome.retrievedAt} className="hidden text-xs text-fg-4 md:inline" />}
          {outcome && (
            <button type="button" className="btn btn-ghost btn-sm btn-icon" aria-label={`Inspect ${meta?.name ?? provider} response`} title="Inspect response" onClick={() => openSource(provider)}>
              <FileSearch size={13} />
            </button>
          )}
        </span>
      </header>
      <div className="p-[var(--panel-pad)]">
        {pending ? (
          <div className="flex flex-col gap-2" aria-busy="true">
            <Skeleton className="h-3 w-2/5" />
            <Skeleton className="h-3 w-3/5" />
            <Skeleton className="h-3 w-1/3" />
          </div>
        ) : hasResult ? (
          <div className="flex flex-col gap-4">
            {outcome.result!.summary && <p className="text-sm text-fg-2">{outcome.result!.summary}</p>}
            {children}
            {showFacts && <FactsGrid facts={outcome.result!.facts} />}
            {!!outcome.result!.links?.length && (
              <div className="flex flex-wrap gap-2">
                {outcome.result!.links.map((l) => (
                  <a key={l.url} href={l.url} target="_blank" rel="noopener noreferrer nofollow" className="btn btn-ghost btn-sm">
                    {l.label} <ArrowUpRight size={11} />
                  </a>
                ))}
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-fg-3">{outcome.result?.summary ?? outcome.errorMessage ?? "No result."}</p>
        )}
      </div>
    </section>
  );
}

export function SectionIntro({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="mb-3 flex items-baseline gap-3">
      <h2 className="label text-fg-2">{title}</h2>
      {children && <p className="text-xs text-fg-4">{children}</p>}
    </div>
  );
}

/** Small state marker used inside specialised views (pass / warn / fail / info). */
export function Mark({ state, children }: { state: "pass" | "warn" | "fail" | "info"; children?: ReactNode }) {
  const color = state === "pass" ? "var(--color-ok)" : state === "warn" ? "var(--color-warn)" : state === "fail" ? "var(--color-err)" : "var(--color-fg-3)";
  const glyph = state === "pass" ? "✓" : state === "warn" ? "!" : state === "fail" ? "×" : "i";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" style={{ color }}>
      <span aria-hidden className="mono grid h-[15px] w-[15px] place-items-center rounded-[2px] text-[10px] font-semibold" style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${color} 35%, transparent)` }}>
        {glyph}
      </span>
      {children}
    </span>
  );
}
