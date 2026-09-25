"use client";

import { ArrowUpRight, ChevronRight, FileSearch, Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { SEVERITIES, type FindingRecord, type Severity } from "@/lib/core/types";
import { useCatalog } from "@/lib/client/catalog";
import { cx } from "@/lib/client/cx";
import { severityCounts, sortFindings } from "@/lib/client/investigation";
import { Prov, SEVERITY_COLOR, SeverityBadge } from "@/components/ui/badges";
import { CopyButton, EmptyState } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";
import { FactValueView } from "./Facts";
import { useWorkspace } from "./context";

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1.5 sm:grid-cols-[112px_minmax(0,1fr)] sm:gap-4">
      <div className="label pt-0.5">{label}</div>
      <div className="min-w-0 text-sm text-fg-2">{children}</div>
    </div>
  );
}

export function FindingItem({ finding, defaultOpen = false, isNew = false }: { finding: FindingRecord; defaultOpen?: boolean; isNew?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const { inv, openSource } = useWorkspace();
  const { name } = useCatalog();
  const ref = useRef<HTMLLIElement>(null);
  const color = SEVERITY_COLOR[finding.severity];
  const affected = finding.observable && finding.observable !== inv.normalizedObservable ? finding.observable : null;
  const bodyId = `finding-${finding.id}`;

  useEffect(() => {
    if (defaultOpen) ref.current?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [defaultOpen]);

  return (
    <li ref={ref} className={cx("group/f relative", isNew && "animate-rise")} data-severity={finding.severity}>
      <span aria-hidden className="absolute top-0 bottom-0 left-0 w-[2px] transition-opacity" style={{ background: color, opacity: open ? 1 : finding.severity === "INFO" ? 0.35 : 0.8 }} />
      <button
        type="button"
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={() => setOpen((o) => !o)}
        className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 py-3 pr-3 pl-4 text-left transition-colors hover:bg-ink-2"
      >
        <SeverityBadge severity={finding.severity} className="mt-px" />
        <span className="min-w-0">
          <span className="block text-sm font-medium text-fg-1">{finding.title}</span>
          <span className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-fg-3">
            <Prov id={finding.source} />
            <span className="hidden sm:inline">{name(finding.source)}</span>
            {affected && <span className="mono max-w-[260px] truncate text-fg-2" title={affected}>→ {affected}</span>}
            {finding.confidence && <span className="text-fg-3">Confidence: {finding.confidence}</span>}
          </span>
        </span>
        <span className="flex items-center gap-3 pt-0.5">
          <Time iso={finding.observedAt} className="hidden text-xs whitespace-nowrap text-fg-4 md:block" />
          <ChevronRight size={14} className={cx("text-fg-4 transition-transform duration-200", open && "rotate-90 text-fg-2")} aria-hidden />
        </span>
      </button>

      <div id={bodyId} className="grid transition-[grid-template-rows] duration-300 ease-[var(--ease-out-quint)]" style={{ gridTemplateRows: open ? "1fr" : "0fr" }}>
        <div className="overflow-hidden">
          <div className={cx("flex flex-col gap-3.5 pr-4 pb-4 pl-4 transition-opacity duration-300", open ? "opacity-100" : "opacity-0")} inert={!open}>
            <Section label="Finding">{finding.description}</Section>
            {finding.rationale && <Section label="Why it matters">{finding.rationale}</Section>}
            <Section label="Evidence">
              <div className="rounded-[2px] bg-ink-0 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
                <div className="flex items-start gap-2 px-3 py-2">
                  <span className="mono min-w-0 flex-1 text-[12px] break-words text-fg-1">{finding.evidence}</span>
                  <CopyButton value={finding.evidence} label="Copy evidence" />
                </div>
                {finding.evidenceData && Object.keys(finding.evidenceData).length > 0 && (
                  <dl className="grid border-t border-line-1 px-3 py-2 sm:grid-cols-[auto_minmax(0,1fr)] sm:gap-x-4">
                    {Object.entries(finding.evidenceData).map(([k, v]) => (
                      <div key={k} className="contents">
                        <dt className="mono pt-1 text-[11px] text-fg-3">{k}</dt>
                        <dd className="min-w-0 py-1 text-xs text-fg-1">
                          <FactValueView fact={{ value: v, format: Array.isArray(v) ? "list" : "mono" }} max={20} />
                        </dd>
                      </div>
                    ))}
                  </dl>
                )}
              </div>
            </Section>
            {finding.remediation && <Section label="Remediation">{finding.remediation}</Section>}
            {!!finding.references?.length && (
              <Section label="References">
                <ul className="flex flex-col gap-1">
                  {finding.references.map((r) => (
                    <li key={r.url}>
                      <a href={r.url} target="_blank" rel="noopener noreferrer nofollow" className="link inline-flex items-center gap-1 text-xs">
                        {r.label} <ArrowUpRight size={11} />
                      </a>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
            <Section label="Source">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-fg-1">{name(finding.source)}</span>
                <span className="mono text-[11px] text-fg-4">rule {finding.rule}</span>
                <span className="text-xs text-fg-4">
                  · observed <Time iso={finding.observedAt} mode="absolute" seconds />
                </span>
                <span className="ml-auto flex gap-1.5">
                  <button type="button" className="btn btn-sm" onClick={() => openSource(finding.source)}>
                    <FileSearch size={12} /> Source response
                  </button>
                  <button type="button" className="btn btn-ghost btn-sm" onClick={() => openSource(finding.source, "raw")}>
                    Raw
                  </button>
                </span>
              </div>
            </Section>
          </div>
        </div>
      </div>
    </li>
  );
}

export function FindingsList({ findings, focusId, compact = false, limit }: { findings: FindingRecord[]; focusId?: string | null; compact?: boolean; limit?: number }) {
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [source, setSource] = useState("ALL");
  const [q, setQ] = useState("");
  const { name } = useCatalog();
  // Findings retrieved after this list mounted animate in; the initial set does not.
  const [mountedAt] = useState(() => Date.now());
  const counts = severityCounts(findings);
  const sources = useMemo(() => [...new Set(findings.map((f) => f.source))], [findings]);

  const shown = sortFindings(findings).filter(
    (f) => (severity === "ALL" || f.severity === severity) && (source === "ALL" || f.source === source) && (!q || `${f.title} ${f.description} ${f.evidence} ${f.rule}`.toLowerCase().includes(q.toLowerCase()))
  );
  const visible = limit ? shown.slice(0, limit) : shown;

  if (!findings.length) {
    return <EmptyState icon={<FileSearch size={16} />} title="No findings">No finding was produced. See Sources for what each source returned — a source that answered with nothing is still a result; a failed one is not.</EmptyState>;
  }

  return (
    <div>
      {!compact && (
        <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
          <div role="radiogroup" aria-label="Filter by severity" className="flex flex-wrap gap-1">
            {(["ALL", ...SEVERITIES] as const).map((s) => {
              const n = s === "ALL" ? findings.length : counts[s];
              if (s !== "ALL" && !n) return null;
              const active = severity === s;
              return (
                <button
                  key={s}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  onClick={() => setSeverity(s)}
                  className={cx("inline-flex h-[26px] items-center gap-1.5 rounded-[2px] border px-2 text-xs transition-colors", active ? "border-line-3 bg-ink-3 text-fg-1" : "border-transparent text-fg-3 hover:text-fg-1")}
                >
                  {s !== "ALL" && <span aria-hidden className="h-[6px] w-[6px] rotate-45" style={{ background: SEVERITY_COLOR[s] }} />}
                  {s === "ALL" ? "All" : s.charAt(0) + s.slice(1).toLowerCase()}
                  <span className="mono tabular text-[10.5px] text-fg-4">{n}</span>
                </button>
              );
            })}
          </div>
          <div className="ml-auto flex items-center gap-2">
            {sources.length > 1 && (
              <select className="input h-[26px] w-auto text-xs" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Filter by source">
                <option value="ALL">All sources</option>
                {sources.map((s) => (
                  <option key={s} value={s}>
                    {name(s)}
                  </option>
                ))}
              </select>
            )}
            <label className="relative">
              <span className="sr-only">Search findings</span>
              <Search size={12} className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-fg-4" />
              <input className="input h-[26px] w-[180px] pl-6 text-xs" placeholder="Search findings" value={q} onChange={(e) => setQ(e.target.value)} />
            </label>
          </div>
        </div>
      )}
      {visible.length ? (
        <ul className="divide-y divide-line-1">
          {visible.map((f) => (
            <FindingItem key={f.id} finding={f} defaultOpen={f.id === focusId} isNew={new Date(f.observedAt).getTime() > mountedAt} />
          ))}
        </ul>
      ) : (
        <div className="px-4 py-8 text-center text-sm text-fg-3">No findings match these filters.</div>
      )}
    </div>
  );
}
