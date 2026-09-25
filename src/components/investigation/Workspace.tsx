"use client";

import { ChevronDown, ChevronRight, Download, FileText, History, Library, Loader2, MoreHorizontal, Printer, RotateCw, Trash2 } from "lucide-react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { OBSERVABLE_LABELS, type Fact, type InvestigationRecord, type InvestigationSummary } from "@/lib/core/types";
import { api, ApiClientError } from "@/lib/client/api";
import { useCatalog } from "@/lib/client/catalog";
import { cx } from "@/lib/client/cx";
import { duration } from "@/lib/client/format";
import { useInvestigate } from "@/lib/client/investigate";
import { progressOf, sortFindings, useElapsed, useLiveInvestigation } from "@/lib/client/investigation";
import { useSession } from "@/lib/client/session";
import { InvestigationStatusBadge, ModeTag, Prov, StatusDot, TypeTag } from "@/components/ui/badges";
import { Dialog, Tabs, useToast, type TabItem } from "@/components/ui/overlays";
import { CopyButton, ErrorNote, Skeleton } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";
import { FindingCounts } from "@/components/investigations/InvestigationsTable";
import { FactValueView } from "./Facts";
import { FindingsList } from "./Findings";
import { ProgressStrip, SourceDrawer, SourcesTable } from "./Sources";
import { WorkspaceContext } from "./context";
import { CertificatesSection, WebSection } from "./views/web";
import { DnsSection, EmailSection } from "./views/dns";
import { AssessmentPanel, AttackSection, InfrastructureSection, ThreatIntelSection, TimelineSection, VulnerabilitySection } from "./views/intel";

const EvidenceGraph = dynamic(() => import("./graph/EvidenceGraph"), {
  ssr: false,
  loading: () => <Skeleton className="h-[560px] rounded-none" />,
});

type HistoryItem = Pick<InvestigationSummary, "id" | "createdAt" | "mode" | "status" | "summary" | "findingCounts">;

const SECTION_PROVIDERS: Record<string, string[]> = {
  intel: ["virustotal", "abuseipdb", "greynoise", "otx", "threatfox", "urlhaus", "malwarebazaar", "yaraify", "circl-hashlookup", "feodo", "internetdb", "kev-exposure"],
  vulnerability: ["cve-org", "nvd", "cisa-kev", "epss"],
  dns: ["dns", "dnssec", "reverse-dns", "hostname-analysis"],
  email: ["email-security"],
  certificates: ["tls", "certspotter", "crtsh"],
  web: ["http", "url-analysis"],
  infrastructure: ["address-context", "hosting", "rdap", "ripestat"],
  attack: ["attack"],
};

function Menu({ label, icon, children, align = "right" }: { label: string; icon: ReactNode; children: (close: () => void) => ReactNode; align?: "left" | "right" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);
  return (
    <div ref={ref} className="relative">
      <button type="button" className="btn btn-sm" aria-haspopup="menu" aria-expanded={open} aria-label={label || "More actions"} onClick={() => setOpen((o) => !o)}>
        {icon}
        {label && <span className="hidden sm:inline">{label}</span>}
        {label && <ChevronDown size={12} className="text-fg-3" />}
      </button>
      {open && (
        <div role="menu" className={cx("panel absolute top-[calc(100%+6px)] z-30 min-w-[230px] animate-rise p-1 shadow-[0_16px_48px_rgba(0,0,0,0.55)]", align === "right" ? "right-0" : "left-0")}>
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}

function MenuItem({ icon, children, hint, onClick, href, download }: { icon: ReactNode; children: ReactNode; hint?: string; onClick?: () => void; href?: string; download?: boolean }) {
  const cls = "flex w-full items-start gap-2.5 rounded-[2px] px-2.5 py-2 text-left text-sm text-fg-1 hover:bg-ink-2";
  const body = (
    <>
      <span className="mt-0.5 text-fg-3">{icon}</span>
      <span>
        <span className="block">{children}</span>
        {hint && <span className="block text-xs text-fg-4">{hint}</span>}
      </span>
    </>
  );
  return href ? (
    <a role="menuitem" href={href} className={cls} download={download} onClick={onClick}>
      {body}
    </a>
  ) : (
    <button role="menuitem" type="button" className={cls} onClick={onClick}>
      {body}
    </button>
  );
}

function KeyFacts({ inv }: { inv: InvestigationRecord }) {
  const rows = useMemo(() => {
    const out: { provider: string; fact: Fact }[] = [];
    const seen = new Set<string>();
    for (const o of inv.providerResults) {
      if (o.provider === "correlation" || !o.result) continue;
      for (const f of o.result.facts) {
        if (!f.primary) continue;
        const key = `${f.label}:${JSON.stringify(f.value)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ provider: o.provider, fact: f });
      }
    }
    return out.slice(0, 24);
  }, [inv.providerResults]);
  if (!rows.length) return null;
  return (
    <section className="panel panel-ticks" aria-label="Key facts">
      <header className="border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <h2 className="label text-fg-2">Key facts</h2>
      </header>
      <dl className="divide-y divide-line-1">
        {rows.map(({ provider, fact }) => (
          <div key={`${provider}-${fact.key}`} className="grid grid-cols-[minmax(0,150px)_minmax(0,1fr)_auto] items-start gap-3 px-[var(--panel-pad)] py-2">
            <dt className="pt-px text-xs text-fg-3">{fact.label}</dt>
            <dd className="min-w-0 text-sm text-fg-1">
              <FactValueView fact={fact} max={6} />
            </dd>
            <Prov id={provider} />
          </div>
        ))}
      </dl>
    </section>
  );
}

function CompactSources({ inv }: { inv: InvestigationRecord }) {
  const { steps } = progressOf(inv);
  const { name } = useCatalog();
  return (
    <ul className="divide-y divide-line-1">
      {steps.map((s) => (
        <li key={s.id} className="flex items-center gap-2.5 px-[var(--panel-pad)] py-[7px]">
          <StatusDot state={s.state} />
          <span className={cx("min-w-0 flex-1 truncate text-xs", s.outcome ? "text-fg-1" : "text-fg-3")}>{name(s.id)}</span>
          <span key={s.state} className="mono animate-fade text-[10.5px] text-fg-4">
            {s.outcome ? (s.outcome.cached ? "cache" : s.outcome.status === "SKIPPED" || s.outcome.status === "NOT_CONFIGURED" ? "—" : duration(s.outcome.latencyMs)) : s.state === "RUNNING" ? "…" : ""}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function Workspace({ initial, history }: { initial: InvestigationRecord; history: HistoryItem[] }) {
  const { inv, error } = useLiveInvestigation(initial);
  const router = useRouter();
  const path = usePathname();
  const params = useSearchParams();
  const toast = useToast();
  const { session } = useSession();
  const { start, pending: rerunning } = useInvestigate();
  const [source, setSource] = useState<{ id: string; focus?: "raw" } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const running = inv.status === "RUNNING";
  const elapsed = useElapsed(inv.createdAt, running, inv.durationMs);
  const { get: meta, name: sourceName } = useCatalog();
  const progress = progressOf(inv, (id) => meta(id)?.kind === "derived");
  const findings = useMemo(() => sortFindings(inv.findings), [inv.findings]);
  const planned = useMemo(() => new Set([...inv.plan.map((s) => s.id), ...inv.providerResults.map((o) => o.provider)]), [inv.plan, inv.providerResults]);
  const has = useCallback((section: string) => SECTION_PROVIDERS[section].some((p) => planned.has(p)), [planned]);

  const tabs: TabItem[] = useMemo(() => {
    const t: TabItem[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings", count: inv.findings.length }];
    if (inv.observableType === "CVE" && has("vulnerability")) t.push({ id: "vulnerability", label: "Vulnerability" });
    if (has("intel")) t.push({ id: "intel", label: "Threat intel" });
    if (has("dns")) t.push({ id: "dns", label: "DNS" });
    if (has("email")) t.push({ id: "email", label: "Email security" });
    if (has("web")) t.push({ id: "web", label: "Web" });
    if (has("certificates")) t.push({ id: "certificates", label: "Certificates" });
    if (has("infrastructure")) t.push({ id: "infrastructure", label: "Infrastructure" });
    if (has("attack")) t.push({ id: "attack", label: "ATT&CK" });
    t.push({ id: "graph", label: "Graph", count: inv.relationships.length }, { id: "timeline", label: "Timeline" }, { id: "sources", label: "Sources", count: progress.total });
    return t;
  }, [inv.findings.length, inv.relationships.length, inv.observableType, has, progress.total]);

  const requested = params.get("tab");
  const focusFinding = params.get("finding");
  const [tab, setTab] = useState(() => (focusFinding ? "findings" : requested && tabs.some((t) => t.id === requested) ? requested : "overview"));
  const goTab = useCallback(
    (id: string) => {
      setTab(id);
      const sp = new URLSearchParams(params.toString());
      if (id === "overview") sp.delete("tab");
      else sp.set("tab", id);
      sp.delete("finding");
      router.replace(`${path}${sp.size ? `?${sp}` : ""}`, { scroll: false });
    },
    [params, path, router]
  );

  const ctx = useMemo(
    () => ({ inv, openSource: (id: string, focus?: "raw") => setSource({ id, focus }), openFinding: () => goTab("findings"), goTab }),
    [inv, goTab]
  );

  const addToLibrary = async () => {
    try {
      await api("/api/ioc", { method: "POST", json: { entries: [{ value: inv.normalizedObservable, type: inv.observableType, investigationId: inv.id }], source: "investigation" } });
      toast({ kind: "success", title: "Added to IOC library", body: inv.normalizedObservable });
    } catch (e) {
      toast({ kind: "error", title: "Could not add to the IOC library", body: (e as ApiClientError).message });
    }
  };

  const remove = async () => {
    setDeleting(true);
    try {
      await api(`/api/investigations/${inv.id}`, { method: "DELETE" });
      toast({ kind: "success", title: "Investigation deleted" });
      router.push("/investigations");
    } catch (e) {
      toast({ kind: "error", title: "Delete failed", body: (e as ApiClientError).message });
      setDeleting(false);
      setConfirmDelete(false);
    }
  };

  const previous = history[0];
  const seconds = (elapsed / 1000).toFixed(1);

  return (
    <WorkspaceContext.Provider value={ctx}>
      <div className="grid-canvas grid-fade pointer-events-none absolute inset-x-0 top-0 -z-10 h-[260px]" aria-hidden />
      <nav aria-label="Breadcrumb" className="mb-3 flex items-center gap-1.5 text-xs text-fg-3">
        <Link href="/investigations" className="hover:text-fg-1">
          Investigations
        </Link>
        <ChevronRight size={12} className="text-fg-4" />
        <span>{OBSERVABLE_LABELS[inv.observableType]}</span>
      </nav>

      <header className="mb-4">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-3">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-2">
              <h1 className={cx("mono min-w-0 leading-tight font-medium tracking-tight break-all text-fg-1", inv.normalizedObservable.length > 64 ? "text-[17px] sm:text-[19px]" : "text-[22px] sm:text-[26px]")}>{inv.normalizedObservable}</h1>
              <CopyButton value={inv.normalizedObservable} label="Copy observable" size="md" />
            </div>
            {inv.observable !== inv.normalizedObservable && <div className="mono mt-0.5 truncate text-[11px] text-fg-4">input: {inv.observable}</div>}
            <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-fg-3">
              <TypeTag type={inv.observableType} long />
              <ModeTag mode={inv.mode} />
              <InvestigationStatusBadge status={inv.status} />
              <span>
                Started <Time iso={inv.createdAt} />
              </span>
              <span className="mono tabular text-fg-2" aria-live="off">
                {running ? `${seconds}s` : duration(inv.durationMs)}
              </span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Menu label="Re-run" icon={rerunning ? <Loader2 size={13} className="animate-spin" /> : <RotateCw size={13} />}>
              {(close) => (
                <>
                  <MenuItem icon={<RotateCw size={13} />} hint="Passive sources, bypassing caches" onClick={() => (close(), void start(inv.normalizedObservable, "QUICK", { type: inv.observableType, fresh: true }))}>
                    Quick scan again
                  </MenuItem>
                  <MenuItem icon={<RotateCw size={13} />} hint={session?.operator ? "All sources plus direct probes" : "Requires an operator session"} onClick={() => (close(), void start(inv.normalizedObservable, "DEEP", { type: inv.observableType, fresh: true }))}>
                    Deep investigation
                  </MenuItem>
                </>
              )}
            </Menu>
            <Menu label="Export" icon={<Download size={13} />}>
              {(close) => (
                <>
                  <MenuItem icon={<FileText size={13} />} hint="Readable report, observables defanged" href={`/api/investigations/${inv.id}/export?format=md`} onClick={close}>
                    Markdown report
                  </MenuItem>
                  <MenuItem icon={<Download size={13} />} hint="Findings as rows" href={`/api/investigations/${inv.id}/export?format=csv`} onClick={close}>
                    Findings CSV
                  </MenuItem>
                  <MenuItem icon={<Download size={13} />} hint="Complete normalised record" href={`/api/investigations/${inv.id}/export?format=json`} onClick={close}>
                    JSON
                  </MenuItem>
                  <MenuItem icon={<Printer size={13} />} hint="Print or save as PDF" href={`/investigations/${inv.id}/report`} onClick={close}>
                    Printable report
                  </MenuItem>
                </>
              )}
            </Menu>
            <Menu label="" icon={<MoreHorizontal size={14} />}>
              {(close) => (
                <>
                  <MenuItem icon={<Library size={13} />} hint="Track this indicator" onClick={() => (close(), void addToLibrary())}>
                    Add to IOC library
                  </MenuItem>
                  <MenuItem icon={<Trash2 size={13} />} hint="Removes results, findings and relationships" onClick={() => (close(), setConfirmDelete(true))}>
                    Delete investigation
                  </MenuItem>
                </>
              )}
            </Menu>
          </div>
        </div>

        <div className="mt-4">
          <ProgressStrip steps={progress.steps} />
          <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-fg-3" aria-live="polite">
            <span>
              <span className="mono tabular text-fg-1">{progress.done}</span>/{progress.total} steps finished
            </span>
            {progress.running > 0 && <span className="text-ice">{progress.running} querying</span>}
            <span>
              <span className="mono tabular text-fg-1">{progress.answered}</span>/{progress.sources} sources answered
            </span>
            {progress.failed > 0 && <span className="text-warn">{progress.failed} failed</span>}
            <span className="flex items-center gap-2">
              <span className="mono tabular text-fg-1">{inv.findings.length}</span> findings
              <FindingCounts counts={findings.reduce((c, f) => ({ ...c, [f.severity]: c[f.severity] + 1 }), { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 })} />
            </span>
            <span>
              <span className="mono tabular text-fg-1">{inv.relationships.length}</span> relationships
            </span>
            {previous && (
              <Link href={`/investigations/compare?a=${previous.id}&b=${inv.id}`} className="ml-auto flex items-center gap-1.5 hover:text-fg-1">
                <History size={12} /> Compare with <Time iso={previous.createdAt} /> ({history.length} earlier)
              </Link>
            )}
          </div>
        </div>
        {error && (
          <div className="mt-3">
            <ErrorNote title="Live updates interrupted">Retrying automatically — {error}</ErrorNote>
          </div>
        )}
        {!running && progress.failed > 0 && (
          <div className="mt-3">
            <ErrorNote
              title={progress.answered === 0 ? "No source could answer" : `${progress.failed} of ${progress.sources} sources failed`}
              action={
                <button type="button" className="btn btn-sm shrink-0" onClick={() => void start(inv.normalizedObservable, inv.mode, { type: inv.observableType, fresh: true })}>
                  <RotateCw size={12} /> Re-run
                </button>
              }
            >
              {progress.failedSteps.slice(0, 4).map((s, i) => (
                <span key={s.id}>
                  {i > 0 && "; "}
                  <button type="button" className="link" onClick={() => setSource({ id: s.id })}>
                    {sourceName(s.id)}
                  </button>
                  : {s.outcome?.errorType ?? s.state}
                </span>
              ))}
              {progress.failed > 4 && ` and ${progress.failed - 4} more`}.{" "}
              {progress.answered === 0 ? "Nothing below reflects the observable itself — the absence of findings here means no data, not a clean result." : "Everything below comes from the sources that did answer; the failed ones are simply missing from the picture."}
            </ErrorNote>
          </div>
        )}
      </header>

      <Tabs items={tabs} value={tab} onChange={goTab} label="Investigation sections" className="sticky top-[var(--topbar-h)] z-10 -mx-4 bg-[color-mix(in_srgb,var(--color-ink-0)_92%,transparent)] px-4 backdrop-blur-md sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8" />

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} key={tab} className="animate-fade pt-5">
        {tab === "overview" && (
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
            <div className="flex min-w-0 flex-col gap-4">
              <AssessmentPanel />
              <section className="panel panel-ticks" aria-label="Key findings">
                <header className="flex items-center border-b border-line-1 px-[var(--panel-pad)] py-2.5">
                  <h2 className="label text-fg-2">Key findings</h2>
                  {inv.findings.length > 5 && (
                    <button type="button" className="btn btn-ghost btn-sm ml-auto" onClick={() => goTab("findings")}>
                      All {inv.findings.length} findings <ChevronRight size={12} />
                    </button>
                  )}
                </header>
                {running && !inv.findings.length ? (
                  <div className="flex flex-col gap-2 p-[var(--panel-pad)]" aria-busy="true">
                    <Skeleton className="h-4 w-3/5" />
                    <Skeleton className="h-4 w-2/5" />
                    <p className="text-xs text-fg-4">Findings appear here as sources answer.</p>
                  </div>
                ) : !running && progress.answered === 0 && !inv.findings.length ? (
                  <p className="p-[var(--panel-pad)] text-sm text-fg-3">No findings, because no source answered. Re-run once the failing sources are reachable.</p>
                ) : (
                  <FindingsList findings={findings.filter((f) => f.severity !== "INFO").length ? findings.filter((f) => f.severity !== "INFO") : findings} compact limit={5} />
                )}
              </section>
              <KeyFacts inv={inv} />
            </div>
            <aside className="flex flex-col gap-4">
              <section className="panel panel-ticks" aria-label="Sources">
                <header className="flex items-center border-b border-line-1 px-[var(--panel-pad)] py-2.5">
                  <h2 className="label text-fg-2">Sources</h2>
                  <button type="button" className="btn btn-ghost btn-sm ml-auto" onClick={() => goTab("sources")}>
                    Details <ChevronRight size={12} />
                  </button>
                </header>
                <CompactSources inv={inv} />
              </section>
              {history.length > 0 && (
                <section className="panel" aria-label="Earlier investigations">
                  <header className="border-b border-line-1 px-[var(--panel-pad)] py-2.5">
                    <h2 className="label text-fg-2">Earlier investigations</h2>
                  </header>
                  <ul className="divide-y divide-line-1">
                    {history.slice(0, 6).map((h) => (
                      <li key={h.id} className="flex items-center gap-2 px-[var(--panel-pad)] py-2 text-xs">
                        <Link href={`/investigations/${h.id}`} className="min-w-0 flex-1 hover:underline">
                          <Time iso={h.createdAt} />
                        </Link>
                        <ModeTag mode={h.mode} />
                        <FindingCounts counts={h.findingCounts} />
                        <Link href={`/investigations/compare?a=${h.id}&b=${inv.id}`} className="text-fg-3 hover:text-fg-1">
                          Diff
                        </Link>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </aside>
          </div>
        )}
        {tab === "findings" && (
          <section className="panel panel-ticks">
            <FindingsList findings={inv.findings} focusId={focusFinding} />
          </section>
        )}
        {tab === "vulnerability" && <VulnerabilitySection />}
        {tab === "intel" && <ThreatIntelSection />}
        {tab === "dns" && <DnsSection />}
        {tab === "email" && <EmailSection />}
        {tab === "web" && <WebSection />}
        {tab === "certificates" && <CertificatesSection />}
        {tab === "infrastructure" && <InfrastructureSection />}
        {tab === "attack" && <AttackSection />}
        {tab === "graph" && (
          <section className="panel panel-ticks overflow-hidden">
            {inv.relationships.length ? (
              <EvidenceGraph inv={inv} />
            ) : (
              <div className="p-10 text-center text-sm text-fg-3">{running ? "Relationships appear here as sources report them." : "No source reported relationships for this observable."}</div>
            )}
          </section>
        )}
        {tab === "timeline" && <TimelineSection />}
        {tab === "sources" && (
          <section className="panel panel-ticks">
            <SourcesTable steps={progress.steps} />
          </section>
        )}
      </div>

      <SourceDrawer provider={source?.id ?? null} focus={source?.focus} onClose={() => setSource(null)} />
      <Dialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title="Delete this investigation?"
        footer={
          <>
            <button type="button" className="btn" onClick={() => setConfirmDelete(false)}>
              Cancel
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void remove()} disabled={deleting}>
              {deleting ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />} Delete
            </button>
          </>
        }
      >
        Results, findings and relationships for <span className="mono text-fg-1">{inv.normalizedObservable}</span> will be removed permanently. {!session?.operator && "This requires an operator session."}
      </Dialog>
    </WorkspaceContext.Provider>
  );
}
