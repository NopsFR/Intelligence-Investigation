"use client";

import Link from "next/link";
import { useMemo } from "react";
import { SEVERITY_RANK, type Severity } from "@/lib/core/types";
import { useCatalog } from "@/lib/client/catalog";
import { cx } from "@/lib/client/cx";
import { dateOnly } from "@/lib/client/format";
import { usePrefs } from "@/lib/client/prefs";
import { Prov, SEVERITY_COLOR, SeverityBadge } from "@/components/ui/badges";
import { EmptyState } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";
import { useWorkspace } from "../context";
import { SectionIntro, SourceBlock, useData, useOutcome } from "./common";

// ─────────────────────────────── vulnerability

interface CvssBlock {
  baseScore: number;
  baseSeverity?: string;
  vectorString?: string;
  version?: string;
}
interface CveRecord {
  kind: "cve-record";
  id: string;
  state: string;
  title?: string;
  description?: string;
  products?: { vendor?: string; product: string; affected: string[]; fixed: string[] }[];
  cwes?: string[];
  cnaCvss?: CvssBlock;
  adpCvss?: CvssBlock;
  ssvc?: Record<string, string>;
  solutions?: string[];
  workarounds?: string[];
}
interface Assessment {
  kind: "assessment";
  highest: Severity | null;
  adverse: { provider: string; name: string; vendor: string; severity: Severity; rules: string[]; titles: string[] }[];
  benign: { provider: string; name: string; titles: string[] }[];
  silent: string[];
  coverage: { planned: number; answered: number; failed: number; notConfigured: number; skipped: number };
  cvss?: { chosen?: { score: number; severity: string; vector?: string; version: string; source: string }; all: { score: number; source: string; vector?: string; version: string }[] };
}
interface KevData {
  kind: "kev";
  listed: boolean;
  entry?: { vendorProject?: string; product?: string; vulnerabilityName?: string; dateAdded?: string; requiredAction?: string; dueDate?: string; knownRansomwareCampaignUse?: string; shortDescription?: string };
}
interface EpssData {
  kind: "epss";
  probability: number;
  percentile: number;
  date?: string;
}

const CVSS_V3: Record<string, [string, Record<string, string>]> = {
  AV: ["Attack vector", { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }],
  AC: ["Complexity", { L: "Low", H: "High" }],
  PR: ["Privileges", { N: "None", L: "Low", H: "High" }],
  UI: ["User interaction", { N: "None", R: "Required", P: "Passive", A: "Active" }],
  S: ["Scope", { U: "Unchanged", C: "Changed" }],
  C: ["Confidentiality", { N: "None", L: "Low", H: "High" }],
  I: ["Integrity", { N: "None", L: "Low", H: "High" }],
  A: ["Availability", { N: "None", L: "Low", H: "High" }],
  AT: ["Attack requirements", { N: "None", P: "Present" }],
  VC: ["Confidentiality", { N: "None", L: "Low", H: "High" }],
  VI: ["Integrity", { N: "None", L: "Low", H: "High" }],
  VA: ["Availability", { N: "None", L: "Low", H: "High" }],
};

function severityOf(score: number): Severity {
  return score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : score > 0 ? "LOW" : "INFO";
}

/** CVSS score on a 0–10 rail with the metric breakdown underneath. */
function CvssPanel({ score, vector, source, version }: { score: number; vector?: string; source: string; version: string }) {
  const sev = severityOf(score);
  const metrics = (vector ?? "")
    .split("/")
    .slice(vector?.startsWith("CVSS:") ? 1 : 0)
    .map((p) => p.split(":"))
    .filter(([k]) => CVSS_V3[k])
    .map(([k, v]) => ({ key: k, label: CVSS_V3[k][0], value: CVSS_V3[k][1][v] ?? v, worst: ["N", "H", "C"].includes(v) && !["AC"].includes(k) ? (k === "PR" || k === "UI" || k === "AT" ? v === "N" : v !== "N") : false }));
  return (
    <div className="panel panel-ticks p-[var(--panel-pad)]">
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
        <div>
          <div className="label mb-1">CVSS {version.startsWith("4") ? "4.0" : version}</div>
          <div className="flex items-baseline gap-2">
            <span className="display tabular text-3xl" style={{ color: SEVERITY_COLOR[sev] }}>
              {score.toFixed(1)}
            </span>
            <SeverityBadge severity={sev} />
          </div>
        </div>
        <div className="min-w-[200px] flex-1">
          <div className="relative h-[6px] rounded-[1px]" style={{ background: "linear-gradient(90deg, var(--color-sev-low) 0 40%, var(--color-sev-medium) 40% 70%, var(--color-sev-high) 70% 90%, var(--color-sev-critical) 90%)", opacity: 0.35 }} />
          <div className="relative -mt-[6px] h-[6px]">
            <span className="absolute -top-[4px] h-[14px] w-[2px] bg-fg-1 transition-[left] duration-700" style={{ left: `calc(${score * 10}% - 1px)` }} />
          </div>
          <div className="mono mt-1.5 flex justify-between text-[10px] text-fg-4">
            <span>0</span>
            <span>4</span>
            <span>7</span>
            <span>9</span>
            <span>10</span>
          </div>
        </div>
        <div className="text-xs text-fg-3">Scored by {source}</div>
      </div>
      {metrics.length > 0 && (
        <dl className="mt-4 grid grid-cols-2 gap-px overflow-hidden rounded-[2px] bg-line-1 sm:grid-cols-4">
          {metrics.map((m) => (
            <div key={m.key} className="bg-ink-0 px-3 py-2">
              <dt className="text-[10.5px] text-fg-4">{m.label}</dt>
              <dd className={cx("text-sm", m.worst ? "text-fg-1" : "text-fg-3")}>{m.value}</dd>
            </div>
          ))}
        </dl>
      )}
      {vector && <code className="mono mt-3 block text-[11px] break-all text-fg-4">{vector}</code>}
    </div>
  );
}

export function VulnerabilitySection() {
  const record = useData<CveRecord>("cve-org", "cve-record");
  const assessment = useData<Assessment>("correlation", "assessment");
  const kev = useData<KevData>("cisa-kev", "kev");
  const epss = useData<EpssData>("epss", "epss");
  const { prefs } = usePrefs();
  const chosen = assessment?.cvss?.chosen;
  return (
    <div className="flex flex-col gap-4">
      {record?.title || record?.description ? (
        <div className="panel panel-ticks p-[var(--panel-pad)]">
          <div className="label mb-1.5 flex items-center gap-2">
            <Prov id="cve-org" /> {record.id} · {record.state}
          </div>
          {record.title && <h2 className="mb-2 text-lg font-semibold text-fg-1">{record.title}</h2>}
          {record.description && <p className="max-w-4xl text-sm leading-relaxed text-fg-2">{record.description}</p>}
          {!!record.cwes?.length && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {record.cwes.map((c) => (
                <span key={c} className="mono rounded-[2px] bg-ink-2 px-1.5 py-0.5 text-[11px] text-fg-2">
                  {c}
                </span>
              ))}
            </div>
          )}
        </div>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        {chosen ? <CvssPanel score={chosen.score} vector={chosen.vector} source={chosen.source} version={chosen.version} /> : <div className="panel p-[var(--panel-pad)] text-sm text-fg-3">No CVSS score has been published by NVD, the CNA or CISA ADP yet.</div>}
        <div className="grid gap-4">
          <div className="panel panel-ticks p-[var(--panel-pad)]">
            <div className="label mb-2 flex items-center gap-2">
              <Prov id="cisa-kev" /> Known exploited
            </div>
            {kev ? (
              kev.listed && kev.entry ? (
                <div className="flex flex-col gap-2 text-sm">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity="CRITICAL" compact />
                    <span className="font-semibold text-fg-1">Listed in CISA KEV since {dateOnly(kev.entry.dateAdded, prefs.tz)}</span>
                  </div>
                  <p className="text-xs text-fg-2">{kev.entry.requiredAction}</p>
                  <div className="mono flex flex-wrap gap-x-4 text-[11px] text-fg-3">
                    {kev.entry.dueDate && <span>Federal due date {kev.entry.dueDate}</span>}
                    {kev.entry.knownRansomwareCampaignUse && <span className={kev.entry.knownRansomwareCampaignUse === "Known" ? "text-err" : undefined}>Ransomware use: {kev.entry.knownRansomwareCampaignUse}</span>}
                  </div>
                </div>
              ) : (
                <p className="text-sm text-fg-2">Not in the CISA KEV catalog — no confirmed in-the-wild exploitation recorded by CISA.</p>
              )
            ) : (
              <p className="text-sm text-fg-4">KEV catalog not available for this investigation.</p>
            )}
          </div>
          <div className="panel panel-ticks p-[var(--panel-pad)]">
            <div className="label mb-2 flex items-center gap-2">
              <Prov id="epss" /> Exploit prediction (EPSS)
            </div>
            {epss ? (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="display tabular text-2xl text-fg-1">{(epss.probability * 100).toFixed(epss.probability < 0.01 ? 2 : 1)}%</div>
                  <div className="text-xs text-fg-3">probability of exploitation in 30 days</div>
                </div>
                <div>
                  <div className="display tabular text-2xl text-fg-1">{(epss.percentile * 100).toFixed(1)}</div>
                  <div className="text-xs text-fg-3">percentile of all scored CVEs{epss.date ? ` · ${epss.date}` : ""}</div>
                  <div className="mt-2 h-[4px] rounded-[1px] bg-ink-3">
                    <div className="h-full rounded-[1px] bg-fg-2 transition-[width] duration-700" style={{ width: `${epss.percentile * 100}%` }} />
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-sm text-fg-4">No EPSS score available.</p>
            )}
          </div>
        </div>
      </div>

      {!!record?.products?.length && (
        <div className="panel panel-ticks">
          <div className="border-b border-line-1 px-[var(--panel-pad)] py-2.5">
            <span className="label text-fg-2">Affected products</span> <span className="text-xs text-fg-4">as declared by the CNA</span>
          </div>
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Affected</th>
                  <th>Fixed in</th>
                </tr>
              </thead>
              <tbody>
                {record.products.slice(0, 40).map((p, i) => (
                  <tr key={`${p.product}-${i}`}>
                    <td className="text-sm text-fg-1">
                      {p.vendor && <span className="text-fg-3">{p.vendor} </span>}
                      {p.product}
                    </td>
                    <td className="mono text-[11.5px] text-fg-2">{p.affected.join("; ") || "—"}</td>
                    <td className="mono text-[11.5px] text-ok">{p.fixed.join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(record?.solutions?.length || record?.workarounds?.length) && (
        <div className="panel panel-ticks p-[var(--panel-pad)]">
          {!!record?.solutions?.length && (
            <>
              <div className="label mb-1.5">Vendor solution</div>
              {record.solutions.map((s, i) => (
                <p key={i} className="mb-2 text-sm text-fg-2">
                  {s}
                </p>
              ))}
            </>
          )}
          {!!record?.workarounds?.length && (
            <>
              <div className="label mb-1.5">Workarounds</div>
              {record.workarounds.map((s, i) => (
                <p key={i} className="mb-2 text-sm text-fg-2">
                  {s}
                </p>
              ))}
            </>
          )}
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <SourceBlock provider="nvd" />
        <SourceBlock provider="cve-org" />
      </div>
    </div>
  );
}

// ─────────────────────────────── threat intelligence

interface OtxData {
  kind: "otx";
  gui?: string;
  validation?: { source?: string; message?: string; name?: string }[];
  pulses: { id: string; name: string; created?: string; modified?: string; tags: string[]; adversary?: string; families: string[]; techniques: string[]; tlp?: string; author?: string }[];
}

function OtxPulses() {
  const d = useData<OtxData>("otx", "otx");
  if (!d?.pulses.length) return null;
  return (
    <ul className="divide-y divide-line-1 rounded-[2px] border border-line-1">
      {d.pulses.slice(0, 12).map((p) => (
        <li key={p.id} className="px-3 py-2.5">
          <div className="flex items-start gap-3">
            <a href={`https://otx.alienvault.com/pulse/${p.id}`} target="_blank" rel="noopener noreferrer nofollow" className="link min-w-0 flex-1 text-sm">
              {p.name}
            </a>
            <Time iso={p.modified ?? p.created} className="shrink-0 text-xs text-fg-4" />
          </div>
          <div className="mt-1 flex flex-wrap gap-1.5 text-[11px]">
            {p.author && <span className="text-fg-3">by {p.author}</span>}
            {p.tlp && <span className="mono uppercase text-fg-4">TLP:{p.tlp}</span>}
            {p.adversary && <span className="text-fg-2">adversary {p.adversary}</span>}
            {p.families.slice(0, 4).map((f) => (
              <span key={f} className="rounded-[2px] bg-ink-3 px-1.5 text-fg-1">
                {f}
              </span>
            ))}
            {p.techniques.slice(0, 5).map((t) => (
              <Link key={t} href={`/attack/${t}`} className="mono rounded-[2px] px-1.5 text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-2)] hover:text-fg-1">
                {t}
              </Link>
            ))}
          </div>
        </li>
      ))}
    </ul>
  );
}

const INTEL_ORDER = ["virustotal", "abuseipdb", "greynoise", "otx", "threatfox", "urlhaus", "malwarebazaar", "yaraify", "circl-hashlookup", "feodo", "internetdb", "kev-exposure"];

export function ThreatIntelSection() {
  const { inv } = useWorkspace();
  const present = INTEL_ORDER.filter((id) => inv.plan.some((s) => s.id === id) || inv.providerResults.some((o) => o.provider === id));
  const outcomes = new Map(inv.providerResults.map((o) => [o.provider, o]));
  // Sources with something to say first; unconfigured and empty ones collapse to a compact list.
  const answeredWithData = present.filter((id) => !outcomes.get(id) || ["SUCCESS", "PARTIAL"].includes(outcomes.get(id)!.status));
  const quiet = present.filter((id) => !answeredWithData.includes(id));
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 xl:grid-cols-2">
        {answeredWithData.map((id) =>
          id === "otx" ? (
            <SourceBlock key={id} provider="otx" className="xl:col-span-2">
              <OtxPulses />
            </SourceBlock>
          ) : (
            <SourceBlock key={id} provider={id} />
          )
        )}
      </div>
      {quiet.length > 0 && <QuietSources ids={quiet} />}
    </div>
  );
}

/** Compact list for sources that answered with nothing, were skipped or are not configured. */
export function QuietSources({ ids }: { ids: string[] }) {
  const { inv, openSource } = useWorkspace();
  const { name } = useCatalog();
  return (
    <div className="panel">
      <div className="border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <SectionIntro title="Other sources">No data, not applicable, not configured or failed</SectionIntro>
      </div>
      <ul className="divide-y divide-line-1">
        {ids.map((id) => {
          const o = inv.providerResults.find((r) => r.provider === id);
          return (
            <li key={id}>
              <button type="button" onClick={() => o && openSource(id)} className="grid w-full grid-cols-[48px_170px_minmax(0,1fr)] items-center gap-3 px-[var(--panel-pad)] py-2 text-left hover:bg-ink-2">
                <Prov id={id} className="justify-center" />
                <span className="truncate text-sm text-fg-1">{name(id)}</span>
                <span className="truncate text-xs text-fg-3">{o?.result?.summary ?? o?.errorMessage ?? "Pending"}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function InfrastructureSection() {
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <SourceBlock provider="address-context" />
      <SourceBlock provider="hosting" className="xl:col-span-2" />
      <SourceBlock provider="rdap" />
      <SourceBlock provider="ripestat" />
    </div>
  );
}

// ─────────────────────────────── ATT&CK

interface AttackData {
  kind: "attack-mapping";
  version: string;
  software: { id: string; name: string; kind: string; families: string[]; providers: string[]; techniqueCount: number; groups: { id: string; name: string }[] }[];
  techniques: { id: string; name: string; tactics: string[]; via: string[] }[];
  byTactic?: Record<string, number>;
  unmatched: string[];
}

const TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "stealth", "defense-impairment", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"];

export function AttackSection() {
  const d = useData<AttackData>("attack", "attack-mapping");
  const { outcome } = useOutcome("attack");
  const columns = useMemo(() => {
    if (!d) return [];
    const byTactic = new Map<string, AttackData["techniques"]>();
    for (const t of d.techniques) for (const tac of t.tactics) byTactic.set(tac, [...(byTactic.get(tac) ?? []), t]);
    return [...byTactic.entries()].sort((a, b) => TACTIC_ORDER.indexOf(a[0]) - TACTIC_ORDER.indexOf(b[0]));
  }, [d]);

  if (!d || (!d.software.length && !d.techniques.length)) {
    return (
      <div className="panel">
        <EmptyState title="No ATT&CK context">{outcome?.result?.summary ?? outcome?.errorMessage ?? "No source named a malware family or technique for this observable."}</EmptyState>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-4">
      {d.software.length > 0 && (
        <div className="grid gap-3 md:grid-cols-2">
          {d.software.map((s) => (
            <div key={s.id} className="panel panel-ticks p-[var(--panel-pad)]">
              <div className="mb-1 flex items-baseline gap-2">
                <Link href={`/attack/${s.id}`} className="text-base font-semibold text-fg-1 hover:underline">
                  {s.name}
                </Link>
                <span className="mono text-[11px] text-fg-3">
                  {s.id} · {s.kind}
                </span>
              </div>
              <p className="text-xs text-fg-3">
                Matched from {s.families.map((f) => `“${f}”`).join(", ")} reported by{" "}
                {s.providers.map((p) => (
                  <Prov key={p} id={p} className="mx-0.5" />
                ))}
                · {s.techniqueCount} documented techniques
              </p>
              {s.groups.length > 0 && (
                <p className="mt-2 text-xs text-fg-2">
                  <span className="text-fg-4">Documented users (context, not attribution): </span>
                  {s.groups.slice(0, 8).map((g, i) => (
                    <span key={g.id}>
                      {i > 0 && ", "}
                      <Link href={`/attack/${g.id}`} className="link">
                        {g.name}
                      </Link>
                    </span>
                  ))}
                  {s.groups.length > 8 && ` +${s.groups.length - 8}`}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
      <div className="panel panel-ticks">
        <div className="flex flex-wrap items-baseline gap-3 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
          <span className="label text-fg-2">Techniques by tactic</span>
          <span className="text-xs text-fg-4">
            {d.techniques.length} techniques · ATT&CK Enterprise {d.version}
          </span>
        </div>
        <div className="flex gap-px overflow-x-auto bg-line-1">
          {columns.map(([tactic, techniques]) => (
            <div key={tactic} className="w-[190px] shrink-0 bg-ink-1">
              <div className="label border-b border-line-1 px-2.5 py-2 text-fg-2">
                {tactic.replace(/-/g, " ")} <span className="mono text-fg-4">{techniques.length}</span>
              </div>
              <ul className="flex flex-col gap-px p-1.5">
                {techniques.map((t) => (
                  <li key={t.id}>
                    <Link href={`/attack/${t.id}`} className="block rounded-[2px] px-2 py-1.5 transition-colors hover:bg-ink-3" title={`Via ${t.via.join(", ")}`}>
                      <span className="mono block text-[10.5px] text-fg-4">{t.id}</span>
                      <span className="block text-xs leading-snug text-fg-1">{t.name}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
      {d.unmatched.length > 0 && <p className="text-xs text-fg-4">No ATT&CK entry for: {d.unmatched.join(", ")}</p>}
      <p className="text-2xs text-fg-4">MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Content © The MITRE Corporation, used under the ATT&CK Terms of Use.</p>
    </div>
  );
}

// ─────────────────────────────── assessment + timeline

export function AssessmentPanel() {
  const d = useData<Assessment>("correlation", "assessment");
  const { outcome, planned } = useOutcome("correlation");
  if (!planned) return null;
  if (!d) {
    return (
      <div className="panel panel-ticks p-[var(--panel-pad)]">
        <div className="label mb-2">Assessment</div>
        <p className="text-sm text-fg-3">{outcome ? outcome.errorMessage ?? outcome.result?.summary : "Waiting for sources to finish — the assessment is computed from all of them."}</p>
      </div>
    );
  }
  const tone = d.adverse.length ? SEVERITY_COLOR[d.highest ?? "MEDIUM"] : "var(--color-fg-2)";
  return (
    <div className="panel panel-ticks relative overflow-hidden p-[var(--panel-pad)]">
      <span aria-hidden className="absolute inset-y-0 left-0 w-[3px]" style={{ background: tone }} />
      <div className="label mb-1.5 flex items-center gap-2">
        <Prov id="correlation" /> Assessment
      </div>
      <p className="text-lg font-semibold text-fg-1">{outcome?.result?.summary}</p>
      <div className="mt-3 grid gap-4 text-xs sm:grid-cols-3">
        <div>
          <div className="mb-1 text-fg-4">Adverse records</div>
          {d.adverse.length ? (
            <ul className="flex flex-col gap-1">
              {[...d.adverse].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]).map((a) => (
                <li key={a.provider} className="flex items-center gap-2">
                  <span aria-hidden className="h-[6px] w-[6px] rotate-45" style={{ background: SEVERITY_COLOR[a.severity] }} />
                  <span className="text-fg-1">{a.name}</span>
                </li>
              ))}
            </ul>
          ) : (
            <span className="text-fg-2">None</span>
          )}
        </div>
        <div>
          <div className="mb-1 text-fg-4">Indicates benign</div>
          {d.benign.length ? d.benign.map((b) => <div key={b.provider} className="text-fg-1">{b.name}</div>) : <span className="text-fg-2">None</span>}
        </div>
        <div>
          <div className="mb-1 text-fg-4">Coverage</div>
          <div className="text-fg-1">
            {d.coverage.answered} answered · {d.coverage.failed} failed
          </div>
          <div className="text-fg-3">
            {d.coverage.notConfigured} not configured · {d.coverage.skipped} not applicable
          </div>
        </div>
      </div>
    </div>
  );
}

export function TimelineSection() {
  const { inv } = useWorkspace();
  const { prefs } = usePrefs();
  const events = useMemo(() => {
    const list = inv.providerResults.flatMap((o) => (o.result?.timeline ?? []).map((e) => ({ ...e, provider: o.provider })));
    list.push({ at: inv.createdAt, label: "Investigation started", provider: "", detail: inv.mode === "DEEP" ? "Deep investigation" : "Quick scan" });
    if (inv.completedAt) list.push({ at: inv.completedAt, label: "Investigation completed", provider: "", detail: inv.status });
    return list.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
  }, [inv]);
  if (events.length <= 2) {
    return (
      <div className="panel">
        <EmptyState title="No dated events from sources">Registration, certificate, first-seen and publication dates appear here when sources provide them.</EmptyState>
      </div>
    );
  }
  return (
    <div className="panel panel-ticks p-[var(--panel-pad)]">
      <ol className="relative">
        {events.map((e, i) => {
          const year = e.at.slice(0, 4);
          const showYear = i === 0 || events[i - 1].at.slice(0, 4) !== year;
          const own = !e.provider;
          return (
            <li key={`${e.at}-${i}`} className="grid grid-cols-[64px_18px_minmax(0,1fr)] gap-3">
              <div className="mono pt-2.5 text-right text-[11px] text-fg-3">{showYear ? year : ""}</div>
              <div className="relative flex justify-center">
                <span className="absolute inset-y-0 w-px bg-line-2" aria-hidden />
                <span aria-hidden className={cx("relative mt-3.5 h-[7px] w-[7px] rotate-45", own ? "bg-signal" : "border border-fg-3 bg-ink-1")} />
              </div>
              <div className="border-b border-line-1 py-2.5">
                <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                  <span className="mono tabular text-[11.5px] text-fg-2">{dateOnly(e.at, prefs.tz)}</span>
                  <span className="text-sm text-fg-1">{e.label}</span>
                  {e.provider && <Prov id={e.provider} />}
                </div>
                {e.detail && <div className="mt-0.5 text-xs text-fg-3">{e.detail}</div>}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

