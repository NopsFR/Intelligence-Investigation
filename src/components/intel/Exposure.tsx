"use client";

import { AlertTriangle, ArrowRight, Clock, Database, Eye, EyeOff, FileSearch, KeyRound, Mail, Search, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api, ApiClientError } from "@/lib/client/api";
import { registrableDomain } from "@/lib/observables/detect";
import { useInvestigate } from "@/lib/client/investigate";
import { ErrorNote, Panel } from "@/components/ui/primitives";
import { Chip, Mono } from "../analysis/common";
import { Time } from "../ui/Time";

interface DomainBreach {
  name: string;
  title: string;
  breachDate?: string;
  addedDate?: string;
  pwnCount?: number;
  dataClasses?: string[];
  verified?: boolean;
  sensitive?: boolean;
  retired?: boolean;
  description?: string;
}
interface DomainResult {
  domain: string;
  status: "confirmed-exposure" | "no-result";
  note?: string;
  fetchedAt: string;
  source: string;
  breaches: DomainBreach[];
}

async function sha1Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function Exposure() {
  return (
    <div className="flex flex-col gap-4">
      <EmailExposure />
      <DomainExposure />
      <PasswordExposure />
    </div>
  );
}

// ---------------------------------------------------------------- Email investigation

interface EmailExposureResult {
  email: string;
  domain: string;
  exposureOverview: {
    status: "confirmed-exposure" | "no-result" | "not-configured" | "rate-limited" | "provider-unavailable";
    breachCount: number;
    earliestBreach?: string;
    latestBreach?: string;
    dataClasses: string[];
    stealerLogCount: number;
    passwordExposed: boolean;
  };
  breaches: {
    name: string;
    title: string;
    domain?: string;
    breachDate?: string;
    addedDate?: string;
    pwnCount?: number;
    dataClasses: string[];
    verified?: boolean;
    sensitive?: boolean;
    retired?: boolean;
    stealerLog?: boolean;
    description?: string;
  }[];
  credentialExposure: { status: string; passwordExposed: boolean; stealerLogCount: number; pasteExposure: { status: string; note: string } };
  emailIntelligence: { domain: string; disposable: boolean; disposableListSize: number; provider: string };
  domainExposure: { status: string; breachCount: number; note: string };
  timeline: { date?: string; label: string; kind: string; stealerLog: boolean }[];
  evidence: { source: string; status: string; retrievedAt: string; configured?: boolean }[];
  methodology: string;
}

const STATUS_CHIP: Record<string, { tone: "err" | "ok" | "warn" | "neutral"; label: string }> = {
  "confirmed-exposure": { tone: "err", label: "Confirmed exposure" },
  "no-result": { tone: "ok", label: "No result" },
  "not-configured": { tone: "neutral", label: "Not configured" },
  "rate-limited": { tone: "warn", label: "Rate limited" },
  "provider-unavailable": { tone: "warn", label: "Provider unavailable" },
  unsupported: { tone: "neutral", label: "Unsupported" },
};

function StatusChip({ status }: { status: string }) {
  const s = STATUS_CHIP[status] ?? { tone: "neutral" as const, label: status };
  return <Chip tone={s.tone}>{s.label}</Chip>;
}

function EmailExposure() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<{ phase: "idle" } | { phase: "loading" } | { phase: "done"; result: EmailExposureResult } | { phase: "error"; message: string }>({ phase: "idle" });
  const { start, pending } = useInvestigate();

  const run = async (raw: string) => {
    const value = raw.trim();
    if (!value) return;
    setState({ phase: "loading" });
    try {
      const result = await api<EmailExposureResult>(`/api/intel/exposure/email?email=${encodeURIComponent(value)}`);
      setState({ phase: "done", result });
    } catch (err) {
      setState({ phase: "error", message: (err as ApiClientError).message });
    }
  };

  return (
    <section className="panel panel-ticks">
      <header className="flex items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <Mail size={14} className="text-fg-3" />
        <h2 className="label text-fg-2">Email exposure investigation</h2>
      </header>
      <div className="p-[var(--panel-pad)]">
        <p className="mb-3 max-w-2xl text-sm text-fg-3">
          Treats an email address as an observable — breach history, exposed data categories, and domain mail-security context — sourced from authenticated provider APIs. This is exposure intelligence, not a people-search: no address, phone number, or personal record is looked up.
        </p>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(email);
          }}
        >
          <input className="input h-9 max-w-sm flex-1" placeholder="someone@example.com" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="Email address to investigate" />
          <button type="submit" className="btn btn-primary" disabled={state.phase === "loading"}>
            <Search size={14} /> Investigate
          </button>
        </form>

        {state.phase === "error" && (
          <div className="mt-3">
            <ErrorNote title="Could not complete the investigation">{state.message}</ErrorNote>
          </div>
        )}

        {state.phase === "done" && (
          <div className="mt-4 flex flex-col gap-4">
            {/* Exposure Overview */}
            <Panel title="Exposure overview" meta={<StatusChip status={state.result.exposureOverview.status} />} bodyClassName="p-0">
              <div className="grid grid-cols-2 gap-x-6 gap-y-3 p-[var(--panel-pad)] sm:grid-cols-4">
                <Stat label="Known breaches" value={state.result.exposureOverview.breachCount} />
                <Stat label="Earliest exposure" value={state.result.exposureOverview.earliestBreach ?? "—"} />
                <Stat label="Latest exposure" value={state.result.exposureOverview.latestBreach ?? "—"} />
                <Stat label="Stealer-log hits" value={state.result.exposureOverview.stealerLogCount} />
              </div>
              {state.result.exposureOverview.dataClasses.length > 0 && (
                <div className="flex flex-wrap gap-1 border-t border-line-1 px-[var(--panel-pad)] py-2.5">
                  {state.result.exposureOverview.dataClasses.map((c) => (
                    <Chip key={c} tone={c.toLowerCase().includes("password") ? "err" : "neutral"}>
                      {c}
                    </Chip>
                  ))}
                </div>
              )}
              {state.result.exposureOverview.status === "not-configured" && <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-3">HIBP_API_KEY is not configured — per-account breach lookups are unavailable. The domain-wide catalogue check below still runs (keyless).</p>}
            </Panel>

            {/* Breaches */}
            {state.result.breaches.length > 0 && (
              <Panel title="Breaches" meta={`${state.result.breaches.length}`} bodyClassName="p-0">
                <ul className="flex flex-col divide-y divide-line-1">
                  {state.result.breaches.map((b) => (
                    <li key={b.name} className="px-[var(--panel-pad)] py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-fg-1">{b.title}</span>
                        {b.verified === false && <Chip tone="warn">unverified</Chip>}
                        {b.sensitive && <Chip tone="warn">sensitive</Chip>}
                        {b.retired && <Chip>retired</Chip>}
                        {b.stealerLog && <Chip tone="err">stealer log</Chip>}
                        {b.breachDate && <Mono className="text-xs text-fg-4">{b.breachDate}</Mono>}
                        {b.pwnCount !== undefined && <span className="text-xs text-fg-4">{b.pwnCount.toLocaleString()} accounts</span>}
                      </div>
                      {b.description && <p className="mt-1 max-w-2xl text-xs text-fg-3" dangerouslySetInnerHTML={{ __html: b.description.replace(/<a /g, '<a rel="noopener noreferrer nofollow" target="_blank" ') }} />}
                      {b.dataClasses.length > 0 && (
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {b.dataClasses.map((c) => (
                            <Chip key={c} tone={c.toLowerCase().includes("password") ? "err" : "neutral"}>
                              {c}
                            </Chip>
                          ))}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </Panel>
            )}

            {/* Credential exposure */}
            <Panel title="Credential exposure" bodyClassName="p-0">
              <div className="flex flex-col gap-2 p-[var(--panel-pad)] text-sm">
                <div className="flex items-center gap-2">
                  {state.result.credentialExposure.passwordExposed ? <ShieldAlert size={14} className="text-err" /> : <ShieldCheck size={14} className="text-ok" />}
                  <span className="text-fg-2">{state.result.credentialExposure.passwordExposed ? "A password data class appears in at least one breach" : "No password data class found in known breaches"}</span>
                </div>
                <div className="flex items-center gap-2">
                  <AlertTriangle size={14} className={state.result.credentialExposure.stealerLogCount > 0 ? "text-err" : "text-fg-4"} />
                  <span className="text-fg-2">{state.result.credentialExposure.stealerLogCount > 0 ? `${state.result.credentialExposure.stealerLogCount} stealer-log-sourced breach record(s)` : "No stealer-log indicators"}</span>
                </div>
                <div className="flex items-center gap-2">
                  <StatusChip status={state.result.credentialExposure.pasteExposure.status} />
                  <span className="text-xs text-fg-4">{state.result.credentialExposure.pasteExposure.note}</span>
                </div>
                <p className="mt-1 text-xs text-fg-4">Actual passwords, hashes, or other secrets are never fetched, stored, or displayed — only whether a breach&apos;s disclosed data-class list includes password-related fields.</p>
              </div>
            </Panel>

            {/* Email intelligence */}
            <Panel title="Email intelligence" bodyClassName="p-0">
              <div className="grid grid-cols-2 gap-x-6 gap-y-3 p-[var(--panel-pad)] sm:grid-cols-3">
                <Stat label="Domain" value={state.result.emailIntelligence.domain} mono />
                <Stat label="Disposable provider" value={state.result.emailIntelligence.disposable ? "Yes" : "Not in curated list"} />
                <Stat label="Breach data provider" value={state.result.emailIntelligence.provider} />
              </div>
              <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-4">Disposable-domain detection uses a curated static list of {state.result.emailIntelligence.disposableListSize} known providers — a &quot;no&quot; result means not in this list, not confirmed non-disposable.</p>
            </Panel>

            {/* Domain-wide exposure + full investigation handoff */}
            <Panel title="Domain exposure & threat intelligence" meta={<StatusChip status={state.result.domainExposure.status} />} bodyClassName="p-0">
              <div className="flex flex-col gap-2 p-[var(--panel-pad)] text-sm text-fg-2">
                <p className="text-xs text-fg-4">{state.result.domainExposure.note}</p>
                <p>{state.result.domainExposure.breachCount} domain-wide breach{state.result.domainExposure.breachCount === 1 ? "" : "es"} attributed to {state.result.domain}.</p>
              </div>
              <div className="flex flex-wrap gap-2 border-t border-line-1 px-[var(--panel-pad)] py-2.5">
                <button type="button" className="btn btn-ghost btn-sm" disabled={pending} onClick={() => void start(state.result.domain, "QUICK", { type: "DOMAIN" })}>
                  <FileSearch size={13} /> RDAP, DNS, SPF/DKIM/DMARC, certificates, threat intel for {state.result.domain} <ArrowRight size={12} />
                </button>
              </div>
            </Panel>

            {/* Timeline */}
            {state.result.timeline.length > 0 && (
              <Panel title="Timeline" meta={<Clock size={13} className="text-fg-4" />} bodyClassName="p-0">
                <ol className="flex flex-col divide-y divide-line-1">
                  {state.result.timeline.map((e, i) => (
                    <li key={i} className="flex items-center gap-3 px-[var(--panel-pad)] py-2 text-sm">
                      <Mono className="w-24 shrink-0 text-xs text-fg-4">{e.date}</Mono>
                      <span className="text-fg-2">{e.label}</span>
                      {e.stealerLog && <Chip tone="err">stealer log</Chip>}
                    </li>
                  ))}
                </ol>
              </Panel>
            )}

            {/* Evidence */}
            <Panel title="Evidence" meta={<Database size={13} className="text-fg-4" />} bodyClassName="p-0">
              <ul className="flex flex-col divide-y divide-line-1">
                {state.result.evidence.map((e, i) => (
                  <li key={i} className="flex flex-wrap items-center gap-2 px-[var(--panel-pad)] py-2 text-xs">
                    <span className="text-fg-2">{e.source}</span>
                    <StatusChip status={e.status} />
                    <span className="text-fg-4">
                      retrieved <Time iso={e.retrievedAt} />
                    </span>
                  </li>
                ))}
              </ul>
              <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-4">{state.result.methodology}</p>
            </Panel>
          </div>
        )}
      </div>
    </section>
  );
}

function Stat({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-fg-4">{label}</div>
      <div className={mono ? "mono text-sm text-fg-1" : "text-sm text-fg-1"}>{value}</div>
    </div>
  );
}

function DomainExposure() {
  const [domain, setDomain] = useState("");
  const [state, setState] = useState<{ phase: "idle" } | { phase: "loading" } | { phase: "done"; result: DomainResult } | { phase: "error"; message: string }>({ phase: "idle" });

  const run = async (raw: string) => {
    const d = registrableDomain(raw.trim().toLowerCase());
    if (!d) {
      setState({ phase: "error", message: "Enter a valid domain, e.g. example.com." });
      return;
    }
    setState({ phase: "loading" });
    try {
      const result = await api<DomainResult>(`/api/intel/exposure/domain?domain=${encodeURIComponent(d)}`);
      setState({ phase: "done", result });
    } catch (err) {
      setState({ phase: "error", message: (err as ApiClientError).message });
    }
  };

  return (
    <section className="panel panel-ticks">
      <header className="flex items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <ShieldAlert size={14} className="text-fg-3" />
        <h2 className="label text-fg-2">Domain breach exposure</h2>
      </header>
      <div className="p-[var(--panel-pad)]">
        <p className="mb-3 max-w-2xl text-sm text-fg-3">Checks HIBP&apos;s public breach catalogue for breaches attributed to a domain. This confirms exposure when found — it never proves a domain is unaffected, since not every breach records a domain, and HIBP does not index every breach.</p>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(domain);
          }}
        >
          <input className="input h-9 max-w-sm flex-1" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} aria-label="Domain to check" />
          <button type="submit" className="btn btn-primary" disabled={state.phase === "loading"}>
            <Search size={14} /> Check
          </button>
        </form>

        {state.phase === "error" && (
          <div className="mt-3">
            <ErrorNote title="Could not complete the check">{state.message}</ErrorNote>
          </div>
        )}
        {state.phase === "done" && (
          <div className="mt-4">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              {state.result.status === "confirmed-exposure" ? (
                <Chip tone="err">Confirmed exposure — {state.result.breaches.length} breach{state.result.breaches.length === 1 ? "" : "es"}</Chip>
              ) : (
                <Chip tone="ok">No result in the catalogue</Chip>
              )}
              <span className="text-xs text-fg-4">
                {state.result.source} · fetched <Time iso={state.result.fetchedAt} />
              </span>
            </div>
            {state.result.note && <p className="mb-3 max-w-2xl text-xs text-fg-3">{state.result.note}</p>}
            {state.result.breaches.length > 0 && (
              <ul className="flex flex-col divide-y divide-line-1">
                {state.result.breaches.map((b) => (
                  <li key={b.name} className="py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-fg-1">{b.title}</span>
                      {b.verified === false && <Chip tone="warn">unverified</Chip>}
                      {b.sensitive && <Chip tone="warn">sensitive</Chip>}
                      {b.retired && <Chip>retired</Chip>}
                      {b.breachDate && <Mono className="text-xs text-fg-4">{b.breachDate}</Mono>}
                      {b.pwnCount !== undefined && <span className="text-xs text-fg-4">{b.pwnCount.toLocaleString()} accounts</span>}
                    </div>
                    {b.description && <p className="mt-1 max-w-2xl text-xs text-fg-3" dangerouslySetInnerHTML={{ __html: b.description.replace(/<a /g, '<a rel="noopener noreferrer nofollow" target="_blank" ') }} />}
                    {b.dataClasses && b.dataClasses.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {b.dataClasses.map((c) => (
                          <Chip key={c}>{c}</Chip>
                        ))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function PasswordExposure() {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [state, setState] = useState<{ phase: "idle" } | { phase: "loading" } | { phase: "done"; count: number } | { phase: "error"; message: string }>({ phase: "idle" });

  const check = async () => {
    if (!pw) return;
    setState({ phase: "loading" });
    try {
      const hash = await sha1Hex(pw);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const res = await api<{ suffixes: { suffix: string; count: number }[] }>("/api/intel/exposure/password", { method: "POST", json: { prefix } });
      const match = res.suffixes.find((s) => s.suffix === suffix);
      setState({ phase: "done", count: match?.count ?? 0 });
    } catch (err) {
      setState({ phase: "error", message: (err as ApiClientError).message });
    }
  };

  return (
    <section className="panel panel-ticks">
      <header className="flex items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <KeyRound size={14} className="text-fg-3" />
        <h2 className="label text-fg-2">Password exposure (k-anonymity)</h2>
      </header>
      <div className="p-[var(--panel-pad)]">
        <p className="mb-3 max-w-2xl text-sm text-fg-3">
          Your browser computes the SHA-1 hash locally and sends only its first 5 characters to Pwned Passwords, which returns every hash sharing that prefix (typically 500–1000). Your browser finds the match — the full hash and the password itself never leave this device.
        </p>
        <form
          className="flex max-w-sm gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void check();
          }}
        >
          <div className="relative flex-1">
            <input type={show ? "text" : "password"} className="input h-9 w-full pr-9" placeholder="Password to check" value={pw} onChange={(e) => setPw(e.target.value)} aria-label="Password to check" autoComplete="off" />
            <button type="button" className="absolute top-1/2 right-2 -translate-y-1/2 text-fg-4 hover:text-fg-1" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}>
              {show ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
          <button type="submit" className="btn btn-primary" disabled={!pw || state.phase === "loading"}>
            Check
          </button>
        </form>
        {state.phase === "error" && (
          <div className="mt-3">
            <ErrorNote title="Could not complete the check">{state.message}</ErrorNote>
          </div>
        )}
        {state.phase === "done" &&
          (state.count > 0 ? (
            <p className="mt-4 flex items-center gap-2 text-sm text-err">
              <ShieldAlert size={15} /> Seen in {state.count.toLocaleString()} known breach dump{state.count === 1 ? "" : "s"}. Do not use this password.
            </p>
          ) : (
            <p className="mt-4 flex items-center gap-2 text-sm text-ok">
              <ShieldCheck size={15} /> Not found in Pwned Passwords. Absence there is not a guarantee of strength or of safety elsewhere.
            </p>
          ))}
      </div>
    </section>
  );
}

