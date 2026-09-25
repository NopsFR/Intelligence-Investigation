"use client";

import { useState } from "react";
import { usePrefs } from "@/lib/client/prefs";
import { dateOnly } from "@/lib/client/format";
import { cx } from "@/lib/client/cx";
import { Mark, SourceBlock, useData } from "./common";

interface ChainCert {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  keyType?: string;
  keySize?: number;
  curve?: string;
  selfSigned: boolean;
  isCA?: boolean;
}

interface TlsData {
  kind: "tls";
  hostname: string;
  protocol: string | null;
  cipher?: string;
  authorized: boolean;
  authorizationError?: string;
  hostnameMatches: boolean;
  chain: ChainCert[];
  daysRemaining: number;
  tls13?: boolean;
  legacy?: { tls10: boolean; tls11: boolean };
}

function cn(dn: string) {
  return dn.match(/CN=([^,]+)/)?.[1] ?? dn.split(",")[0] ?? dn;
}

/** Validity window with a "now" marker — the part of a certificate people actually need to see. */
function ValidityBar({ from, to }: { from: string; to: string }) {
  const { prefs } = usePrefs();
  const a = new Date(from).getTime();
  const b = new Date(to).getTime();
  const [now] = useState(() => Date.now());
  const pct = Math.min(100, Math.max(0, ((now - a) / (b - a)) * 100));
  const left = Math.round((b - now) / 86_400_000);
  const color = left < 0 ? "var(--color-err)" : left < 14 ? "var(--color-warn)" : "var(--color-fg-3)";
  return (
    <div>
      <div className="relative h-[4px] rounded-[1px] bg-ink-3">
        <div className="absolute inset-y-0 left-0 rounded-[1px] transition-[width] duration-700" style={{ width: `${pct}%`, background: color }} />
        <div className="absolute -top-[3px] h-[10px] w-px bg-fg-1" style={{ left: `${pct}%` }} aria-hidden />
      </div>
      <div className="mono mt-1 flex justify-between text-[10.5px] text-fg-4">
        <span>{dateOnly(from, prefs.tz)}</span>
        <span style={{ color }}>{left < 0 ? `expired ${-left}d ago` : `${left}d left`}</span>
        <span>{dateOnly(to, prefs.tz)}</span>
      </div>
    </div>
  );
}

function TlsChain() {
  const d = useData<TlsData>("tls", "tls");
  if (!d) return null;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-x-5 gap-y-2">
        <Mark state={d.authorized ? "pass" : "fail"}>{d.authorized ? "Trusted chain" : `Untrusted: ${d.authorizationError ?? "verification failed"}`}</Mark>
        <Mark state={d.hostnameMatches ? "pass" : "fail"}>{d.hostnameMatches ? "Hostname matches" : "Hostname mismatch"}</Mark>
        <Mark state={d.protocol === "TLSv1.3" ? "pass" : d.protocol === "TLSv1.2" ? "info" : "fail"}>{d.protocol ?? "Unknown protocol"}</Mark>
        {d.legacy && <Mark state={d.legacy.tls10 || d.legacy.tls11 ? "warn" : "pass"}>{d.legacy.tls10 || d.legacy.tls11 ? "Legacy TLS accepted" : "Legacy TLS refused"}</Mark>}
      </div>
      <ol className="relative flex flex-col gap-2">
        {d.chain.map((c, i) => (
          <li key={c.fingerprint256} className="relative grid grid-cols-[18px_minmax(0,1fr)] gap-3">
            <span aria-hidden className="relative flex justify-center">
              <span className={cx("mt-3 h-[9px] w-[9px] rotate-45 border", i === 0 ? "border-fg-1 bg-fg-1" : "border-fg-3 bg-ink-1")} />
              {i < d.chain.length - 1 && <span className="absolute top-[22px] bottom-[-14px] w-px bg-line-3" />}
            </span>
            <div className="rounded-[2px] border border-line-1 bg-ink-0 p-3">
              <div className="mb-1 flex flex-wrap items-baseline gap-x-2">
                <span className="label">{i === 0 ? "Leaf" : c.selfSigned ? "Root" : "Intermediate"}</span>
                <span className="text-sm font-medium text-fg-1">{cn(c.subject)}</span>
                <span className="text-xs text-fg-3">issued by {cn(c.issuer)}</span>
              </div>
              <div className="mono mb-2 flex flex-wrap gap-x-4 text-[11px] text-fg-3">
                <span>{c.keyType ? `${c.keyType.toUpperCase()}${c.keySize ? ` ${c.keySize}` : ""}${c.curve ? ` ${c.curve}` : ""}` : "key unknown"}</span>
                <span className="truncate" title={c.fingerprint256}>
                  SHA-256 {c.fingerprint256.slice(0, 23)}…
                </span>
              </div>
              <ValidityBar from={c.validFrom} to={c.validTo} />
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

interface HttpData {
  kind: "http";
  requested: string;
  finalUrl?: string;
  status?: number;
  hops?: { url: string; status: number; location?: string; server?: string; latencyMs: number }[];
  checks: { id: string; header: string; status: "pass" | "warn" | "fail" | "info"; value?: string; note: string }[];
  headerFindingsApplied?: boolean;
  upgrade?: { reachable: boolean; status?: number; location?: string; upgrades?: boolean } | null;
  error?: string;
}

function HttpDetail() {
  const d = useData<HttpData>("http", "http");
  if (!d) return null;
  return (
    <div className="flex flex-col gap-5">
      {!!d.hops?.length && (
        <div>
          <div className="label mb-2">Request chain</div>
          <ol className="flex flex-col">
            {d.hops.map((h, i) => (
              <li key={`${h.url}-${i}`} className="grid grid-cols-[46px_minmax(0,1fr)_auto] items-center gap-3 py-1.5">
                <span className={cx("mono rounded-[2px] px-1.5 py-0.5 text-center text-[11px] font-semibold", h.status >= 400 ? "text-err" : h.status >= 300 ? "text-warn" : "text-ok")} style={{ background: "var(--color-ink-2)" }}>
                  {h.status}
                </span>
                <span className="mono min-w-0 truncate text-[12px] text-fg-1" title={h.url}>
                  {h.url}
                </span>
                <span className="mono text-[10.5px] text-fg-4">{h.latencyMs} ms</span>
              </li>
            ))}
          </ol>
        </div>
      )}
      {d.upgrade?.reachable && (
        <Mark state={d.upgrade.upgrades ? "pass" : "warn"}>
          {d.upgrade.upgrades ? `HTTP redirects to HTTPS (${d.upgrade.status})` : `HTTP answers ${d.upgrade.status} without upgrading to HTTPS`}
        </Mark>
      )}
      {d.checks.length > 0 && (
        <div>
          <div className="label mb-2">Security headers {d.headerFindingsApplied === false && <span className="ml-1 normal-case tracking-normal text-fg-4">(reference only for URL investigations)</span>}</div>
          <div className="overflow-x-auto rounded-[2px] border border-line-1">
            <table className="table">
              <tbody>
                {d.checks.map((c) => (
                  <tr key={c.id}>
                    <td className="w-[36px] align-middle">
                      <Mark state={c.status} />
                    </td>
                    <td className="w-[240px] text-sm whitespace-nowrap text-fg-1">{c.header}</td>
                    <td className="text-xs text-fg-2">
                      <div>{c.note}</div>
                      {c.value && c.value !== c.note && <div className="mono mt-0.5 line-clamp-2 text-[11px] break-all text-fg-4">{c.value}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

interface CtData {
  kind: "ct-issuances";
  names: string[];
  certificates: { id: string; names: string[]; issuer?: string; notBefore?: string; notAfter?: string; revoked?: boolean }[];
}

function CtLog({ provider }: { provider: string }) {
  const d = useData<CtData>(provider, "ct-issuances");
  const { prefs } = usePrefs();
  if (!d) return null;
  return (
    <div className="flex flex-col gap-4">
      {d.names.length > 0 && (
        <div>
          <div className="label mb-2">Names seen in certificates · {d.names.length}</div>
          <div className="flex max-h-[160px] flex-wrap gap-1 overflow-y-auto">
            {d.names.slice(0, 200).map((n) => (
              <span key={n} className="mono rounded-[2px] bg-ink-2 px-1.5 py-px text-[11px] text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
                {n}
              </span>
            ))}
          </div>
        </div>
      )}
      <div className="max-h-[320px] overflow-auto rounded-[2px] border border-line-1">
        <table className="table">
          <thead>
            <tr>
              <th>Issuer</th>
              <th>Names</th>
              <th className="text-right">Valid from</th>
              <th className="text-right">Until</th>
            </tr>
          </thead>
          <tbody>
            {d.certificates.slice(0, 60).map((c) => (
              <tr key={c.id}>
                <td className="text-xs whitespace-nowrap text-fg-2">{c.issuer ?? "—"}</td>
                <td className="mono max-w-[380px] truncate text-[11px] text-fg-1" title={c.names.join(", ")}>
                  {c.names.slice(0, 3).join(", ")}
                  {c.names.length > 3 && <span className="text-fg-4"> +{c.names.length - 3}</span>}
                </td>
                <td className="mono text-right text-[11px] text-fg-3">{dateOnly(c.notBefore, prefs.tz)}</td>
                <td className="mono text-right text-[11px] text-fg-3">{dateOnly(c.notAfter, prefs.tz)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function CertificatesSection() {
  return (
    <div className="flex flex-col gap-4">
      <SourceBlock provider="tls" showFacts={false}>
        <TlsChain />
      </SourceBlock>
      <SourceBlock provider="certspotter" showFacts={false}>
        <CtLog provider="certspotter" />
      </SourceBlock>
      <SourceBlock provider="crtsh" showFacts={false}>
        <CtLog provider="crtsh" />
      </SourceBlock>
    </div>
  );
}

export function WebSection() {
  return (
    <div className="flex flex-col gap-4">
      <SourceBlock provider="url-analysis" />
      <SourceBlock provider="http">
        <HttpDetail />
      </SourceBlock>
    </div>
  );
}
