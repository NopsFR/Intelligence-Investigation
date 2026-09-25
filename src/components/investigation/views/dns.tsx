"use client";

import { cx } from "@/lib/client/cx";
import { CopyButton } from "@/components/ui/primitives";
import { Mark, SourceBlock, useData } from "./common";

interface DnsData {
  kind: "dns";
  host: string;
  records: { type: string; values: string[]; ttl?: number; resolver?: string; error?: string }[];
  comparison: { type: string; answers: Record<string, string[] | null>; consistent: boolean }[];
  cname: string[];
  authenticated: boolean;
  nxdomain?: boolean;
}

const RESOLVER_NAMES: Record<string, string> = { cloudflare: "Cloudflare", google: "Google", dnssb: "DNS.SB" };

function DnsRecords() {
  const d = useData<DnsData>("dns", "dns");
  if (!d || d.nxdomain) return null;
  const rows = d.records.flatMap((r) => (r.values.length ? r.values.map((v, i) => ({ type: r.type, value: v, ttl: r.ttl, first: i === 0, count: r.values.length })) : []));
  const missing = d.records.filter((r) => !r.values.length && !r.error).map((r) => r.type);
  return (
    <div className="flex flex-col gap-4">
      <div className="overflow-x-auto rounded-[2px] border border-line-1">
        <table className="table">
          <thead>
            <tr>
              <th className="w-[70px]">Type</th>
              <th>Value</th>
              <th className="w-[80px] text-right">TTL</th>
              <th className="w-[32px]" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.type}-${i}`} className="group">
                <td className={cx("mono text-[11px] font-semibold", r.first ? "text-fg-1" : "text-transparent")}>{r.type}</td>
                <td className="mono text-[12px] break-all text-fg-1">{r.value}</td>
                <td className="mono tabular text-right text-[11px] text-fg-3">{r.first && r.ttl !== undefined ? `${r.ttl}s` : ""}</td>
                <td>
                  <span className="opacity-0 transition-opacity group-hover:opacity-100">
                    <CopyButton value={r.value} />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {missing.length > 0 && <p className="text-xs text-fg-4">No records: {missing.join(", ")}</p>}
      <div>
        <div className="label mb-2">Resolver agreement</div>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {d.comparison.map((c) => (
            <div key={c.type} className="rounded-[2px] border border-line-1 bg-ink-0 p-2.5">
              <div className="mb-1.5 flex items-center justify-between">
                <span className="mono text-[11px] font-semibold text-fg-1">{c.type}</span>
                <Mark state={c.consistent ? "pass" : "info"}>{c.consistent ? "Consistent" : "Differs"}</Mark>
              </div>
              <ul className="flex flex-col gap-1">
                {Object.entries(c.answers).map(([resolver, values]) => (
                  <li key={resolver} className="grid grid-cols-[70px_1fr] gap-2 text-[11px]">
                    <span className="text-fg-3">{RESOLVER_NAMES[resolver] ?? resolver}</span>
                    <span className="mono truncate text-fg-2" title={values?.join(", ")}>
                      {values === null ? <span className="text-fg-4">no answer</span> : values.length ? values.join(", ") : <span className="text-fg-4">empty</span>}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

interface EmailData {
  kind: "email-security";
  domain: string;
  mx: string[];
  nullMx: boolean;
  receivesMail: boolean;
  spf: { record?: string | null; all: string | null; lookups: number; voidLookups: number; includes: string[]; errors: string[]; multiple: boolean };
  dmarc: { record: string; inherited?: boolean; policy?: string; subdomainPolicy?: string; pct: number; rua: string[]; ruf: string[]; valid: boolean; errors: string[] } | null;
  dkim: { probed: boolean; selectorsChecked: number; found: { selector: string; keyType?: string; bits?: number | null; testing?: boolean }[] };
  mtaSts: { record?: string | null; policy?: { mode?: string; mx: string[]; maxAge?: number } | null; error?: string | null };
  tlsRpt: { record: string; rua?: string } | null;
  bimi: { record: string; l?: string; a?: string } | null;
}

function Control({ name, state, verdict, record, children }: { name: string; state: "pass" | "warn" | "fail" | "info"; verdict: string; record?: string | null; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2 rounded-[2px] border border-line-1 bg-ink-0 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-semibold text-fg-1">{name}</span>
        <Mark state={state}>{verdict}</Mark>
      </div>
      {record && <code className="mono block rounded-[2px] bg-ink-1 px-2 py-1.5 text-[11px] leading-relaxed break-all text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{record}</code>}
      {children && <div className="text-xs text-fg-3">{children}</div>}
    </div>
  );
}

function EmailControls() {
  const d = useData<EmailData>("email-security", "email-security");
  if (!d) return null;
  const spfState = !d.spf.record ? "fail" : d.spf.multiple || d.spf.errors.length || d.spf.all === "+" ? "fail" : d.spf.all === "-" || d.spf.all === "~" ? (d.spf.lookups > 10 ? "warn" : "pass") : "warn";
  const dmarcState = !d.dmarc ? "fail" : !d.dmarc.valid ? "fail" : d.dmarc.policy === "none" || d.dmarc.pct < 100 ? "warn" : "pass";
  const mode = d.mtaSts.policy?.mode;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Control name="SPF" state={spfState} verdict={!d.spf.record ? "Missing" : `${d.spf.all ? `${d.spf.all}all` : "no all"} · ${d.spf.lookups}/10 lookups`} record={d.spf.record}>
        {d.spf.includes.length > 0 && <>Includes {d.spf.includes.join(", ")}</>}
        {d.spf.errors.length > 0 && <div className="text-err">{d.spf.errors.join("; ")}</div>}
      </Control>
      <Control name="DMARC" state={dmarcState} verdict={!d.dmarc ? "Missing" : `p=${d.dmarc.policy ?? "?"}${d.dmarc.pct < 100 ? ` · pct=${d.dmarc.pct}` : ""}`} record={d.dmarc?.record}>
        {d.dmarc?.inherited && <>Inherited from the organisational domain. </>}
        {d.dmarc && (d.dmarc.rua.length ? `Aggregate reports → ${d.dmarc.rua.join(", ")}` : "No aggregate reporting address.")}
      </Control>
      <Control name="DKIM" state={d.dkim.found.length ? (d.dkim.found.some((k) => k.bits && k.bits < 2048) ? "warn" : "pass") : d.dkim.probed ? "info" : "info"} verdict={d.dkim.found.length ? `${d.dkim.found.length} selector(s) found` : d.dkim.probed ? "No common selector found" : "Not probed in quick scan"}>
        {d.dkim.found.length > 0 ? d.dkim.found.map((k) => `${k.selector}${k.bits ? ` (${k.keyType ?? "rsa"} ${k.bits})` : ""}${k.testing ? " · testing mode" : ""}`).join(", ") : d.dkim.probed ? `Checked ${d.dkim.selectorsChecked} common selectors. Selectors are arbitrary, so absence here does not mean DKIM is unused.` : "Deep investigation probes common selectors."}
      </Control>
      <Control name="MTA-STS" state={mode === "enforce" ? "pass" : mode === "testing" ? "warn" : d.mtaSts.record ? "warn" : "info"} verdict={mode ? `mode=${mode}` : d.mtaSts.record ? "Record present" : "Not deployed"} record={d.mtaSts.record}>
        {d.mtaSts.error ? d.mtaSts.error : d.mtaSts.policy?.mx.length ? `Policy MX: ${d.mtaSts.policy.mx.join(", ")}` : null}
      </Control>
      <Control name="TLS-RPT" state={d.tlsRpt ? "pass" : "info"} verdict={d.tlsRpt ? "Reporting enabled" : "Not deployed"} record={d.tlsRpt?.record} />
      <Control name="BIMI" state={d.bimi ? "pass" : "info"} verdict={d.bimi ? "Published" : "Not published"} record={d.bimi?.record}>
        {d.bimi?.a ? "Includes a verified mark certificate reference." : null}
      </Control>
    </div>
  );
}

export function DnsSection() {
  return (
    <div className="flex flex-col gap-4">
      <SourceBlock provider="dns" showFacts={false}>
        <DnsRecords />
      </SourceBlock>
      <div className="grid gap-4 xl:grid-cols-2">
        <SourceBlock provider="dnssec" />
        <SourceBlock provider="hostname-analysis" />
        <SourceBlock provider="reverse-dns" />
      </div>
    </div>
  );
}

export function EmailSection() {
  return (
    <SourceBlock provider="email-security" showFacts={false}>
      <EmailControls />
    </SourceBlock>
  );
}
