"use client";

import { Binary, Calculator, FileInput, Globe, Loader2, Radar, Shield, ShieldOff } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";
import type { ObservableType } from "@/lib/core/types";
import { api, type ApiClientError } from "@/lib/client/api";
import { cx } from "@/lib/client/cx";
import { useInvestigate } from "@/lib/client/investigate";
import { parseCvssVector, severityFromScore } from "@/lib/intel/cvss";
import { defang, refang } from "@/lib/observables/fang";
import { classifyIp, ipv4ToNumber, isIpv4 } from "@/lib/observables/ip";
import { TypeTag } from "@/components/ui/badges";
import { CopyButton, ErrorNote } from "@/components/ui/primitives";

const TOOLS: { id: string; label: string; icon: ReactNode; hint: string }[] = [
  { id: "fang", label: "Defang / refang", icon: <ShieldOff size={14} />, hint: "Make indicators safe to share, or usable again" },
  { id: "extract", label: "Extract indicators", icon: <FileInput size={14} />, hint: "Pull IOCs out of free text" },
  { id: "dns", label: "DNS lookup", icon: <Globe size={14} />, hint: "Live query via public DoH resolvers" },
  { id: "cidr", label: "IPv4 subnet", icon: <Calculator size={14} />, hint: "Network, range and special-purpose status" },
  { id: "cvss", label: "CVSS vector", icon: <Shield size={14} />, hint: "Decode a CVSS v2/v3/v4 vector" },
  { id: "decode", label: "Decode", icon: <Binary size={14} />, hint: "Base64, URL encoding, epoch timestamps" },
];

function Output({ value, label = "Result" }: { value: string; label?: string }) {
  return (
    <div className="relative">
      <div className="label mb-1.5">{label}</div>
      <pre className="mono min-h-[80px] overflow-auto rounded-[2px] bg-ink-0 p-3 pr-10 text-[12px] leading-relaxed break-all whitespace-pre-wrap text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{value || <span className="text-fg-4">—</span>}</pre>
      {value && (
        <div className="absolute top-7 right-1.5">
          <CopyButton value={value} />
        </div>
      )}
    </div>
  );
}

function FangTool() {
  const [text, setText] = useState("");
  const [mode, setMode] = useState<"defang" | "refang">("defang");
  const out = text
    .split("\n")
    .map((l) => (mode === "defang" ? defang(l) : refang(l)))
    .join("\n");
  return (
    <div className="flex flex-col gap-4">
      <div className="inline-flex self-start rounded-[3px] border border-line-2 bg-ink-0 p-[2px]" role="radiogroup" aria-label="Direction">
        {(["defang", "refang"] as const).map((m) => (
          <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)} className={cx("h-[26px] rounded-[2px] px-3 text-sm capitalize", mode === m ? "bg-ink-3 text-fg-1" : "text-fg-3")}>
            {m}
          </button>
        ))}
      </div>
      <textarea className="input mono min-h-[140px] text-[12px]" placeholder={mode === "defang" ? "https://malicious.example/payload.exe" : "hxxps://malicious[.]example/payload[.]exe"} value={text} onChange={(e) => setText(e.target.value)} aria-label="Input" />
      <Output value={out} />
    </div>
  );
}

function ExtractTool() {
  const [text, setText] = useState("");
  const [found, setFound] = useState<{ value: string; type: ObservableType; occurrences: number }[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { start } = useInvestigate();
  const run = async () => {
    setBusy(true);
    try {
      setFound((await api<{ indicators: typeof found }>("/api/extract", { method: "POST", json: { text } })).indicators);
      setError(null);
    } catch (e) {
      setError((e as ApiClientError).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-col gap-4">
      <textarea className="input mono min-h-[160px] text-[12px]" placeholder="Paste a threat report, phishing email headers, SIEM alert or chat transcript…" value={text} onChange={(e) => setText(e.target.value)} aria-label="Text to extract from" />
      <button type="button" className="btn self-start" onClick={() => void run()} disabled={busy || !text.trim()}>
        {busy ? <Loader2 size={13} className="animate-spin" /> : <FileInput size={13} />} Extract
      </button>
      {error && <ErrorNote>{error}</ErrorNote>}
      {found && (
        <>
          <div className="overflow-hidden rounded-[2px] border border-line-1">
            {found.length ? (
              <table className="table">
                <tbody>
                  {found.map((f) => (
                    <tr key={`${f.type}:${f.value}`} className="group">
                      <td className="w-[70px]">
                        <TypeTag type={f.type} />
                      </td>
                      <td className="mono text-[12px] break-all text-fg-1">{f.value}</td>
                      <td className="mono w-[50px] text-right text-[11px] text-fg-4">{f.occurrences > 1 ? `×${f.occurrences}` : ""}</td>
                      <td className="w-[120px] text-right">
                        <button type="button" className="btn btn-sm opacity-60 group-hover:opacity-100" onClick={() => void start(f.value, "QUICK", { type: f.type })}>
                          <Radar size={12} /> Scan
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="p-4 text-sm text-fg-3">No valid indicators found.</p>
            )}
          </div>
          {found.length > 0 && <Output label="As list" value={found.map((f) => f.value).join("\n")} />}
        </>
      )}
    </div>
  );
}

interface DnsAnswer {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

function DnsTool() {
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const [resolver, setResolver] = useState("cloudflare");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ query: { name: string; type: string }; rcodeName: string; authenticated: boolean; answers: DnsAnswer[]; latencyMs: number; resolver: { name: string; protocol: string } } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    try {
      setRes(await api(`/api/toolbox/dns?${new URLSearchParams({ name: name.trim(), type, resolver })}`));
      setError(null);
    } catch (e) {
      setError((e as ApiClientError).message);
      setRes(null);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-col gap-4">
      <form className="flex flex-wrap gap-2" onSubmit={(e) => (e.preventDefault(), void run())}>
        <input className="input mono min-w-[220px] flex-1 text-[12px]" placeholder="example.com (or an IP for PTR)" value={name} onChange={(e) => setName(e.target.value)} aria-label="Name" />
        <select className="input w-auto" value={type} onChange={(e) => setType(e.target.value)} aria-label="Record type">
          {["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "PTR", "DS", "DNSKEY", "SRV", "HTTPS"].map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        <select className="input w-auto" value={resolver} onChange={(e) => setResolver(e.target.value)} aria-label="Resolver">
          <option value="cloudflare">Cloudflare (JSON)</option>
          <option value="google">Google (JSON)</option>
          <option value="dnssb">DNS.SB (RFC 8484)</option>
        </select>
        <button type="submit" className="btn btn-primary" disabled={busy || !name.trim()}>
          {busy ? <Loader2 size={13} className="animate-spin" /> : <Globe size={13} />} Resolve
        </button>
      </form>
      {error && <ErrorNote title="Lookup failed">{error}</ErrorNote>}
      {res && (
        <div className="animate-fade">
          <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-3">
            <span className="mono text-fg-1">
              {res.query.name} {res.query.type}
            </span>
            <span>
              rcode <span className="mono text-fg-1">{res.rcodeName}</span>
            </span>
            <span>{res.authenticated ? "DNSSEC-validated (AD)" : "Not DNSSEC-validated"}</span>
            <span>
              {res.resolver.name} · {res.latencyMs} ms
            </span>
          </div>
          <div className="overflow-x-auto rounded-[2px] border border-line-1">
            {res.answers.length ? (
              <table className="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th className="text-right">TTL</th>
                    <th>Data</th>
                  </tr>
                </thead>
                <tbody>
                  {res.answers.map((a, i) => (
                    <tr key={i}>
                      <td className="mono text-[11.5px] text-fg-2">{a.name}</td>
                      <td className="mono text-[11px] text-fg-1">{a.type}</td>
                      <td className="mono text-right text-[11px] text-fg-3">{a.ttl}</td>
                      <td className="mono text-[12px] break-all text-fg-1">{a.data}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="p-4 text-sm text-fg-3">No answers.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function numberToIp(n: number) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function CidrTool() {
  const [input, setInput] = useState("192.0.2.0/24");
  const result = useMemo(() => {
    const [addr, bitsRaw] = input.trim().split("/");
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (!isIpv4(addr) || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    const ip = ipv4ToNumber(addr);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const network = (ip & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const size = 2 ** (32 - bits);
    const c = classifyIp(numberToIp(network));
    return {
      network: `${numberToIp(network)}/${bits}`,
      mask: numberToIp(mask),
      wildcard: numberToIp(~mask >>> 0),
      first: numberToIp(bits >= 31 ? network : network + 1),
      last: numberToIp(bits >= 31 ? broadcast : broadcast - 1),
      broadcast: numberToIp(broadcast),
      size,
      usable: bits >= 31 ? size : size - 2,
      scope: c ? `${c.scope}${c.range ? ` (${c.range} — ${c.description})` : ""}` : "—",
    };
  }, [input]);
  return (
    <div className="flex flex-col gap-4">
      <input className="input mono text-[12px]" value={input} onChange={(e) => setInput(e.target.value)} aria-label="IPv4 CIDR" placeholder="10.20.30.0/22" />
      {result ? (
        <dl className="grid overflow-hidden rounded-[2px] border border-line-1 sm:grid-cols-2">
          {Object.entries({ Network: result.network, Netmask: result.mask, Wildcard: result.wildcard, "First host": result.first, "Last host": result.last, Broadcast: result.broadcast, Addresses: result.size.toLocaleString("en-GB"), "Usable hosts": result.usable.toLocaleString("en-GB"), "Address space": result.scope }).map(([k, v]) => (
            <div key={k} className="flex items-baseline justify-between gap-3 border-b border-line-1 px-3 py-2 sm:odd:border-r">
              <dt className="text-xs text-fg-3">{k}</dt>
              <dd className="mono text-right text-[12px] text-fg-1">{v}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-sm text-fg-3">Enter an IPv4 address with an optional prefix length, e.g. 10.20.30.0/22.</p>
      )}
    </div>
  );
}

function CvssTool() {
  const [vector, setVector] = useState("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  const [score, setScore] = useState("10.0");
  const parsed = parseCvssVector(vector.trim());
  const s = Number(score);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2">
        <input className="input mono min-w-[260px] flex-1 text-[12px]" value={vector} onChange={(e) => setVector(e.target.value)} aria-label="CVSS vector" />
        <input className="input mono w-[90px] text-[12px]" value={score} onChange={(e) => setScore(e.target.value)} aria-label="Base score (optional)" placeholder="score" />
      </div>
      {parsed ? (
        <>
          <div className="text-xs text-fg-3">
            CVSS {parsed.version}
            {Number.isFinite(s) && score && ` · base score ${s} → ${severityFromScore(s, parsed.version)}`}
          </div>
          <dl className="grid gap-px overflow-hidden rounded-[2px] bg-line-1 sm:grid-cols-2 lg:grid-cols-4">
            {parsed.metrics.map((m) => (
              <div key={m.key} className="bg-ink-0 px-3 py-2">
                <dt className="text-[10.5px] text-fg-4">
                  {m.metric} <span className="mono">({m.key})</span>
                </dt>
                <dd className="text-sm text-fg-1">{m.value}</dd>
              </div>
            ))}
          </dl>
          <p className="text-xs text-fg-4">Base scores are published by NVD and CNAs; this decoder explains the vector rather than recomputing the score.</p>
        </>
      ) : (
        <p className="text-sm text-fg-3">Not a recognised CVSS vector.</p>
      )}
    </div>
  );
}

function DecodeTool() {
  const [input, setInput] = useState("");
  const results = useMemo(() => {
    const v = input.trim();
    if (!v) return [];
    const out: { label: string; value: string }[] = [];
    if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(v) && v.length % 4 !== 1) {
      try {
        const bytes = Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
        const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
        const printable = text.replace(/[^\x20-\x7e\n\t -￿]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);
        out.push({ label: `Base64 → text (${bytes.length} bytes)`, value: printable });
      } catch {
        /* not base64 */
      }
    }
    if (/%[0-9a-f]{2}/i.test(v)) {
      try {
        out.push({ label: "URL decoded", value: decodeURIComponent(v) });
      } catch {
        /* malformed */
      }
    }
    if (/^\d{9,13}(\.\d+)?$/.test(v)) {
      const n = Number(v);
      const ms = n > 1e12 ? n : n * 1000;
      out.push({ label: n > 1e12 ? "Epoch milliseconds → UTC" : "Epoch seconds → UTC", value: new Date(ms).toISOString() });
    }
    const d = new Date(v);
    if (!/^\d+$/.test(v) && !Number.isNaN(d.getTime())) out.push({ label: "Date → epoch seconds", value: String(Math.floor(d.getTime() / 1000)) });
    return out;
  }, [input]);
  return (
    <div className="flex flex-col gap-4">
      <textarea className="input mono min-h-[100px] text-[12px]" placeholder="Base64, %-encoded text, an epoch timestamp or a date" value={input} onChange={(e) => setInput(e.target.value)} aria-label="Value to decode" />
      {input.trim() && !results.length && <p className="text-sm text-fg-3">Nothing recognised.</p>}
      {results.map((r) => (
        <Output key={r.label} label={r.label} value={r.value} />
      ))}
      <p className="text-xs text-fg-4">Decoding happens in your browser; nothing is sent to the server.</p>
    </div>
  );
}

export function Toolbox() {
  const params = useSearchParams();
  const router = useRouter();
  const path = usePathname();
  const tool = TOOLS.some((t) => t.id === params.get("tool")) ? params.get("tool")! : "fang";
  const select = (id: string) => router.replace(`${path}?tool=${id}`, { scroll: false });
  const active = TOOLS.find((t) => t.id === tool)!;
  return (
    <div className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)]">
      <nav aria-label="Tools" className="panel h-fit p-1.5">
        <ul className="flex gap-1 overflow-x-auto lg:flex-col">
          {TOOLS.map((t) => (
            <li key={t.id} className="shrink-0">
              <button type="button" onClick={() => select(t.id)} aria-current={t.id === tool ? "page" : undefined} className={cx("flex w-full items-start gap-2.5 rounded-[2px] px-2.5 py-2 text-left transition-colors", t.id === tool ? "bg-ink-3 text-fg-1" : "text-fg-3 hover:bg-ink-2 hover:text-fg-1")}>
                <span className="mt-0.5">{t.icon}</span>
                <span>
                  <span className="block text-sm font-medium">{t.label}</span>
                  <span className="hidden text-xs text-fg-4 lg:block">{t.hint}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <section key={tool} className="panel panel-ticks animate-fade p-[var(--panel-pad)]" aria-label={active.label}>
        <h2 className="mb-1 text-base font-semibold text-fg-1">{active.label}</h2>
        <p className="mb-4 text-xs text-fg-3">{active.hint}</p>
        {tool === "fang" && <FangTool />}
        {tool === "extract" && <ExtractTool />}
        {tool === "dns" && <DnsTool />}
        {tool === "cidr" && <CidrTool />}
        {tool === "cvss" && <CvssTool />}
        {tool === "decode" && <DecodeTool />}
      </section>
    </div>
  );
}

