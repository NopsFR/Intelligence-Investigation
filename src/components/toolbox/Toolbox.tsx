"use client";

import { Binary, Braces, Calculator, FileInput, Fingerprint, Globe, KeyRound, Link2, Loader2, Radar, Shield, ShieldOff, Wifi } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";
import type { ObservableType } from "@/lib/core/types";
import { api, type ApiClientError } from "@/lib/client/api";
import { cx } from "@/lib/client/cx";
import { useInvestigate } from "@/lib/client/investigate";
import { parseCvssVector, severityFromScore } from "@/lib/intel/cvss";
import { defang, refang } from "@/lib/observables/fang";
import { classifyIp, formatIpv6, ipv4ToNumber, isIpv4, isIpv6, parseIpv6 } from "@/lib/observables/ip";
import { certificatesFromPem } from "@/lib/analysis/der";
import { TypeTag } from "@/components/ui/badges";
import { CopyButton, ErrorNote } from "@/components/ui/primitives";

const TOOLS: { id: string; label: string; icon: ReactNode; hint: string }[] = [
  { id: "fang", label: "Defang / refang", icon: <ShieldOff size={14} />, hint: "Make indicators safe to share, or usable again" },
  { id: "extract", label: "Extract indicators", icon: <FileInput size={14} />, hint: "Pull IOCs out of free text" },
  { id: "dns", label: "DNS lookup", icon: <Globe size={14} />, hint: "Live query via public DoH resolvers" },
  { id: "cidr", label: "IPv4 subnet", icon: <Calculator size={14} />, hint: "Network, range and special-purpose status" },
  { id: "cvss", label: "CVSS vector", icon: <Shield size={14} />, hint: "Decode a CVSS v2/v3/v4 vector" },
  { id: "decode", label: "Decode", icon: <Binary size={14} />, hint: "Base64, URL encoding, epoch timestamps" },
  { id: "ipv6", label: "IPv6", icon: <Wifi size={14} />, hint: "Expand, compress and classify an IPv6 address" },
  { id: "mac", label: "MAC / OUI", icon: <Fingerprint size={14} />, hint: "Vendor lookup from the IEEE registry" },
  { id: "url", label: "URL parser", icon: <Link2 size={14} />, hint: "Break a URL into its parts" },
  { id: "jwt", label: "JWT decoder", icon: <KeyRound size={14} />, hint: "Inspect header and payload claims (no signature check)" },
  { id: "json", label: "JSON", icon: <Braces size={14} />, hint: "Format, validate and minify" },
  { id: "cert", label: "Certificate", icon: <Shield size={14} />, hint: "Decode a PEM certificate" },
  { id: "ref", label: "References", icon: <FileInput size={14} />, hint: "TCP flags, HTTP status, ports and protocols" },
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

function Ipv6Tool() {
  const [input, setInput] = useState("2001:db8::1");
  const result = useMemo(() => {
    const v = input.trim();
    if (!isIpv6(v)) return null;
    const big = parseIpv6(v)!;
    const compressed = formatIpv6(big);
    const full = Array.from({ length: 8 }, (_, i) => ((big >> BigInt((7 - i) * 16)) & BigInt(0xffff)).toString(16).padStart(4, "0")).join(":");
    const c = classifyIp(compressed);
    const isV4Mapped = /^::ffff:/i.test(compressed);
    return { compressed, full, scope: c ? `${c.scope}${c.range ? ` (${c.range} — ${c.description})` : ""}` : "—", isV4Mapped };
  }, [input]);
  return (
    <div className="flex flex-col gap-4">
      <input className="input mono text-[12px]" value={input} onChange={(e) => setInput(e.target.value)} aria-label="IPv6 address" placeholder="2001:db8::1 or ::ffff:192.0.2.1" />
      {result ? (
        <dl className="grid overflow-hidden rounded-[2px] border border-line-1 sm:grid-cols-2">
          {Object.entries({ Compressed: result.compressed, "Fully expanded": result.full, Scope: result.scope, "IPv4-mapped": result.isV4Mapped ? "yes" : "no" }).map(([k, v]) => (
            <div key={k} className="flex items-baseline justify-between gap-3 border-b border-line-1 px-3 py-2 sm:odd:border-r">
              <dt className="text-xs text-fg-3">{k}</dt>
              <dd className="mono text-right text-[12px] break-all text-fg-1">{v}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-sm text-fg-3">Enter a valid IPv6 address.</p>
      )}
    </div>
  );
}

function MacTool() {
  const [mac, setMac] = useState("00:1A:2B:33:44:55");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ found: boolean; prefix?: string; vendor?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    try {
      setRes(await api(`/api/toolbox/oui?mac=${encodeURIComponent(mac.trim())}`));
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
        <input className="input mono min-w-[220px] flex-1 text-[12px]" value={mac} onChange={(e) => setMac(e.target.value)} aria-label="MAC address or OUI prefix" placeholder="00:1A:2B:33:44:55" />
        <button type="submit" className="btn btn-primary" disabled={busy || !mac.trim()}>
          {busy ? <Loader2 size={13} className="animate-spin" /> : <Fingerprint size={13} />} Look up
        </button>
      </form>
      {error && <ErrorNote title="Lookup failed">{error}</ErrorNote>}
      {res && (
        <div className="rounded-[2px] border border-line-1 p-3 text-sm">
          {res.found ? (
            <>
              <span className="mono text-fg-3">{res.prefix}</span> <span className="text-fg-1">{res.vendor}</span>
            </>
          ) : (
            <span className="text-fg-3">No vendor registered for this prefix in the IEEE MA-L registry (it may be a locally-administered or randomised address).</span>
          )}
        </div>
      )}
      <p className="text-xs text-fg-4">Source: IEEE public MAC address registry (MA-L), fetched and cached server-side.</p>
    </div>
  );
}

function UrlParseTool() {
  const [input, setInput] = useState("https://user@sub.example.com:8443/path/to/page?query=1&x=2#frag");
  const parsed = useMemo(() => {
    try {
      return new URL(input.trim());
    } catch {
      return null;
    }
  }, [input]);
  return (
    <div className="flex flex-col gap-4">
      <input className="input mono text-[12px]" value={input} onChange={(e) => setInput(e.target.value)} aria-label="URL" />
      {parsed ? (
        <>
          <dl className="grid overflow-hidden rounded-[2px] border border-line-1 sm:grid-cols-2">
            {Object.entries({ Scheme: parsed.protocol.replace(":", ""), Username: parsed.username || "—", Host: parsed.hostname, Port: parsed.port || "(default)", Path: parsed.pathname, Fragment: parsed.hash.replace("#", "") || "—", Origin: parsed.origin }).map(([k, v]) => (
              <div key={k} className="flex items-baseline justify-between gap-3 border-b border-line-1 px-3 py-2 sm:odd:border-r">
                <dt className="text-xs text-fg-3">{k}</dt>
                <dd className="mono text-right text-[12px] break-all text-fg-1">{v}</dd>
              </div>
            ))}
          </dl>
          {[...parsed.searchParams].length > 0 && (
            <div className="overflow-hidden rounded-[2px] border border-line-1">
              <table className="table">
                <thead>
                  <tr>
                    <th>Query parameter</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {[...parsed.searchParams].map(([k, v], i) => (
                    <tr key={i}>
                      <td className="mono text-[12px] text-fg-1">{k}</td>
                      <td className="mono text-[12px] break-all text-fg-2">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      ) : (
        <p className="text-sm text-fg-3">Not a valid absolute URL.</p>
      )}
    </div>
  );
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad), (c) => c.charCodeAt(0));
}

function JwtTool() {
  const [token, setToken] = useState("");
  const [now] = useState(() => Date.now());
  const parsed = useMemo(() => {
    const parts = token.trim().split(".");
    if (parts.length < 2) return null;
    try {
      const header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
      const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
      const claims: { key: string; note?: string }[] = [];
      if (typeof payload.exp === "number") claims.push({ key: "exp", note: `${new Date(payload.exp * 1000).toISOString()}${payload.exp * 1000 < now ? " (expired)" : ""}` });
      if (typeof payload.iat === "number") claims.push({ key: "iat", note: new Date(payload.iat * 1000).toISOString() });
      if (typeof payload.nbf === "number") claims.push({ key: "nbf", note: new Date(payload.nbf * 1000).toISOString() });
      return { header, payload, claims, hasSignature: parts.length === 3 && parts[2].length > 0 };
    } catch {
      return null;
    }
  }, [token, now]);
  return (
    <div className="flex flex-col gap-4">
      <textarea className="input mono min-h-[90px] text-[12px]" placeholder="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.…" value={token} onChange={(e) => setToken(e.target.value)} aria-label="JWT" />
      {token.trim() && !parsed && <p className="text-sm text-fg-3">Not a decodable JWT (needs a base64url header and payload).</p>}
      {parsed && (
        <>
          <Output label="Header" value={JSON.stringify(parsed.header, null, 2)} />
          <Output label="Payload" value={JSON.stringify(parsed.payload, null, 2)} />
          {parsed.claims.length > 0 && (
            <ul className="flex flex-col gap-1 text-xs text-fg-3">
              {parsed.claims.map((c) => (
                <li key={c.key}>
                  <span className="mono text-fg-1">{c.key}</span>: {c.note}
                </li>
              ))}
            </ul>
          )}
          <p className="flex items-center gap-1.5 text-xs text-warn">
            <Shield size={12} /> The signature was not verified — this only decodes the claims. Never trust a JWT&apos;s contents without checking its signature against the issuer&apos;s key.
          </p>
        </>
      )}
    </div>
  );
}

function JsonTool() {
  const [input, setInput] = useState('{\n  "example": true,\n  "nested": { "a": 1, "b": [1, 2, 3] }\n}');
  const result = useMemo(() => {
    try {
      const parsed = JSON.parse(input);
      return { ok: true as const, pretty: JSON.stringify(parsed, null, 2), minified: JSON.stringify(parsed) };
    } catch (e) {
      return { ok: false as const, error: (e as Error).message };
    }
  }, [input]);
  return (
    <div className="flex flex-col gap-4">
      <textarea className="input mono min-h-[160px] text-[12px]" value={input} onChange={(e) => setInput(e.target.value)} aria-label="JSON input" spellCheck={false} />
      {result.ok ? (
        <>
          <Output label="Formatted" value={result.pretty} />
          <Output label="Minified" value={result.minified} />
        </>
      ) : (
        <ErrorNote title="Invalid JSON">{result.error}</ErrorNote>
      )}
    </div>
  );
}

function CertTool() {
  const [pem, setPem] = useState("");
  const certs = useMemo(() => {
    if (!/-----BEGIN CERTIFICATE-----/.test(pem)) return null;
    try {
      return certificatesFromPem(pem);
    } catch {
      return [];
    }
  }, [pem]);
  return (
    <div className="flex flex-col gap-4">
      <textarea className="input mono min-h-[140px] text-[12px]" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" value={pem} onChange={(e) => setPem(e.target.value)} aria-label="PEM certificate" spellCheck={false} />
      {certs === null && pem.trim() && <p className="text-sm text-fg-3">Paste one or more PEM certificates (-----BEGIN CERTIFICATE-----).</p>}
      {certs?.length === 0 && <ErrorNote title="Could not parse">The input did not parse as a valid X.509 certificate.</ErrorNote>}
      {certs && certs.length > 0 && (
        <div className="flex flex-col gap-3">
          {certs.map((c, i) => (
            <dl key={i} className="grid overflow-hidden rounded-[2px] border border-line-1 sm:grid-cols-2">
              {Object.entries({ Subject: c.subject.text, Issuer: c.issuer.text, Serial: c.serial, "Valid from": c.notBefore ?? "?", "Valid until": c.notAfter ?? "?", "Public key": `${c.publicKey.algorithm}${c.publicKey.bits ? ` ${c.publicKey.bits}-bit` : ""}${c.publicKey.curve ? ` ${c.publicKey.curve}` : ""}`, Signature: c.signatureAlgorithm, "Subject alt names": c.subjectAltNames.slice(0, 10).join(", ") || "—", "Self-issued": c.selfIssued ? "yes" : "no" }).map(([k, v]) => (
                <div key={k} className="flex items-baseline justify-between gap-3 border-b border-line-1 px-3 py-2 sm:odd:border-r">
                  <dt className="text-xs text-fg-3">{k}</dt>
                  <dd className="mono text-right text-[12px] break-all text-fg-1">{v}</dd>
                </div>
              ))}
            </dl>
          ))}
        </div>
      )}
      <p className="text-xs text-fg-4">Parsed only — the signature and chain of trust are not verified.</p>
    </div>
  );
}

const TCP_FLAGS_REF = [
  { bit: "FIN", value: "0x01", meaning: "No more data from sender; graceful connection close." },
  { bit: "SYN", value: "0x02", meaning: "Synchronise sequence numbers; sent to start a connection." },
  { bit: "RST", value: "0x04", meaning: "Reset the connection, usually after an error or a closed port." },
  { bit: "PSH", value: "0x08", meaning: "Push buffered data to the application without waiting." },
  { bit: "ACK", value: "0x10", meaning: "The Acknowledgment field is significant." },
  { bit: "URG", value: "0x20", meaning: "The Urgent pointer field is significant." },
  { bit: "ECE", value: "0x40", meaning: "ECN-Echo: explicit congestion notification received (or, in a SYN, ECN-capable)." },
  { bit: "CWR", value: "0x80", meaning: "Congestion Window Reduced, acknowledging an ECE." },
];
const HTTP_STATUS_REF = [
  ["200", "OK"], ["201", "Created"], ["202", "Accepted"], ["204", "No Content"],
  ["301", "Moved Permanently"], ["302", "Found"], ["303", "See Other"], ["304", "Not Modified"], ["307", "Temporary Redirect"], ["308", "Permanent Redirect"],
  ["400", "Bad Request"], ["401", "Unauthorized"], ["403", "Forbidden"], ["404", "Not Found"], ["405", "Method Not Allowed"], ["408", "Request Timeout"], ["409", "Conflict"], ["410", "Gone"], ["429", "Too Many Requests"],
  ["500", "Internal Server Error"], ["501", "Not Implemented"], ["502", "Bad Gateway"], ["503", "Service Unavailable"], ["504", "Gateway Timeout"],
] as const;
const PORTS_REF = [
  ["20/21", "FTP"], ["22", "SSH"], ["23", "Telnet"], ["25", "SMTP"], ["53", "DNS"], ["67/68", "DHCP"], ["69", "TFTP"], ["80", "HTTP"], ["88", "Kerberos"], ["110", "POP3"], ["123", "NTP"], ["135", "MS-RPC"],
  ["137-139", "NetBIOS"], ["143", "IMAP"], ["161/162", "SNMP"], ["389", "LDAP"], ["443", "HTTPS"], ["445", "SMB"], ["465", "SMTPS"], ["514", "Syslog"], ["587", "SMTP submission"], ["636", "LDAPS"], ["853", "DNS over TLS"],
  ["993", "IMAPS"], ["995", "POP3S"], ["1433", "MSSQL"], ["1521", "Oracle DB"], ["2049", "NFS"], ["3306", "MySQL"], ["3389", "RDP"], ["5060/5061", "SIP"], ["5432", "PostgreSQL"], ["5900", "VNC"], ["5985/5986", "WinRM"], ["6379", "Redis"], ["8080", "HTTP alt"], ["9200", "Elasticsearch"], ["27017", "MongoDB"],
] as const;
const PROTOCOLS_REF = [
  ["1", "ICMP"], ["2", "IGMP"], ["6", "TCP"], ["17", "UDP"], ["41", "IPv6 encapsulation"], ["47", "GRE"], ["50", "ESP"], ["51", "AH"], ["58", "ICMPv6"], ["89", "OSPF"], ["132", "SCTP"],
] as const;

function ReferenceTool() {
  const [tab, setTab] = useState<"tcp" | "http" | "ports" | "proto">("tcp");
  return (
    <div className="flex flex-col gap-4">
      <div className="inline-flex flex-wrap gap-1.5" role="tablist" aria-label="Reference table">
        {([["tcp", "TCP flags"], ["http", "HTTP status"], ["ports", "Common ports"], ["proto", "IP protocol numbers"]] as const).map(([id, label]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)} className={cx("btn btn-sm", tab === id ? "btn-primary" : "btn-ghost")}>
            {label}
          </button>
        ))}
      </div>
      {tab === "tcp" && (
        <div className="overflow-hidden rounded-[2px] border border-line-1">
          <table className="table">
            <thead><tr><th>Flag</th><th>Bit</th><th>Meaning</th></tr></thead>
            <tbody>{TCP_FLAGS_REF.map((f) => (<tr key={f.bit}><td className="mono text-fg-1">{f.bit}</td><td className="mono text-fg-3">{f.value}</td><td className="text-fg-2">{f.meaning}</td></tr>))}</tbody>
          </table>
        </div>
      )}
      {tab === "http" && (
        <div className="grid gap-px overflow-hidden rounded-[2px] bg-line-1 sm:grid-cols-2 lg:grid-cols-3">
          {HTTP_STATUS_REF.map(([code, text]) => (
            <div key={code} className="bg-ink-0 px-3 py-2 text-sm"><span className="mono text-fg-1">{code}</span> <span className="text-fg-3">{text}</span></div>
          ))}
        </div>
      )}
      {tab === "ports" && (
        <div className="grid gap-px overflow-hidden rounded-[2px] bg-line-1 sm:grid-cols-2 lg:grid-cols-3">
          {PORTS_REF.map(([port, svc]) => (
            <div key={port} className="bg-ink-0 px-3 py-2 text-sm"><span className="mono text-fg-1">{port}</span> <span className="text-fg-3">{svc}</span></div>
          ))}
        </div>
      )}
      {tab === "proto" && (
        <div className="grid gap-px overflow-hidden rounded-[2px] bg-line-1 sm:grid-cols-2 lg:grid-cols-3">
          {PROTOCOLS_REF.map(([n, name]) => (
            <div key={n} className="bg-ink-0 px-3 py-2 text-sm"><span className="mono text-fg-1">{n}</span> <span className="text-fg-3">{name}</span></div>
          ))}
        </div>
      )}
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
        {tool === "ipv6" && <Ipv6Tool />}
        {tool === "mac" && <MacTool />}
        {tool === "url" && <UrlParseTool />}
        {tool === "jwt" && <JwtTool />}
        {tool === "json" && <JsonTool />}
        {tool === "cert" && <CertTool />}
        {tool === "ref" && <ReferenceTool />}
      </section>
    </div>
  );
}

