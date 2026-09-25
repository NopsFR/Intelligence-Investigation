"use client";

import { Download, Library, Network, RotateCcw, ShieldCheck } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { MAX_CAPTURE_BYTES, type CaptureReport } from "@/lib/pcap/analyze";
import { api } from "@/lib/client/api";
import { useInvestigate } from "@/lib/client/investigate";
import { useSession } from "@/lib/client/session";
import { useWorker } from "@/lib/client/worker";
import { SEVERITY_COLOR, TypeTag } from "@/components/ui/badges";
import { Tabs, useToast } from "@/components/ui/overlays";
import { Bars, ErrorNote, Panel, Stat } from "@/components/ui/primitives";
import { FileDrop, formatBytes } from "@/components/ui/workbench";
import { CertificateCard } from "../CertificateCard";
import { Chip, DataTable, LocalFindings, Mono, downloadJson } from "../common";
import { ConversationMap } from "./ConversationMap";
import { FollowStream, PacketsView, type PcapCall } from "./PacketsView";

const createWorker = () => new Worker(new URL("../../../lib/pcap/pcap.worker.ts", import.meta.url), { type: "module" });

type State = { phase: "idle" } | { phase: "working"; name: string } | { phase: "done"; report: CaptureReport } | { phase: "error"; name: string; message: string };

function dur(s: number) {
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export function PcapAnalysis() {
  const [state, setState] = useState<State>({ phase: "idle" });
  const post = useWorker<Record<string, unknown>, Record<string, unknown>>(createWorker);
  const call = useCallback(<T,>(payload: Record<string, unknown>) => post(payload) as Promise<T>, [post]) as PcapCall;

  const onFile = useCallback(
    async (file: File) => {
      setState({ phase: "working", name: file.name });
      try {
        const res = await call<{ report: CaptureReport }>({ op: "load", file });
        setState({ phase: "done", report: res.report });
      } catch (err) {
        setState({ phase: "error", name: file.name, message: err instanceof Error ? err.message : String(err) });
      }
    },
    [call]
  );

  if (state.phase !== "done") {
    return (
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="flex flex-col gap-3">
          <FileDrop
            onFile={(f) => void onFile(f)}
            accept=".pcap,.pcapng,.cap,.dmp,application/vnd.tcpdump.pcap"
            maxBytes={MAX_CAPTURE_BYTES}
            busy={state.phase === "working"}
            title={state.phase === "working" ? `Dissecting ${state.name}` : "Drop a packet capture"}
            description="pcap or pcapng from Wireshark, tcpdump, dumpcap or a sensor. Ethernet, Linux cooked, loopback and raw IP link types."
          />
          {state.phase === "error" && <ErrorNote title={`Could not read ${state.name}`}>{state.message}</ErrorNote>}
        </div>
        <Panel title="What you get">
          <ul className="flex flex-col gap-2.5 text-sm text-fg-2">
            <li className="flex gap-2.5">
              <ShieldCheck size={15} className="mt-0.5 shrink-0 text-ok" />
              <span>Parsed in a browser worker. The capture never leaves this machine.</span>
            </li>
            <li className="flex gap-2.5">
              <Network size={15} className="mt-0.5 shrink-0 text-fg-3" />
              <span>Conversations with TCP reassembly, DNS, HTTP (objects hashed), TLS with SNI, certificates, JA3 / JA3S / JA4, DHCP and ARP.</span>
            </li>
            <li className="flex gap-2.5">
              <Library size={15} className="mt-0.5 shrink-0 text-fg-3" />
              <span>Findings for cleartext credentials, executable downloads, beaconing, scanning, DNS tunnelling and certificate problems — each with the frames that show it.</span>
            </li>
          </ul>
          <p className="mt-4 text-xs text-fg-4">Passwords, cookies and tokens are masked in dissections, streams, findings and reports. The hex view shows the raw bytes of your own file.</p>
        </Panel>
      </div>
    );
  }
  return <CaptureWorkspace report={state.report} call={call} reset={() => setState({ phase: "idle" })} />;
}

function CaptureWorkspace({ report: r, call, reset }: { report: CaptureReport; call: PcapCall; reset: () => void }) {
  const [tab, setTab] = useState("overview");
  const [filter, setFilter] = useState("");
  const [follow, setFollow] = useState<number | null>(null);
  const { start, pending } = useInvestigate();
  const operator = useSession().session?.operator ?? false;
  const toast = useToast();
  const worst = r.findings[0]?.severity;
  const duration = r.end - r.start;
  const external = r.endpoints.filter((e) => e.public).length;
  const findings = useMemo(() => r.findings.map((f) => ({ ...f, evidence: f.frames?.length ? [...f.evidence, `frames: ${f.frames.slice(0, 12).join(", ")}${f.frames.length > 12 ? " …" : ""}`] : f.evidence })), [r.findings]);

  const importIocs = async () => {
    const entries = r.indicators.filter((i) => i.type !== "URL" || i.value.length < 2000).slice(0, 500).map((i) => ({ value: i.value, type: i.type, tags: ["pcap"], notes: `${r.name}: ${i.sources.join(", ")}` }));
    try {
      const res = await api<{ created: number; updated: number; rejected: string[] }>("/api/ioc", { method: "POST", json: { entries, source: `pcap:${r.name}`.slice(0, 200) } });
      toast({ kind: "success", title: "Indicators added to the IOC library", body: `${res.created} new, ${res.updated} updated${res.rejected.length ? `, ${res.rejected.length} rejected` : ""}.` });
    } catch (err) {
      toast({ kind: "error", title: "Could not add indicators", body: err instanceof Error ? err.message : String(err) });
    }
  };

  const tabs = [
    { id: "overview", label: "Overview", count: r.findings.length },
    { id: "packets", label: "Packets", count: r.packets },
    { id: "conversations", label: "Conversations", count: r.flows.length },
    { id: "dns", label: "DNS", count: r.dns.length },
    { id: "http", label: "HTTP", count: r.http.length },
    { id: "tls", label: "TLS", count: r.tls.length },
    { id: "hosts", label: "Hosts", count: r.endpoints.length },
    { id: "indicators", label: "Indicators", count: r.indicators.length },
  ];

  return (
    <div className="flex flex-col gap-4">
      <section className="panel panel-ticks animate-rise">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-3 border-b border-line-1 p-[var(--panel-pad)]">
          <div className="min-w-0 flex-1">
            <div className="label mb-1">Packet capture · {r.durationMs} ms · local</div>
            <h2 className="display truncate text-xl text-fg-1">{r.name}</h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-fg-3">
              <Chip tone="ice">{r.format}</Chip>
              {r.linkTypes.map((l) => (
                <Chip key={l}>{l}</Chip>
              ))}
              <span>{formatBytes(r.size)}</span>
              {r.start > 0 && <span className="mono">{new Date(r.start * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC</span>}
              {r.interfaces.length > 0 && <span>on {r.interfaces.join(", ")}</span>}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn" onClick={() => downloadJson(`${r.name}.analysis.json`, { ...r, rows: undefined })}>
              <Download size={14} /> Report
            </button>
            <button type="button" className="btn btn-ghost" onClick={reset}>
              <RotateCcw size={14} /> Another capture
            </button>
          </div>
        </div>
        <div className="grid gap-px bg-line-1 sm:grid-cols-2 xl:grid-cols-5">
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Highest finding" value={worst ? <span style={{ color: SEVERITY_COLOR[worst] }}>{worst[0] + worst.slice(1).toLowerCase()}</span> : "None"} sub={`${r.findings.length} findings`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Packets" value={<span className="tabular">{r.packets.toLocaleString()}</span>} sub={`${formatBytes(r.bytes)} on the wire${r.truncated ? " · capped" : ""}`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Duration" value={dur(duration)} sub={r.packets > 1 ? `${(r.packets / Math.max(duration, 0.001)).toFixed(1)} packets/s` : "single packet"} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Conversations" value={<span className="tabular">{r.flows.length.toLocaleString()}</span>} sub={`${r.tls.length} TLS · ${r.http.length} HTTP · ${r.dns.length} DNS`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Public hosts" value={<span className="tabular">{external}</span>} sub={`${r.indicators.length} indicators extracted`} />
          </div>
        </div>
      </section>

      <section className="panel">
        <Tabs items={tabs} value={tab} onChange={setTab} label="Capture sections" className="px-2" />
        <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} key={tab} className="animate-fade">
          {tab === "overview" && (
            <div className="grid gap-px bg-line-1 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
              <div className="bg-ink-1">
                <LocalFindings findings={findings} empty="No rule matched this traffic. Absence of findings is not proof of absence — check the conversations and indicators." />
              </div>
              <div className="flex flex-col gap-5 bg-ink-1 p-[var(--panel-pad)]">
                <div>
                  <h3 className="label mb-2">Traffic over time</h3>
                  <Bars values={r.timeline.map((b) => b.packets)} labels={r.timeline.map((b) => `+${dur(b.t)}: ${b.packets} packets, ${formatBytes(b.bytes)}`)} height={64} highlightLast={false} />
                  <div className="mono mt-1 flex justify-between text-[10.5px] text-fg-4">
                    <span>0</span>
                    <span>{dur(duration)}</span>
                  </div>
                </div>
                <div>
                  <h3 className="label mb-2">Protocols</h3>
                  <ul className="flex flex-col gap-1">
                    {r.protocols.slice(0, 12).map((p) => (
                      <li key={p.name} className="grid grid-cols-[110px_minmax(0,1fr)_64px] items-center gap-3 text-xs">
                        <span className="mono truncate text-fg-1">{p.name}</span>
                        <span className="h-[5px] rounded-[1px] bg-ink-3">
                          <span className="block h-full rounded-[1px] bg-ice" style={{ width: `${(p.packets / r.packets) * 100}%` }} />
                        </span>
                        <span className="mono text-right text-fg-3 tabular">{p.packets.toLocaleString()}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3 className="label mb-2">Service ports</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {r.ports.slice(0, 20).map((p) => (
                      <Chip key={`${p.transport}${p.port}`} title={`${p.flows} conversations`}>
                        {`${p.transport.toLowerCase()}/${p.port}${p.name ? ` ${p.name}` : ""} · ${p.flows}`}
                      </Chip>
                    ))}
                  </div>
                </div>
              </div>
              <div className="bg-ink-1 p-[var(--panel-pad)] xl:col-span-2">
                <h3 className="label mb-2">Conversation map</h3>
                <ConversationMap report={r} />
              </div>
            </div>
          )}
          {tab === "packets" && <PacketsView report={r} call={call} filter={filter} setFilter={setFilter} onFollow={setFollow} />}
          {tab === "conversations" && (
            <DataTable
              rows={r.flows}
              columns={[
                { key: "id", label: "Stream", render: (f) => <button type="button" className="mono link text-[12px]" onClick={() => setFollow(f.id)}>{f.id}</button>, sort: (f) => f.id },
                { key: "t", label: "Proto", render: (f) => <Mono>{f.transport}</Mono> },
                { key: "c", label: "Client", render: (f) => <Mono className="text-fg-1">{`${f.client}:${f.clientPort}`}</Mono>, sort: (f) => f.client },
                { key: "s", label: "Server", render: (f) => <Mono className="text-fg-1">{`${f.server}:${f.serverPort}`}</Mono>, sort: (f) => f.server },
                { key: "a", label: "Application", render: (f) => <span className="flex items-center gap-1.5"><Mono>{f.app}</Mono>{(f.sni ?? f.host) && <span className="truncate text-xs text-fg-3">{f.sni ?? f.host}</span>}</span> },
                { key: "p", label: "Packets", render: (f) => <Mono>{f.packets}</Mono>, sort: (f) => f.packets, className: "text-right" },
                { key: "b", label: "Bytes ↑ / ↓", render: (f) => <Mono>{`${formatBytes(f.clientBytes)} / ${formatBytes(f.serverBytes)}`}</Mono>, sort: (f) => f.bytes, className: "text-right" },
                { key: "d", label: "Duration", render: (f) => <Mono>{dur(f.end - f.start)}</Mono>, sort: (f) => f.end - f.start, className: "text-right" },
                { key: "st", label: "State", render: (f) => <Mono className="text-fg-3">{f.transport === "TCP" ? [f.syn && "SYN", f.synAck && "SYN-ACK", f.fin && "FIN", f.rst && "RST"].filter(Boolean).join(" ") : ""}</Mono> },
              ]}
            />
          )}
          {tab === "dns" && (
            <DataTable
              rows={r.dns}
              empty="No DNS in this capture."
              columns={[
                { key: "f", label: "Frame", render: (q) => <Mono className="text-fg-4">{q.frame}</Mono>, sort: (q) => q.frame },
                { key: "c", label: "Client → server", render: (q) => <Mono>{`${q.client} → ${q.server}`}</Mono> },
                { key: "n", label: "Query", render: (q) => <Mono className="break-all text-fg-1">{q.name}</Mono>, sort: (q) => q.name },
                { key: "t", label: "Type", render: (q) => <Mono>{q.type}</Mono>, sort: (q) => q.type },
                { key: "r", label: "Result", render: (q) => (q.rcode === undefined ? <span className="text-xs text-fg-4">no response</span> : q.rcode !== "NOERROR" ? <Chip tone={q.rcode === "NXDOMAIN" ? "warn" : "err"}>{q.rcode}</Chip> : <Mono className="break-all text-fg-2">{q.answers.slice(0, 4).join(", ") || "(empty)"}</Mono>) },
                { key: "l", label: "Latency", render: (q) => (q.latencyMs !== undefined ? <Mono>{q.latencyMs} ms</Mono> : ""), sort: (q) => q.latencyMs ?? -1, className: "text-right" },
              ]}
            />
          )}
          {tab === "http" && (
            <DataTable
              rows={r.http}
              empty="No cleartext HTTP in this capture."
              columns={[
                { key: "s", label: "Stream", render: (h) => <button type="button" className="mono link text-[12px]" onClick={() => setFollow(h.stream)}>{h.stream}</button> },
                { key: "m", label: "Request", render: (h) => <Mono className="break-all text-fg-1">{`${h.method} ${h.url}`}</Mono>, sort: (h) => h.url },
                { key: "st", label: "Status", render: (h) => <Mono className={h.status && h.status >= 400 ? "text-warn" : ""}>{h.status ?? "—"}</Mono>, sort: (h) => h.status ?? 0 },
                { key: "ua", label: "User agent", render: (h) => <span className="text-xs text-fg-3">{h.userAgent ?? "(none)"}</span> },
                { key: "b", label: "Response body", render: (h) => (h.body ? <span className="flex flex-wrap items-center gap-1.5"><Chip tone={h.body.type.family === "executable" ? "err" : h.body.type.family === "script" ? "warn" : "neutral"}>{h.body.type.label}</Chip><Mono className="text-fg-3">{formatBytes(h.body.size)}</Mono></span> : <span className="text-xs text-fg-4">{h.contentType ?? ""}</span>) },
                {
                  key: "h",
                  label: "SHA-256",
                  render: (h) =>
                    h.body?.sha256 ? (
                      <button type="button" className="mono link text-[11px]" disabled={pending} title="Investigate this hash" onClick={() => void start(h.body!.sha256!, "QUICK", { type: "SHA256" })}>
                        {h.body.sha256.slice(0, 16)}…
                      </button>
                    ) : h.body ? (
                      <span className="text-xs text-fg-4">incomplete</span>
                    ) : (
                      ""
                    ),
                },
                { key: "a", label: "Auth", render: (h) => (h.authorization ? <Chip tone="err">{h.authorization}</Chip> : "") },
              ]}
            />
          )}
          {tab === "tls" && <TlsView report={r} onFollow={setFollow} />}
          {tab === "hosts" && <HostsView report={r} />}
          {tab === "indicators" && (
            <div>
              <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-3 py-2">
                <p className="text-xs text-fg-3">Public addresses, domains, URLs and transferred-file hashes. Private addresses and local names are excluded.</p>
                <button type="button" className="btn btn-sm ml-auto" disabled={!operator || !r.indicators.length} title={operator ? undefined : "Unlock an operator session to write to the IOC library"} onClick={() => void importIocs()}>
                  <Library size={13} /> Add all to IOC library
                </button>
              </div>
              <DataTable
                rows={r.indicators}
                empty="No public indicators in this capture."
                columns={[
                  { key: "t", label: "Type", render: (i) => <TypeTag type={i.type} /> },
                  { key: "v", label: "Indicator", render: (i) => <Mono className="break-all text-fg-1">{i.value}</Mono>, sort: (i) => i.value },
                  { key: "s", label: "Seen in", render: (i) => <span className="text-xs text-fg-3">{i.sources.join(", ")}</span> },
                  { key: "n", label: "Count", render: (i) => <Mono>{i.count}</Mono>, sort: (i) => i.count, className: "text-right" },
                  { key: "f", label: "First frame", render: (i) => <Mono className="text-fg-4">{i.firstFrame}</Mono>, sort: (i) => i.firstFrame },
                  { key: "a", label: "", render: (i) => <button type="button" className="btn btn-ghost btn-sm" disabled={pending} onClick={() => void start(i.value, "QUICK", { type: i.type })}>Investigate</button> },
                ]}
              />
            </div>
          )}
        </div>
      </section>
      <FollowStream stream={follow} call={call} onClose={() => setFollow(null)} />
    </div>
  );
}

function TlsView({ report: r, onFollow }: { report: CaptureReport; onFollow: (s: number) => void }) {
  const [open, setOpen] = useState<number | null>(null);
  if (!r.tls.length) return <p className="px-3 py-6 text-sm text-fg-3">No TLS handshakes in this capture.</p>;
  const ja4Counts = r.tls.reduce<Record<string, number>>((m, t) => ((m[t.ja4] = (m[t.ja4] ?? 0) + 1), m), {});
  return (
    <div>
      <div className="border-b border-line-1 px-3 py-2">
        <h3 className="label mb-1.5">Client fingerprints</h3>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(ja4Counts)
            .sort((a, b) => b[1] - a[1])
            .map(([j, n]) => (
              <Chip key={j} title="JA4 client fingerprint">{`${j} × ${n}`}</Chip>
            ))}
        </div>
      </div>
      <ul className="divide-y divide-line-1">
        {r.tls.map((t, i) => (
          <li key={i}>
            <button type="button" className="grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-3 py-2.5 text-left hover:bg-ink-2" onClick={() => setOpen(open === i ? null : i)} aria-expanded={open === i}>
              <span className="min-w-0">
                <span className="block truncate text-sm text-fg-1">{t.sni ?? <span className="text-fg-3">(no SNI) {t.server}</span>}</span>
                <span className="mono mt-0.5 block truncate text-[11px] text-fg-3">
                  {t.client} → {t.server}:{t.serverPort} · {t.version ?? `offered ${t.offeredVersions.join("/")}`} · {t.cipher ?? "no ServerHello"} · {t.alpn.join(",") || "no ALPN"}
                </span>
              </span>
              <span className="flex flex-wrap items-center justify-end gap-1.5">
                {t.certificates[0]?.selfIssued && <Chip tone="warn">self-signed</Chip>}
                {t.ech && <Chip tone="ice">ECH</Chip>}
                {t.alerts.length > 0 && <Chip tone="err">alert</Chip>}
              </span>
            </button>
            {open === i && (
              <div className="flex flex-col gap-3 bg-ink-0/40 px-3 pb-4">
                <dl className="mono grid gap-x-4 gap-y-1 text-[11.5px] sm:grid-cols-[80px_minmax(0,1fr)]">
                  <dt className="text-fg-4">JA4</dt>
                  <dd className="text-fg-1">{t.ja4}</dd>
                  <dt className="text-fg-4">JA3</dt>
                  <dd className="break-all text-fg-1">
                    {t.ja3Hash} <span className="text-fg-4">{t.ja3}</span>
                  </dd>
                  {t.ja3sHash && (
                    <>
                      <dt className="text-fg-4">JA3S</dt>
                      <dd className="text-fg-1">{t.ja3sHash}</dd>
                    </>
                  )}
                  {t.alerts.length > 0 && (
                    <>
                      <dt className="text-fg-4">Alerts</dt>
                      <dd className="text-err">{t.alerts.join(", ")}</dd>
                    </>
                  )}
                </dl>
                <div className="flex gap-2">
                  <button type="button" className="btn btn-sm" onClick={() => onFollow(t.stream)}>
                    Follow stream {t.stream}
                  </button>
                </div>
                {t.certificates.length ? (
                  <div className="grid gap-3 lg:grid-cols-2">
                    {t.certificates.map((c, k) => (
                      <CertificateCard key={k} cert={c} role={k === 0 ? "Leaf" : `Chain ${k}`} now={r.end * 1000} />
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-fg-3">{t.version === "TLS 1.3" ? "TLS 1.3 encrypts the certificate; it is not visible in the capture." : "No certificate message captured."}</p>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function HostsView({ report: r }: { report: CaptureReport }) {
  return (
    <div className="grid gap-px bg-line-1 xl:grid-cols-2">
      <div className="bg-ink-1">
        <h3 className="label px-3 pt-3">Endpoints</h3>
        <DataTable
          rows={r.endpoints}
          columns={[
            { key: "a", label: "Address", render: (e) => <span className="flex items-center gap-2"><Mono className="text-fg-1">{e.address}</Mono>{e.public && <Chip tone="warn">public</Chip>}</span>, sort: (e) => e.address },
            { key: "p", label: "Packets", render: (e) => <Mono>{e.packets.toLocaleString()}</Mono>, sort: (e) => e.packets, className: "text-right" },
            { key: "b", label: "Bytes", render: (e) => <Mono>{formatBytes(e.bytes)}</Mono>, sort: (e) => e.bytes, className: "text-right" },
          ]}
        />
      </div>
      <div className="flex flex-col gap-px bg-line-1">
        <div className="bg-ink-1">
          <h3 className="label px-3 pt-3">DHCP</h3>
          <DataTable
            rows={r.dhcp}
            empty="No DHCP."
            columns={[
              { key: "f", label: "Frame", render: (d) => <Mono className="text-fg-4">{d.frame}</Mono> },
              { key: "t", label: "Message", render: (d) => <Mono>{d.type ?? "?"}</Mono> },
              { key: "c", label: "Client MAC", render: (d) => <Mono>{d.client}</Mono> },
              { key: "h", label: "Host name", render: (d) => <Mono className="text-fg-1">{d.hostname ?? ""}</Mono> },
              { key: "v", label: "Vendor class", render: (d) => <span className="text-xs text-fg-3">{d.vendorClass ?? ""}</span> },
              { key: "i", label: "Requested / server", render: (d) => <Mono>{[d.requestedIp, d.server].filter(Boolean).join(" / ")}</Mono> },
            ]}
          />
        </div>
        <div className="bg-ink-1">
          <h3 className="label px-3 pt-3">ARP bindings</h3>
          <DataTable
            rows={r.arp}
            empty="No ARP."
            columns={[
              { key: "i", label: "IP", render: (a) => <Mono className="text-fg-1">{a.ip}</Mono>, sort: (a) => a.ip },
              { key: "m", label: "MAC addresses", render: (a) => <span className="flex flex-wrap gap-1">{a.macs.map((m) => <Chip key={m} tone={a.macs.length > 1 ? "err" : "neutral"}>{m}</Chip>)}</span> },
            ]}
          />
        </div>
      </div>
    </div>
  );
}
