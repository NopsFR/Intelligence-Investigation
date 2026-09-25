import type { Certificate } from "@/lib/analysis/der";
import { identify, type FileType } from "@/lib/analysis/magic";
import { entropy } from "@/lib/analysis/bytes";
import type { ObservableType, Severity } from "@/lib/core/types";
import { isPublicAddress } from "@/lib/observables/ip";
import { registrableDomain } from "@/lib/observables/detect";
import { readCapture, type CaptureFile, LINK_TYPES } from "./capture";
import { dissect, WELL_KNOWN_PORTS, maskSecretHeader, type Dissection } from "./dissect";
import { header, parseHttpStream } from "./proto/http";
import { ALERTS, CIPHER_NAMES, TLS_VERSIONS, parseTlsStream } from "./proto/tls";

// Whole-capture analysis: flows and TCP reassembly, application transactions
// (DNS, HTTP, TLS, DHCP), statistics, indicators and evidence-backed findings.

export const MAX_CAPTURE_BYTES = 150 * 1024 * 1024;
const MAX_ROWS = 250_000;
const REASSEMBLY_PER_DIRECTION = 2 * 1024 * 1024;
const REASSEMBLY_TOTAL = 96 * 1024 * 1024;

export interface PacketRow {
  n: number;
  t: number;
  len: number;
  src: string;
  dst: string;
  proto: string;
  info: string;
  stream?: number;
  mark?: "syn" | "rst" | "err" | "dns" | "tls" | "http" | "icmp" | "arp" | "dhcp";
}

export interface Flow {
  id: number;
  transport: string;
  client: string;
  server: string;
  clientPort?: number;
  serverPort?: number;
  packets: number;
  bytes: number;
  clientBytes: number;
  serverBytes: number;
  start: number;
  end: number;
  app: string;
  syn: boolean;
  synAck: boolean;
  rst: boolean;
  fin: boolean;
  firstFrame: number;
  sni?: string;
  host?: string;
}

export interface DnsTx {
  frame: number;
  t: number;
  client: string;
  server: string;
  name: string;
  type: string;
  rcode?: string;
  answers: string[];
  latencyMs?: number;
}

export interface HttpTx {
  frame: number;
  t: number;
  stream: number;
  client: string;
  server: string;
  serverPort: number;
  method: string;
  host: string;
  uri: string;
  url: string;
  userAgent?: string;
  referer?: string;
  authorization?: string;
  status?: number;
  contentType?: string;
  responseLength?: number;
  body?: { type: FileType; sha256?: string; complete: boolean; entropy: number; size: number };
}

export interface TlsSession {
  frame: number;
  t: number;
  stream: number;
  client: string;
  server: string;
  serverPort: number;
  sni?: string;
  alpn: string[];
  offeredVersions: string[];
  version?: string;
  cipher?: string;
  ja3: string;
  ja3Hash: string;
  ja4: string;
  ja3sHash?: string;
  ech: boolean;
  certificates: Certificate[];
  alerts: string[];
}

export interface TrafficFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: string[];
  attack?: string[];
  basis: "traffic" | "heuristic";
  frames?: number[];
}

export interface Indicator {
  value: string;
  type: ObservableType;
  sources: string[];
  count: number;
  firstFrame: number;
}

export interface CaptureReport {
  name: string;
  size: number;
  format: string;
  linkTypes: string[];
  interfaces: string[];
  comments: string[];
  errors: string[];
  truncated: boolean;
  packets: number;
  bytes: number;
  start: number;
  end: number;
  rows: PacketRow[];
  rowsTruncated: boolean;
  flows: Flow[];
  dns: DnsTx[];
  http: HttpTx[];
  tls: TlsSession[];
  dhcp: { frame: number; type?: string; client: string; hostname?: string; vendorClass?: string; requestedIp?: string; server?: string; fingerprint?: string }[];
  arp: { ip: string; macs: string[]; frames: number[] }[];
  endpoints: { address: string; packets: number; bytes: number; public: boolean }[];
  protocols: { name: string; packets: number; bytes: number }[];
  ports: { port: number; transport: string; flows: number; name?: string }[];
  timeline: { t: number; packets: number; bytes: number }[];
  indicators: Indicator[];
  credentials: { frame: number; protocol: string; client: string; server: string; user?: string; detail: string }[];
  findings: TrafficFinding[];
  durationMs: number;
}

interface FlowState extends Flow {
  segs: [{ seq: number; data: Uint8Array }[], { seq: number; data: Uint8Array }[]];
  segBytes: [number, number];
  isn: [number | null, number | null];
  frames: number[];
}

function publicFlow(f: FlowState): Flow {
  const { id, transport, client, server, clientPort, serverPort, packets, bytes, clientBytes, serverBytes, start, end, app, syn, synAck, rst, fin, firstFrame, sni, host } = f;
  return { id, transport, client, server, clientPort, serverPort, packets, bytes, clientBytes, serverBytes, start, end, app, syn, synAck, rst, fin, firstFrame, sni, host };
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const endpointKey = (addr: string, port?: number) => (port === undefined ? addr : addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`);

function reassemble(segs: { seq: number; data: Uint8Array }[], isn: number | null): { data: Uint8Array; gaps: number } {
  if (!segs.length) return { data: new Uint8Array(0), gaps: 0 };
  const base = isn !== null ? (isn + 1) >>> 0 : segs.reduce((m, s) => (((s.seq - segs[0].seq) | 0) < ((m - segs[0].seq) | 0) ? s.seq : m), segs[0].seq);
  const rel = segs.map((s) => ({ off: (s.seq - base) | 0, data: s.data })).filter((s) => s.off > -65536).sort((a, b) => a.off - b.off);
  const total = rel.reduce((n, s) => Math.max(n, s.off + s.data.length), 0);
  const out = new Uint8Array(Math.max(0, Math.min(total, REASSEMBLY_PER_DIRECTION)));
  let cursor = 0;
  let gaps = 0;
  for (const s of rel) {
    if (s.off + s.data.length <= cursor) continue; // retransmission
    if (s.off > cursor) {
      gaps++;
      break;
    }
    const from = cursor - s.off;
    const chunk = s.data.subarray(from, Math.min(s.data.length, from + out.length - cursor));
    out.set(chunk, cursor);
    cursor += chunk.length;
    if (cursor >= out.length) break;
  }
  return { data: out.subarray(0, cursor), gaps };
}

async function sha256(b: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", b as unknown as BufferSource);
  return Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, "0")).join("");
}

function stdev(xs: number[]) {
  const m = xs.reduce((a, b) => a + b, 0) / xs.length;
  return { mean: m, sd: Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / xs.length) };
}

export async function analyzeCapture(bytes: Uint8Array, name: string, cap?: CaptureFile, collect?: { streams?: Map<number, number[]> }): Promise<CaptureReport> {
  const started = Date.now();
  const capture = cap ?? readCapture(bytes);
  const frames = capture.frames;
  const t0 = frames[0]?.ts ?? 0;
  const rows: PacketRow[] = [];
  const flows = new Map<string, FlowState>();
  const flowList: FlowState[] = [];
  const protocols = new Map<string, { packets: number; bytes: number }>();
  const endpoints = new Map<string, { packets: number; bytes: number }>();
  const dns: DnsTx[] = [];
  const pendingDns = new Map<string, DnsTx>();
  const dhcp: CaptureReport["dhcp"] = [];
  const arpMap = new Map<string, { macs: Set<string>; frames: number[] }>();
  const credentials: CaptureReport["credentials"] = [];
  const icmpBig: number[] = [];
  let totalBytes = 0;
  let reassembled = 0;

  const bump = <K>(m: Map<K, { packets: number; bytes: number }>, k: K, len: number) => {
    const e = m.get(k);
    if (e) {
      e.packets++;
      e.bytes += len;
    } else m.set(k, { packets: 1, bytes: len });
  };

  for (const f of frames) {
    const data = bytes.subarray(f.offset, f.offset + f.captured);
    const d: Dissection = dissect(data, f.linkType);
    const t = (f.ts - t0) / 1e6;
    totalBytes += f.original;
    bump(protocols, d.protocol, f.original);
    if (d.src && d.transport !== undefined && d.transport !== "ARP") {
      bump(endpoints, d.src, f.original);
      bump(endpoints, d.dst, f.original);
    }

    let stream: number | undefined;
    if ((d.transport === "TCP" || d.transport === "UDP") && d.srcPort !== undefined && d.dstPort !== undefined) {
      const a = endpointKey(d.src, d.srcPort);
      const b = endpointKey(d.dst, d.dstPort);
      const key = `${d.transport}|${a < b ? `${a}|${b}` : `${b}|${a}`}`;
      let fl = flows.get(key);
      const isSyn = d.tcp ? (d.tcp.flags & 0x12) === 0x02 : false;
      const isSynAck = d.tcp ? (d.tcp.flags & 0x12) === 0x12 : false;
      if (!fl) {
        // The first sender is the client unless the first packet is a SYN-ACK
        // (capture started mid-handshake) or ports make it obvious.
        let clientIsSrc = !isSynAck;
        if (!d.tcp || !isSyn) {
          const sKnown = WELL_KNOWN_PORTS[d.srcPort] !== undefined && d.srcPort < 1024;
          const dKnown = WELL_KNOWN_PORTS[d.dstPort] !== undefined && d.dstPort < 1024;
          if (sKnown && !dKnown) clientIsSrc = false;
          else if (!sKnown && dKnown) clientIsSrc = true;
          else if (!isSynAck) clientIsSrc = d.srcPort >= d.dstPort;
        }
        fl = {
          id: flowList.length,
          transport: d.transport,
          client: clientIsSrc ? d.src : d.dst,
          server: clientIsSrc ? d.dst : d.src,
          clientPort: clientIsSrc ? d.srcPort : d.dstPort,
          serverPort: clientIsSrc ? d.dstPort : d.srcPort,
          packets: 0,
          bytes: 0,
          clientBytes: 0,
          serverBytes: 0,
          start: t,
          end: t,
          app: "",
          syn: false,
          synAck: false,
          rst: false,
          fin: false,
          firstFrame: f.index,
          segs: [[], []],
          segBytes: [0, 0],
          isn: [null, null],
          frames: [],
        };
        flows.set(key, fl);
        flowList.push(fl);
      }
      stream = fl.id;
      const fromClient = d.src === fl.client && d.srcPort === fl.clientPort;
      fl.packets++;
      fl.bytes += f.original;
      if (fromClient) fl.clientBytes += f.original;
      else fl.serverBytes += f.original;
      fl.end = t;
      if (fl.frames.length < 50_000) fl.frames.push(f.index);
      if (!fl.app || fl.app === "TCP" || fl.app === "UDP") fl.app = d.protocol;
      d.fields.set("tcp.stream", [fl.id]);
      d.fields.set("udp.stream", [fl.id]);
      if (d.tcp) {
        const dir = fromClient ? 0 : 1;
        if (isSyn) {
          fl.syn = true;
          fl.isn[0] = d.tcp.seq;
        }
        if (isSynAck) {
          fl.synAck = true;
          fl.isn[1] = d.tcp.seq;
        }
        if (d.tcp.flags & 4) fl.rst = true;
        if (d.tcp.flags & 1) fl.fin = true;
        if (d.tcp.payloadLength && fl.segBytes[dir] < REASSEMBLY_PER_DIRECTION && reassembled < REASSEMBLY_TOTAL) {
          const payload = data.subarray(d.tcp.payloadOffset, d.tcp.payloadOffset + d.tcp.payloadLength);
          fl.segs[dir].push({ seq: d.tcp.seq, data: payload });
          fl.segBytes[dir] += payload.length;
          reassembled += payload.length;
        }
        // Cleartext authentication on mail / file transfer protocols (user names only).
        if (d.tcp.payloadLength && fromClient && [21, 110, 143, 25, 587, 23].includes(fl.serverPort!)) {
          const line = String.fromCharCode(...data.subarray(d.tcp.payloadOffset, d.tcp.payloadOffset + Math.min(d.tcp.payloadLength, 200))).split(/\r?\n/)[0];
          const user = /^USER\s+(\S+)/i.exec(line)?.[1] ?? /^\S+\s+LOGIN\s+"?([^"\s]+)/i.exec(line)?.[1];
          if (user) credentials.push({ frame: f.index, protocol: WELL_KNOWN_PORTS[fl.serverPort!] ?? "TCP", client: fl.client, server: fl.server, user, detail: "User name sent in cleartext; the password that follows is not displayed" });
          else if (/^(PASS\s|AUTH\s+(PLAIN|LOGIN))/i.test(line)) credentials.push({ frame: f.index, protocol: WELL_KNOWN_PORTS[fl.serverPort!] ?? "TCP", client: fl.client, server: fl.server, detail: "Password or AUTH exchange sent in cleartext (value not displayed)" });
        }
      }
    }

    if (d.dns) {
      const q = d.dns.questions[0];
      if (q) {
        const key = d.dns.response ? `${d.dst}|${d.src}|${d.dns.id}|${q.name}` : `${d.src}|${d.dst}|${d.dns.id}|${q.name}`;
        if (!d.dns.response) {
          const tx: DnsTx = { frame: f.index, t, client: d.src, server: d.dst, name: q.name, type: q.type, answers: [] };
          dns.push(tx);
          pendingDns.set(key, tx);
        } else {
          const tx = pendingDns.get(key);
          const answers = d.dns.answers.map((a) => `${a.type} ${a.data}`);
          if (tx) {
            tx.rcode = d.dns.rcode;
            tx.answers = answers;
            tx.latencyMs = Math.round((t - tx.t) * 1000);
            pendingDns.delete(key);
          } else dns.push({ frame: f.index, t, client: d.dst, server: d.src, name: q.name, type: q.type, rcode: d.dns.rcode, answers });
        }
      }
    }
    if (d.dhcp) dhcp.push({ frame: f.index, type: d.dhcp.messageType, client: d.dhcp.clientMac, hostname: d.dhcp.hostname, vendorClass: d.dhcp.vendorClass, requestedIp: d.dhcp.requestedIp, server: d.dhcp.serverId, fingerprint: d.dhcp.parameterList?.join(",") });
    if (d.arp && (d.arp.op === 2 || d.arp.op === 1) && d.arp.senderIp !== "0.0.0.0") {
      const e = arpMap.get(d.arp.senderIp) ?? { macs: new Set<string>(), frames: [] };
      e.macs.add(d.arp.senderMac);
      if (e.frames.length < 20) e.frames.push(f.index);
      arpMap.set(d.arp.senderIp, e);
    }
    if (d.icmp && d.icmp.payloadLength > 128 && (d.icmp.type === 8 || d.icmp.type === 0)) icmpBig.push(f.index);

    if (rows.length < MAX_ROWS) {
      const flags = d.tcp?.flags ?? 0;
      rows.push({
        n: f.index,
        t,
        len: f.original,
        src: d.src,
        dst: d.dst,
        proto: d.protocol,
        info: d.info,
        stream,
        mark: d.malformed ? "err" : flags & 4 ? "rst" : d.dns ? "dns" : d.protocol === "TLS" ? "tls" : d.protocol === "HTTP" ? "http" : d.icmp ? "icmp" : d.arp ? "arp" : d.dhcp ? "dhcp" : (flags & 0x12) === 2 ? "syn" : undefined,
      });
    }
  }

  // Application layer over reassembled streams.
  const http: HttpTx[] = [];
  const tls: TlsSession[] = [];
  for (const fl of flowList) {
    if (fl.transport !== "TCP") continue;
    let c = fl.segs[0].length ? reassemble(fl.segs[0], fl.isn[0]).data : new Uint8Array(0);
    let s = fl.segs[1].length ? reassemble(fl.segs[1], fl.isn[1]).data : new Uint8Array(0);
    if (c.length && c[0] >= 0x41 && c[0] <= 0x5a) {
      const reqs = parseHttpStream(c);
      if (reqs.length) {
        const resps = parseHttpStream(s).filter((m) => m.kind === "response");
        fl.app = "HTTP";
        for (const [i, req] of reqs.entries()) {
          if (req.kind !== "request") continue;
          const host = header(req, "host") ?? fl.server;
          fl.host = fl.host ?? host;
          const res = resps[i];
          const tx: HttpTx = {
            frame: fl.firstFrame,
            t: fl.start,
            stream: fl.id,
            client: fl.client,
            server: fl.server,
            serverPort: fl.serverPort!,
            method: req.method!,
            host,
            uri: req.uri!,
            url: /^https?:\/\//i.test(req.uri!) ? req.uri! : `http://${host}${req.uri!.startsWith("/") ? "" : "/"}${req.uri}`,
            userAgent: header(req, "user-agent"),
            referer: header(req, "referer"),
            authorization: header(req, "authorization") ? maskSecretHeader("authorization", header(req, "authorization")!) : undefined,
            status: res?.status,
            contentType: res ? header(res, "content-type") : undefined,
            responseLength: res?.bodyLength,
          };
          if (res && res.body.length >= 4 && req.method !== "CONNECT") {
            const type = identify(res.body);
            tx.body = { type, complete: res.bodyComplete && res.body.length === res.bodyLength, entropy: entropy(res.body), size: res.bodyLength };
            if (tx.body.complete) tx.body.sha256 = await sha256(res.body);
          }
          if (tx.authorization?.startsWith("Basic")) credentials.push({ frame: fl.firstFrame, protocol: "HTTP Basic", client: fl.client, server: `${host}`, user: /user "([^"]*)"/.exec(tx.authorization)?.[1], detail: "HTTP Basic credentials over cleartext HTTP (password not displayed)" });
          http.push(tx);
        }
        // An HTTP CONNECT tunnel carries TLS (or anything else) after the proxy's 200.
        if (reqs[0].method === "CONNECT" && resps[0]?.status === 200) {
          c = c.subarray(reqs[0].bodyOffset);
          s = s.subarray(resps[0].bodyOffset);
        }
      }
    }
    const tlsC = c.length && c[0] === 22 ? parseTlsStream(c) : null;
    if (tlsC?.clientHello) {
      const tlsS = s.length && (s[0] === 22 || s[0] === 21) ? parseTlsStream(s) : null;
      const ch = tlsC.clientHello;
      const sh = tlsS?.serverHello;
      const ver = sh ? (sh.selectedVersion ?? sh.version) : undefined;
      fl.app = "TLS";
      fl.sni = ch.sni;
      tls.push({
        frame: fl.firstFrame,
        t: fl.start,
        stream: fl.id,
        client: fl.client,
        server: fl.server,
        serverPort: fl.serverPort!,
        sni: ch.sni,
        alpn: ch.alpn,
        offeredVersions: (ch.supportedVersions.length ? ch.supportedVersions : [ch.version]).filter((v) => TLS_VERSIONS[v]).map((v) => TLS_VERSIONS[v]),
        version: ver !== undefined ? (TLS_VERSIONS[ver] ?? `0x${ver.toString(16)}`) : undefined,
        cipher: sh ? (CIPHER_NAMES[sh.cipher] ?? `0x${sh.cipher.toString(16).padStart(4, "0")}`) : undefined,
        ja3: ch.ja3,
        ja3Hash: ch.ja3Hash,
        ja4: ch.ja4,
        ja3sHash: sh?.ja3sHash,
        ech: ch.ech,
        certificates: tlsS?.certificates ?? [],
        alerts: [...tlsC.alerts, ...(tlsS?.alerts ?? [])].map((a) => `${a.level === 2 ? "fatal" : "warning"} ${ALERTS[a.description] ?? a.description}`),
      });
    }
  }

  const start = frames.length ? frames[0].ts / 1e6 : 0;
  const end = frames.length ? frames[frames.length - 1].ts / 1e6 : 0;
  const duration = Math.max(0.001, end - start);
  const buckets = 80;
  const timeline = Array.from({ length: buckets }, (_, i) => ({ t: (i * duration) / buckets, packets: 0, bytes: 0 }));
  for (const f of frames) {
    const i = Math.min(buckets - 1, Math.floor((((f.ts - t0) / 1e6) / duration) * buckets));
    timeline[i].packets++;
    timeline[i].bytes += f.original;
  }

  const report: CaptureReport = {
    name,
    size: bytes.length,
    format: capture.format,
    linkTypes: [...new Set(capture.interfaces.map((i) => LINK_TYPES[i.linkType] ?? `LINKTYPE ${i.linkType}`))],
    interfaces: capture.interfaces.map((i) => i.name ?? i.description ?? "").filter(Boolean),
    comments: capture.comments,
    errors: capture.errors,
    truncated: capture.truncated,
    packets: frames.length,
    bytes: totalBytes,
    start,
    end,
    rows,
    rowsTruncated: frames.length > rows.length,
    flows: flowList.map(publicFlow),
    dns,
    http,
    tls,
    dhcp,
    arp: [...arpMap.entries()].map(([ip, e]) => ({ ip, macs: [...e.macs], frames: e.frames })),
    endpoints: [...endpoints.entries()].map(([address, e]) => ({ address, ...e, public: isPublicAddress(address) })).sort((a, b) => b.bytes - a.bytes),
    protocols: [...protocols.entries()].map(([n, e]) => ({ name: n, ...e })).sort((a, b) => b.packets - a.packets),
    ports: [],
    timeline,
    indicators: [],
    credentials,
    findings: [],
    durationMs: 0,
  };

  const portCounts = new Map<string, { port: number; transport: string; flows: number }>();
  for (const fl of flowList) {
    if (fl.serverPort === undefined) continue;
    const k = `${fl.transport}/${fl.serverPort}`;
    const e = portCounts.get(k) ?? { port: fl.serverPort, transport: fl.transport, flows: 0 };
    e.flows++;
    portCounts.set(k, e);
  }
  report.ports = [...portCounts.values()].map((p) => ({ ...p, name: WELL_KNOWN_PORTS[p.port] })).sort((a, b) => b.flows - a.flows).slice(0, 50);
  if (collect?.streams) for (const fl of flowList) collect.streams.set(fl.id, fl.frames);
  report.indicators = indicatorsFor(report);
  report.findings = findingsFor(report, flowList, icmpBig);
  report.durationMs = Date.now() - started;
  return report;
}

function indicatorsFor(r: CaptureReport): Indicator[] {
  const map = new Map<string, Indicator>();
  const add = (value: string, type: ObservableType, source: string, frame: number) => {
    const v = type === "DOMAIN" ? value.toLowerCase().replace(/\.$/, "") : value;
    if (type === "DOMAIN" && (!registrableDomain(v) || /\.(local|lan|home|internal|arpa|localdomain)$/.test(v))) return;
    const k = `${type}:${v}`;
    const e = map.get(k);
    if (e) {
      e.count++;
      if (!e.sources.includes(source)) e.sources.push(source);
    } else map.set(k, { value: v, type, sources: [source], count: 1, firstFrame: frame });
  };
  for (const fl of r.flows) {
    for (const ip of [fl.client, fl.server]) if (isPublicAddress(ip)) add(ip, ip.includes(":") ? "IPV6" : "IPV4", `${fl.transport} flow`, fl.firstFrame);
  }
  for (const q of r.dns) {
    add(q.name, "DOMAIN", "DNS query", q.frame);
    for (const a of q.answers) {
      const [type, value] = a.split(" ");
      if ((type === "A" || type === "AAAA") && isPublicAddress(value)) add(value, type === "A" ? "IPV4" : "IPV6", "DNS answer", q.frame);
      if (type === "CNAME") add(value, "DOMAIN", "DNS CNAME", q.frame);
    }
  }
  for (const t of r.tls) if (t.sni) add(t.sni, "DOMAIN", "TLS SNI", t.frame);
  for (const h of r.http) {
    if (!/^\d+\.\d+\.\d+\.\d+(:\d+)?$/.test(h.host)) add(h.host.replace(/:\d+$/, ""), "DOMAIN", "HTTP Host", h.frame);
    add(h.url, "URL", "HTTP request", h.frame);
    if (h.body?.sha256) add(h.body.sha256, "SHA256", `HTTP object (${h.body.type.label})`, h.frame);
  }
  return [...map.values()].sort((a, b) => b.count - a.count);
}

function findingsFor(r: CaptureReport, flows: FlowState[], icmpBig: number[]): TrafficFinding[] {
  const out: TrafficFinding[] = [];

  // Executable content over HTTP
  const exes = r.http.filter((h) => h.body && (h.body.type.family === "executable" || /x-dosexec|x-msdownload|x-msdos-program|x-executable|x-elf/i.test(h.contentType ?? "")));
  if (exes.length) out.push({ id: "http.executable-download", severity: "HIGH", title: `Executable transferred over HTTP (${exes.length})`, detail: "A program was downloaded in cleartext. Check the hash against intelligence sources and whether the download was expected.", evidence: exes.slice(0, 8).map((h) => `${h.url} → ${h.body?.type.label}${h.body?.sha256 ? ` sha256 ${h.body.sha256}` : " (body incomplete in capture)"}`), attack: ["T1105"], basis: "traffic", frames: exes.map((h) => h.frame) });
  const scripts = r.http.filter((h) => h.body && !exes.includes(h) && (h.body.type.family === "script" || /\.(ps1|hta|vbs|js|bat|cmd|sh)(\?|$)/i.test(h.uri)));
  if (scripts.length) out.push({ id: "http.script-download", severity: "MEDIUM", title: `Script transferred over HTTP (${scripts.length})`, detail: "Script content fetched over HTTP is a common second stage for loaders.", evidence: scripts.slice(0, 8).map((h) => `${h.url} (${h.body?.type.label ?? h.contentType})`), attack: ["T1105", "T1059"], basis: "traffic", frames: scripts.map((h) => h.frame) });
  const rawIp = r.http.filter((h) => /^\d+\.\d+\.\d+\.\d+(:\d+)?$/.test(h.host) && isPublicAddress(h.host.replace(/:\d+$/, "")));
  if (rawIp.length) out.push({ id: "http.ip-host", severity: "LOW", title: "HTTP requests addressed to a bare public IP", detail: "Legitimate web traffic almost always uses a host name; malware staging and C2 frequently do not.", evidence: [...new Set(rawIp.map((h) => `${h.method} ${h.url}`))].slice(0, 8), basis: "heuristic", frames: rawIp.map((h) => h.frame) });
  const toolUa = r.http.filter((h) => /powershell|curl\/|wget\/|python-requests|python-urllib|go-http-client|winhttp|certutil|bitsadmin|microsoft bits/i.test(h.userAgent ?? "") || h.userAgent === undefined);
  if (toolUa.length) out.push({ id: "http.tool-user-agent", severity: "INFO", title: "HTTP clients that are scripts or tools", detail: "Command-line and scripting user agents (or none at all) are normal for automation, and also what loaders use. Look at what they fetched.", evidence: [...new Set(toolUa.map((h) => `${h.userAgent ?? "(no User-Agent)"} → ${h.host}`))].slice(0, 10), basis: "heuristic", frames: toolUa.map((h) => h.frame) });

  // Credentials
  if (r.credentials.length) out.push({ id: "traffic.cleartext-credentials", severity: "HIGH", title: `Credentials sent in cleartext (${r.credentials.length})`, detail: "Authentication crossed the network unencrypted. Anyone on the path could capture it. Secrets are not displayed here; rotate them and move the service to TLS.", evidence: r.credentials.slice(0, 10).map((c) => `${c.protocol} ${c.client} → ${c.server}${c.user ? ` user "${c.user}"` : ""}: ${c.detail}`), attack: ["T1040"], basis: "traffic", frames: r.credentials.map((c) => c.frame) });
  const telnet = flows.filter((f) => f.serverPort === 23 && f.transport === "TCP" && f.packets > 3);
  if (telnet.length) out.push({ id: "traffic.telnet", severity: "MEDIUM", title: "Telnet sessions", detail: "Telnet sends everything, including passwords, in cleartext.", evidence: telnet.slice(0, 6).map((f) => `${f.client} → ${f.server}:23, ${f.packets} packets`), attack: ["T1040"], basis: "traffic", frames: telnet.map((f) => f.firstFrame) });

  // TLS
  const now = r.end * 1000;
  const selfSigned = r.tls.filter((t) => t.certificates.length === 1 && t.certificates[0].selfIssued);
  if (selfSigned.length) out.push({ id: "tls.self-signed", severity: "LOW", title: "Self-signed server certificates", detail: "The server presented a certificate signed by itself. Normal on internal services and appliances; unusual for public services, and common for C2 frameworks' default certificates.", evidence: selfSigned.slice(0, 8).map((t) => `${t.server}:${t.serverPort} ${t.sni ? `(${t.sni}) ` : ""}CN=${t.certificates[0].subject.cn ?? "?"}`), basis: "traffic", frames: selfSigned.map((t) => t.frame) });
  const expired = r.tls.filter((t) => t.certificates[0]?.notAfter && Date.parse(t.certificates[0].notAfter) < now);
  if (expired.length) out.push({ id: "tls.expired", severity: "LOW", title: "Expired certificates at capture time", detail: "The leaf certificate had expired when this traffic was captured.", evidence: expired.slice(0, 8).map((t) => `${t.sni ?? t.server} expired ${t.certificates[0].notAfter}`), basis: "traffic", frames: expired.map((t) => t.frame) });
  const mismatch = r.tls.filter((t) => t.sni && t.certificates[0] && !certMatches(t.certificates[0], t.sni));
  if (mismatch.length) out.push({ id: "tls.name-mismatch", severity: "LOW", title: "Certificate does not cover the requested name", detail: "The server name the client asked for (SNI) is not in the certificate's subject or alternative names — a browser would refuse the connection.", evidence: mismatch.slice(0, 8).map((t) => `SNI ${t.sni} vs certificate ${t.certificates[0].subject.cn ?? "?"} [${t.certificates[0].subjectAltNames.slice(0, 4).join(", ")}]`), basis: "traffic", frames: mismatch.map((t) => t.frame) });
  const oldTls = r.tls.filter((t) => t.version && /SSL|TLS 1\.[01]$/.test(t.version));
  if (oldTls.length) out.push({ id: "tls.deprecated-version", severity: "LOW", title: "Deprecated TLS versions negotiated", detail: "TLS 1.0/1.1 and SSL are deprecated (RFC 8996).", evidence: oldTls.slice(0, 8).map((t) => `${t.sni ?? t.server}: ${t.version}`), basis: "traffic", frames: oldTls.map((t) => t.frame) });
  const weak = r.tls.filter((t) => t.cipher && /RC4|3DES|NULL|EXPORT|_DES_/.test(t.cipher));
  if (weak.length) out.push({ id: "tls.weak-cipher", severity: "MEDIUM", title: "Weak cipher suites negotiated", detail: "RC4, 3DES, NULL and export ciphers are broken or obsolete.", evidence: weak.slice(0, 8).map((t) => `${t.sni ?? t.server}: ${t.cipher}`), basis: "traffic", frames: weak.map((t) => t.frame) });
  const noSni = r.tls.filter((t) => !t.sni && isPublicAddress(t.server));
  if (noSni.length) out.push({ id: "tls.no-sni", severity: "INFO", title: "TLS to public IPs without a server name", detail: "Browsers always send SNI. TLS straight to an IP address is typical of scripts, IoT devices and some malware.", evidence: [...new Set(noSni.map((t) => `${t.server}:${t.serverPort} JA4 ${t.ja4}`))].slice(0, 8), basis: "heuristic", frames: noSni.map((t) => t.frame) });

  // Beaconing
  const groups = new Map<string, FlowState[]>();
  for (const f of flows) {
    if (f.serverPort === undefined || [53, 123, 137, 138, 1900, 5353, 5355, 67, 68].includes(f.serverPort)) continue;
    if (f.transport === "TCP" && !f.syn) continue;
    const k = `${f.transport}|${f.client}|${f.server}|${f.serverPort}`;
    const list = groups.get(k) ?? [];
    list.push(f);
    groups.set(k, list);
  }
  // Beacons: most inter-connection gaps sit close to one interval. Robust to
  // a few unrelated connections to the same service mixed in.
  const beacons: string[] = [];
  const beaconFrames: number[] = [];
  for (const [k, list] of groups) {
    if (list.length < 6) continue;
    const starts = list.map((f) => f.start).sort((a, b) => a - b);
    const gaps = starts.slice(1).map((s, i) => s - starts[i]);
    const sorted = [...gaps].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const regular = gaps.filter((g) => Math.abs(g - median) <= 0.2 * median);
    if (median >= 1 && regular.length >= 5 && regular.length / gaps.length >= 0.6) {
      const { mean, sd } = stdev(regular);
      const [, client, server, port] = k.split("|");
      beacons.push(`${client} → ${server}:${port} every ${mean.toFixed(1)} s (±${((sd / mean) * 100).toFixed(0)}% jitter, ${regular.length + 1} of ${list.length} connections on the interval)`);
      beaconFrames.push(list[0].firstFrame);
    }
  }
  if (beacons.length) out.push({ id: "traffic.beaconing", severity: "MEDIUM", title: "Regular, periodic connections (beaconing)", detail: "New connections to the same destination at near-constant intervals are the signature of a C2 implant checking in. Update agents, monitoring and NTP-like services also do this — identify the process.", evidence: beacons.slice(0, 10), attack: ["T1071", "T1029"], basis: "heuristic", frames: beaconFrames });

  // Scanning
  const vertical = new Map<string, Set<number>>();
  const horizontal = new Map<string, Set<string>>();
  for (const f of flows) {
    if (f.transport !== "TCP" || !f.syn || f.synAck) continue;
    const v = `${f.client}|${f.server}`;
    (vertical.get(v) ?? vertical.set(v, new Set()).get(v)!).add(f.serverPort!);
    const h = `${f.client}|${f.serverPort}`;
    (horizontal.get(h) ?? horizontal.set(h, new Set()).get(h)!).add(f.server);
  }
  const scans = [...[...vertical.entries()].filter(([, s]) => s.size >= 25).map(([k, s]) => `${k.split("|")[0]} probed ${s.size} ports on ${k.split("|")[1]} without completing handshakes`), ...[...horizontal.entries()].filter(([, s]) => s.size >= 25).map(([k, s]) => `${k.split("|")[0]} probed port ${k.split("|")[1]} on ${s.size} hosts`)];
  if (scans.length) out.push({ id: "traffic.scan", severity: "MEDIUM", title: "Port or host scanning", detail: "Many unanswered connection attempts from one source.", evidence: scans.slice(0, 8), attack: ["T1046"], basis: "traffic" });

  // DNS: tunnelling and DGA-like failure bursts
  const bySld = new Map<string, Set<string>>();
  for (const q of r.dns) {
    const sld = registrableDomain(q.name.replace(/\.$/, ""));
    if (!sld) continue;
    const sub = q.name.replace(/\.$/, "").slice(0, -sld.length - 1);
    if (sub.length < 25) continue;
    (bySld.get(sld) ?? bySld.set(sld, new Set()).get(sld)!).add(sub);
  }
  const tunnels = [...bySld.entries()].filter(([, s]) => s.size >= 15);
  if (tunnels.length) out.push({ id: "dns.tunnel", severity: "MEDIUM", title: "Long, unique subdomains under one domain", detail: "Many distinct long labels below one registered domain is how data is encoded into DNS queries (tunnelling, exfiltration). CDNs and anti-virus cloud lookups can look similar.", evidence: tunnels.slice(0, 6).map(([d, s]) => `${d}: ${s.size} unique subdomains, e.g. ${[...s][0].slice(0, 60)}`), attack: ["T1071.004", "T1048"], basis: "heuristic" });
  const nx = new Map<string, Set<string>>();
  for (const q of r.dns) if (q.rcode === "NXDOMAIN") (nx.get(q.client) ?? nx.set(q.client, new Set()).get(q.client)!).add(q.name);
  const dga = [...nx.entries()].filter(([, s]) => s.size >= 20);
  if (dga.length) out.push({ id: "dns.nxdomain-burst", severity: "MEDIUM", title: "Many failed lookups for distinct names", detail: "A host resolving dozens of non-existent domains is the pattern of a domain-generation algorithm looking for its live C2. Typos and search-suffix noise produce smaller numbers.", evidence: dga.slice(0, 6).map(([c, s]) => `${c}: ${s.size} NXDOMAIN names, e.g. ${[...s].slice(0, 3).join(", ")}`), attack: ["T1568.002"], basis: "heuristic" });
  const txt = r.dns.filter((q) => q.type === "TXT" && q.answers.length);
  if (txt.length >= 20) out.push({ id: "dns.txt-volume", severity: "LOW", title: `High volume of TXT lookups (${txt.length})`, detail: "TXT records can carry commands or payloads. Email security (SPF/DKIM) lookups are normal on mail servers.", evidence: [...new Set(txt.map((q) => q.name))].slice(0, 8), attack: ["T1071.004"], basis: "heuristic" });

  // ARP / DHCP
  const spoof = r.arp.filter((a) => a.macs.length > 1);
  if (spoof.length) out.push({ id: "arp.conflict", severity: "MEDIUM", title: "One IP address claimed by several MAC addresses", detail: "Conflicting ARP answers are the mechanism of ARP-spoofing man-in-the-middle attacks. Failover pairs and VM migrations cause benign cases.", evidence: spoof.slice(0, 8).map((a) => `${a.ip} ← ${a.macs.join(", ")}`), attack: ["T1557.002"], basis: "traffic", frames: spoof.flatMap((a) => a.frames.slice(0, 2)) });
  const servers = [...new Set(r.dhcp.filter((d) => (d.type === "OFFER" || d.type === "ACK") && d.server).map((d) => d.server!))];
  if (servers.length > 1) out.push({ id: "dhcp.multiple-servers", severity: "MEDIUM", title: "More than one DHCP server answered", detail: "A second DHCP server can hand out a malicious gateway or DNS server.", evidence: servers.map((s) => `DHCP server ${s}`), attack: ["T1557.003"], basis: "traffic" });

  if (icmpBig.length >= 5) out.push({ id: "icmp.large-payloads", severity: "LOW", title: `Large ICMP echo payloads (${icmpBig.length} packets)`, detail: "Echo requests normally carry 32–64 bytes. Large, repeated payloads can carry data (ICMP tunnelling); path-MTU tests also use them.", evidence: [`${icmpBig.length} echo packets with more than 128 bytes of payload`], attack: ["T1095"], basis: "heuristic", frames: icmpBig.slice(0, 20) });

  const external = r.endpoints.filter((e) => e.public);
  if (external.length) out.push({ id: "traffic.external-hosts", severity: "INFO", title: `${external.length} public addresses contacted`, detail: "Every public IP in the capture. Check the unfamiliar ones against intelligence sources.", evidence: external.slice(0, 10).map((e) => `${e.address}: ${e.packets} packets, ${e.bytes.toLocaleString()} bytes`), basis: "traffic" });
  if (r.errors.length) out.push({ id: "capture.errors", severity: "INFO", title: "Capture file problems", detail: "The file is truncated or damaged. Everything before the problem was analysed.", evidence: r.errors.slice(0, 5), basis: "traffic" });
  return out.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

function certMatches(cert: Certificate, name: string): boolean {
  const n = name.toLowerCase();
  const names = [...cert.subjectAltNames, ...(cert.subject.cn ? [cert.subject.cn] : [])].map((x) => x.toLowerCase());
  return names.some((p) => p === n || (p.startsWith("*.") && n.endsWith(p.slice(1)) && n.split(".").length === p.split(".").length));
}
