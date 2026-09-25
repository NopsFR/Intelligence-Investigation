import { Reader } from "@/lib/analysis/bytes";
import { formatIpv6 } from "@/lib/observables/ip";
import { parseDns, type DnsMessage } from "./proto/dns";
import { looksLikeHttp, parseHttpStream, header } from "./proto/http";
import { TLS_VERSIONS, looksLikeTls, parseTlsStream } from "./proto/tls";

// Single-frame dissection. Produces display-filter fields, a layer tree with
// byte ranges (for the hex view) and a one-line summary. Stream-level
// protocols (HTTP bodies, TLS across segments) are handled in analyze.ts.

export type FieldValue = string | number | boolean;

export interface LayerNode {
  label: string;
  value?: string;
  range?: [number, number];
  children?: LayerNode[];
}

export interface Dissection {
  fields: Map<string, FieldValue[]>;
  layers: LayerNode[];
  protocol: string;
  info: string;
  src: string;
  dst: string;
  srcPort?: number;
  dstPort?: number;
  transport?: "TCP" | "UDP" | "ICMP" | "ICMPv6" | "ARP" | "OTHER";
  tcp?: { flags: number; seq: number; ack: number; window: number; payloadOffset: number; payloadLength: number };
  payloadOffset?: number;
  payloadLength?: number;
  dns?: DnsMessage;
  dhcp?: DhcpInfo;
  arp?: { op: number; senderMac: string; senderIp: string; targetMac: string; targetIp: string };
  icmp?: { type: number; code: number; payloadLength: number };
  malformed?: string;
}

export interface DhcpInfo {
  op: number;
  messageType?: string;
  xid: string;
  clientMac: string;
  yourIp: string;
  hostname?: string;
  requestedIp?: string;
  serverId?: string;
  vendorClass?: string;
  parameterList?: number[];
}

const ETHERTYPES: Record<number, string> = { 0x0800: "IPv4", 0x0806: "ARP", 0x86dd: "IPv6", 0x8100: "802.1Q", 0x88a8: "802.1ad", 0x88cc: "LLDP", 0x888e: "EAPOL", 0x8863: "PPPoE discovery", 0x8864: "PPPoE session" };
const IP_PROTOCOLS: Record<number, string> = { 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP" };
const ICMP_TYPES: Record<number, string> = { 0: "Echo reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect", 8: "Echo request", 11: "Time exceeded", 12: "Parameter problem", 13: "Timestamp", 14: "Timestamp reply" };
const ICMP6_TYPES: Record<number, string> = { 1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 128: "Echo request", 129: "Echo reply", 133: "Router solicitation", 134: "Router advertisement", 135: "Neighbor solicitation", 136: "Neighbor advertisement" };
const DHCP_TYPES = ["", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"];

export const WELL_KNOWN_PORTS: Record<number, string> = {
  20: "FTP-data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  67: "DHCP",
  68: "DHCP",
  69: "TFTP",
  80: "HTTP",
  88: "Kerberos",
  110: "POP3",
  123: "NTP",
  135: "MS-RPC",
  137: "NetBIOS-NS",
  138: "NetBIOS-DGM",
  139: "NetBIOS-SSN",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  514: "Syslog",
  587: "Submission",
  636: "LDAPS",
  853: "DoT",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1900: "SSDP",
  3306: "MySQL",
  3389: "RDP",
  5060: "SIP",
  5353: "mDNS",
  5355: "LLMNR",
  5432: "PostgreSQL",
  5900: "VNC",
  5985: "WinRM",
  5986: "WinRM-TLS",
  6379: "Redis",
  8080: "HTTP-alt",
  8443: "HTTPS-alt",
  9200: "Elasticsearch",
  27017: "MongoDB",
};

export const TCP_FLAG_NAMES: [number, string][] = [
  [0x01, "FIN"],
  [0x02, "SYN"],
  [0x04, "RST"],
  [0x08, "PSH"],
  [0x10, "ACK"],
  [0x20, "URG"],
  [0x40, "ECE"],
  [0x80, "CWR"],
];

export const tcpFlagString = (f: number) => TCP_FLAG_NAMES.filter(([b]) => f & b).map(([, n]) => n).join(", ") || "none";
export const mac = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(":");
const ipv4 = (b: Uint8Array) => `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
const ipv6 = (b: Uint8Array) => {
  let v = BigInt(0);
  for (const c of b) v = (v << BigInt(8)) | BigInt(c);
  return formatIpv6(v);
};

export function dissect(frame: Uint8Array, linkType: number): Dissection {
  const fields = new Map<string, FieldValue[]>();
  const set = (k: string, v: FieldValue) => {
    const list = fields.get(k);
    if (list) list.push(v);
    else fields.set(k, [v]);
  };
  const d: Dissection = { fields, layers: [], protocol: "Frame", info: "", src: "", dst: "" };
  const r = new Reader(frame, false);
  set("frame.len", frame.length);

  try {
    let o = 0;
    let etherType = -1;
    if (linkType === 1) {
      if (frame.length < 14) throw new Error("Ethernet header truncated");
      const dst = mac(frame.subarray(0, 6));
      const src = mac(frame.subarray(6, 12));
      etherType = r.u16(12);
      o = 14;
      const eth: LayerNode = { label: "Ethernet II", value: `${src} → ${dst}`, range: [0, 14], children: [{ label: "Destination", value: dst, range: [0, 6] }, { label: "Source", value: src, range: [6, 12] }, { label: "Type", value: `${ETHERTYPES[etherType] ?? "?"} (0x${etherType.toString(16).padStart(4, "0")})`, range: [12, 14] }] };
      d.layers.push(eth);
      set("eth", true);
      set("eth.src", src);
      set("eth.dst", dst);
      set("eth.addr", src);
      set("eth.addr", dst);
      d.src = src;
      d.dst = dst;
      d.protocol = "Ethernet";
      while ((etherType === 0x8100 || etherType === 0x88a8) && r.has(o, 4)) {
        const tci = r.u16(o);
        d.layers.push({ label: "802.1Q VLAN", value: `ID ${tci & 0xfff}`, range: [o, o + 4] });
        set("vlan.id", tci & 0xfff);
        etherType = r.u16(o + 2);
        o += 4;
      }
    } else if (linkType === 113) {
      etherType = r.u16(14);
      o = 16;
      d.layers.push({ label: "Linux cooked capture", range: [0, 16], value: `protocol 0x${etherType.toString(16)}` });
    } else if (linkType === 276) {
      etherType = r.u16(0);
      o = 20;
      d.layers.push({ label: "Linux cooked capture v2", range: [0, 20], value: `protocol 0x${etherType.toString(16)}` });
    } else if (linkType === 0 || linkType === 108) {
      const family = new Reader(frame, true).u32(0);
      etherType = family === 2 ? 0x0800 : [24, 28, 30].includes(family) ? 0x86dd : -1;
      o = 4;
      d.layers.push({ label: "Loopback", range: [0, 4], value: `family ${family}` });
    } else if (linkType === 101 || linkType === 12 || linkType === 228 || linkType === 229) {
      etherType = frame[0] >> 4 === 6 ? 0x86dd : 0x0800;
    } else {
      d.info = `Link type ${linkType} is not decoded`;
      d.protocol = `LINKTYPE_${linkType}`;
      return d;
    }

    if (etherType === 0x0806) return decodeArp(frame, o, d, set);

    let proto = -1;
    let l4 = o;
    let l4End = frame.length;
    if (etherType === 0x0800) {
      const vihl = r.u8(o);
      if (vihl >> 4 !== 4) throw new Error("IPv4 version field is not 4");
      const ihl = (vihl & 0xf) * 4;
      const total = r.u16(o + 2);
      const flagsFrag = r.u16(o + 6);
      const ttl = r.u8(o + 8);
      proto = r.u8(o + 9);
      const src = ipv4(r.slice(o + 12, 4));
      const dst = ipv4(r.slice(o + 16, 4));
      l4 = o + ihl;
      l4End = Math.min(frame.length, o + (total || frame.length - o));
      const frag = flagsFrag & 0x1fff;
      d.layers.push({
        label: "Internet Protocol v4",
        value: `${src} → ${dst}`,
        range: [o, o + ihl],
        children: [
          { label: "Header length", value: `${ihl} bytes`, range: [o, o + 1] },
          { label: "Total length", value: String(total), range: [o + 2, o + 4] },
          { label: "Identification", value: `0x${r.u16(o + 4).toString(16)}`, range: [o + 4, o + 6] },
          { label: "Flags", value: `${flagsFrag & 0x4000 ? "DF " : ""}${flagsFrag & 0x2000 ? "MF " : ""}offset ${frag * 8}`, range: [o + 6, o + 8] },
          { label: "TTL", value: String(ttl), range: [o + 8, o + 9] },
          { label: "Protocol", value: `${IP_PROTOCOLS[proto] ?? proto} (${proto})`, range: [o + 9, o + 10] },
          { label: "Source", value: src, range: [o + 12, o + 16] },
          { label: "Destination", value: dst, range: [o + 16, o + 20] },
        ],
      });
      set("ip", true);
      set("ip.src", src);
      set("ip.dst", dst);
      set("ip.addr", src);
      set("ip.addr", dst);
      set("ip.ttl", ttl);
      set("ip.proto", proto);
      set("ip.len", total);
      if (flagsFrag & 0x2000 || frag) set("ip.fragment", true);
      d.src = src;
      d.dst = dst;
      d.protocol = "IPv4";
      if (frag) {
        d.info = `Fragment of ${IP_PROTOCOLS[proto] ?? proto} (offset ${frag * 8})`;
        return d;
      }
    } else if (etherType === 0x86dd) {
      const plen = r.u16(o + 4);
      proto = r.u8(o + 6);
      const hop = r.u8(o + 7);
      const src = ipv6(r.slice(o + 8, 16));
      const dst = ipv6(r.slice(o + 24, 16));
      l4 = o + 40;
      l4End = Math.min(frame.length, l4 + plen);
      // Skip common extension headers.
      for (let guard = 0; guard < 8 && [0, 43, 60].includes(proto) && r.has(l4, 2); guard++) {
        proto = r.u8(l4);
        l4 += (r.u8(l4 + 1) + 1) * 8;
      }
      d.layers.push({ label: "Internet Protocol v6", value: `${src} → ${dst}`, range: [o, o + 40], children: [{ label: "Payload length", value: String(plen), range: [o + 4, o + 6] }, { label: "Next header", value: `${IP_PROTOCOLS[proto] ?? proto}`, range: [o + 6, o + 7] }, { label: "Hop limit", value: String(hop), range: [o + 7, o + 8] }, { label: "Source", value: src, range: [o + 8, o + 24] }, { label: "Destination", value: dst, range: [o + 24, o + 40] }] });
      set("ipv6", true);
      set("ipv6.src", src);
      set("ipv6.dst", dst);
      set("ipv6.addr", src);
      set("ipv6.addr", dst);
      set("ip.addr", src);
      set("ip.src", src);
      set("ip.dst", dst);
      d.src = src;
      d.dst = dst;
      d.protocol = "IPv6";
    } else {
      d.protocol = ETHERTYPES[etherType] ?? `0x${etherType.toString(16)}`;
      d.info = `EtherType ${d.protocol}`;
      return d;
    }

    if (proto === 6) decodeTcp(frame, l4, l4End, d, set);
    else if (proto === 17) decodeUdp(frame, l4, l4End, d, set);
    else if (proto === 1 || proto === 58) decodeIcmp(frame, l4, l4End, proto === 58, d, set);
    else {
      d.protocol = IP_PROTOCOLS[proto] ?? `IP proto ${proto}`;
      d.transport = "OTHER";
      d.info = d.protocol;
    }
  } catch (err) {
    d.malformed = err instanceof Error ? err.message : String(err);
    d.info = d.info || `Malformed: ${d.malformed}`;
    set("_ws.malformed", true);
  }
  return d;
}

type Setter = (k: string, v: FieldValue) => void;

/**
 * Credentials and session tokens are summarised, never displayed: a Basic
 * header shows only its user name, cookies and bearer tokens only their size.
 */
export function maskSecretHeader(name: string, value: string): string {
  const k = name.toLowerCase();
  if (k === "authorization" || k === "proxy-authorization") {
    const [scheme, token = ""] = value.split(/\s+/, 2);
    if (/^basic$/i.test(scheme)) {
      try {
        const user = atob(token).split(":")[0];
        return `Basic (user "${user}", password masked)`;
      } catch {
        return "Basic (masked)";
      }
    }
    return `${scheme} (masked, ${token.length} chars)`;
  }
  if (k === "cookie" || k === "set-cookie") return `(masked, ${value.length} chars; ${value.split(";").filter((x) => x.includes("=")).length} values)`;
  return value;
}

function decodeArp(frame: Uint8Array, o: number, d: Dissection, set: Setter): Dissection {
  const r = new Reader(frame, false);
  const op = r.u16(o + 6);
  const senderMac = mac(r.slice(o + 8, 6));
  const senderIp = ipv4(r.slice(o + 14, 4));
  const targetMac = mac(r.slice(o + 18, 6));
  const targetIp = ipv4(r.slice(o + 24, 4));
  d.arp = { op, senderMac, senderIp, targetMac, targetIp };
  d.protocol = "ARP";
  d.transport = "ARP";
  d.info = op === 1 ? `Who has ${targetIp}? Tell ${senderIp}` : op === 2 ? `${senderIp} is at ${senderMac}` : `ARP op ${op}`;
  d.layers.push({ label: "Address Resolution Protocol", value: op === 1 ? "request" : op === 2 ? "reply" : String(op), range: [o, o + 28], children: [{ label: "Sender MAC", value: senderMac, range: [o + 8, o + 14] }, { label: "Sender IP", value: senderIp, range: [o + 14, o + 18] }, { label: "Target MAC", value: targetMac, range: [o + 18, o + 24] }, { label: "Target IP", value: targetIp, range: [o + 24, o + 28] }] });
  set("arp", true);
  set("arp.opcode", op);
  set("arp.src.proto_ipv4", senderIp);
  set("arp.dst.proto_ipv4", targetIp);
  set("arp.src.hw_mac", senderMac);
  return d;
}

function decodeIcmp(frame: Uint8Array, o: number, end: number, v6: boolean, d: Dissection, set: Setter) {
  const r = new Reader(frame, false);
  const type = r.u8(o);
  const code = r.u8(o + 1);
  const name = (v6 ? ICMP6_TYPES : ICMP_TYPES)[type] ?? `type ${type}`;
  d.protocol = v6 ? "ICMPv6" : "ICMP";
  d.transport = v6 ? "ICMPv6" : "ICMP";
  d.icmp = { type, code, payloadLength: Math.max(0, end - o - 8) };
  d.info = `${name}${code ? ` (code ${code})` : ""}${type === 8 || type === 0 || type === 128 || type === 129 ? ` id=0x${r.u16(o + 4).toString(16)} seq=${r.u16(o + 6)}` : ""}`;
  d.layers.push({ label: v6 ? "ICMPv6" : "ICMP", value: name, range: [o, Math.min(end, o + 8)], children: [{ label: "Type", value: `${type} (${name})`, range: [o, o + 1] }, { label: "Code", value: String(code), range: [o + 1, o + 2] }, { label: "Payload", value: `${d.icmp.payloadLength} bytes`, range: [o + 8, end] }] });
  set(v6 ? "icmpv6" : "icmp", true);
  set(v6 ? "icmpv6.type" : "icmp.type", type);
  set(v6 ? "icmpv6.code" : "icmp.code", code);
  d.payloadOffset = o + 8;
  d.payloadLength = Math.max(0, end - o - 8);
}

function decodeTcp(frame: Uint8Array, o: number, end: number, d: Dissection, set: Setter) {
  const r = new Reader(frame, false);
  const sport = r.u16(o);
  const dport = r.u16(o + 2);
  const seq = r.u32(o + 4);
  const ack = r.u32(o + 8);
  const off = (r.u8(o + 12) >> 4) * 4;
  const flags = r.u8(o + 13);
  const window = r.u16(o + 14);
  if (off < 20) throw new Error("TCP header length below 20 bytes");
  const payloadOffset = o + off;
  const payloadLength = Math.max(0, end - payloadOffset);
  d.transport = "TCP";
  d.protocol = "TCP";
  d.srcPort = sport;
  d.dstPort = dport;
  d.tcp = { flags, seq, ack, window, payloadOffset, payloadLength };
  d.payloadOffset = payloadOffset;
  d.payloadLength = payloadLength;
  d.info = `${sport} → ${dport} [${tcpFlagString(flags)}] Seq=${seq} Ack=${ack} Win=${window} Len=${payloadLength}`;
  d.layers.push({
    label: "Transmission Control Protocol",
    value: `${sport} → ${dport}`,
    range: [o, payloadOffset],
    children: [
      { label: "Source port", value: `${sport}${WELL_KNOWN_PORTS[sport] ? ` (${WELL_KNOWN_PORTS[sport]})` : ""}`, range: [o, o + 2] },
      { label: "Destination port", value: `${dport}${WELL_KNOWN_PORTS[dport] ? ` (${WELL_KNOWN_PORTS[dport]})` : ""}`, range: [o + 2, o + 4] },
      { label: "Sequence number", value: String(seq), range: [o + 4, o + 8] },
      { label: "Acknowledgment", value: String(ack), range: [o + 8, o + 12] },
      { label: "Header length", value: `${off} bytes`, range: [o + 12, o + 13] },
      { label: "Flags", value: tcpFlagString(flags), range: [o + 13, o + 14] },
      { label: "Window", value: String(window), range: [o + 14, o + 16] },
      ...(payloadLength ? [{ label: "Payload", value: `${payloadLength} bytes`, range: [payloadOffset, end] as [number, number] }] : []),
    ],
  });
  set("tcp", true);
  set("tcp.srcport", sport);
  set("tcp.dstport", dport);
  set("tcp.port", sport);
  set("tcp.port", dport);
  set("tcp.seq", seq);
  set("tcp.ack", ack);
  set("tcp.len", payloadLength);
  set("tcp.window_size", window);
  set("tcp.flags", flags);
  set("tcp.flags.syn", (flags & 2) !== 0);
  set("tcp.flags.ack", (flags & 0x10) !== 0);
  set("tcp.flags.fin", (flags & 1) !== 0);
  set("tcp.flags.reset", (flags & 4) !== 0);
  set("tcp.flags.push", (flags & 8) !== 0);

  if (!payloadLength) return;
  const payload = frame.subarray(payloadOffset, end);
  if ((sport === 53 || dport === 53) && payload.length > 14) {
    try {
      decodeDnsInto(payload.subarray(2), payloadOffset + 2, d, set);
    } catch {
      // segment of a larger message
    }
  } else if (looksLikeHttp(payload)) {
    const [m] = parseHttpStream(payload, 1);
    if (m) {
      d.protocol = "HTTP";
      set("http", true);
      if (m.kind === "request") {
        set("http.request", true);
        set("http.request.method", m.method!);
        set("http.request.uri", m.uri!);
        const host = header(m, "host");
        if (host) set("http.host", host);
        const ua = header(m, "user-agent");
        if (ua) set("http.user_agent", ua);
        d.info = `${m.method} ${m.uri} HTTP/${m.version}`;
      } else {
        set("http.response", true);
        set("http.response.code", m.status!);
        const ct = header(m, "content-type");
        if (ct) set("http.content_type", ct);
        d.info = `HTTP/${m.version} ${m.status} ${m.reason ?? ""}`;
      }
      d.layers.push({ label: "Hypertext Transfer Protocol", value: d.info, range: [payloadOffset, payloadOffset + m.bodyOffset], children: m.headers.slice(0, 40).map(([k, v]) => ({ label: k, value: maskSecretHeader(k, v) })) });
    }
  } else if (looksLikeTls(payload)) {
    const tls = parseTlsStream(payload);
    d.protocol = "TLS";
    set("tls", true);
    const parts: string[] = [];
    const children: LayerNode[] = [];
    if (tls.clientHello) {
      const ch = tls.clientHello;
      parts.push("Client Hello");
      set("tls.handshake.type", 1);
      if (ch.sni) {
        set("tls.handshake.extensions_server_name", ch.sni);
        set("tls.sni", ch.sni);
      }
      set("tls.handshake.ja3", ch.ja3Hash);
      set("tls.handshake.ja4", ch.ja4);
      for (const a of ch.alpn) set("tls.handshake.extensions_alpn_str", a);
      children.push({ label: "Server name", value: ch.sni ?? "(none)" }, { label: "ALPN", value: ch.alpn.join(", ") || "(none)" }, { label: "Ciphers", value: String(ch.ciphers.length) }, { label: "JA3", value: `${ch.ja3Hash}  (${ch.ja3})` }, { label: "JA4", value: ch.ja4 });
    }
    if (tls.serverHello) {
      parts.push("Server Hello");
      set("tls.handshake.type", 2);
      set("tls.handshake.ja3s", tls.serverHello.ja3sHash);
      const v = tls.serverHello.selectedVersion ?? tls.serverHello.version;
      children.push({ label: "Version", value: TLS_VERSIONS[v] ?? `0x${v.toString(16)}` }, { label: "JA3S", value: tls.serverHello.ja3sHash });
    }
    if (tls.certificates.length) {
      parts.push("Certificate");
      for (const c of tls.certificates) if (c.subject.cn) set("x509sat.commonName", c.subject.cn);
      children.push({ label: "Certificates", value: tls.certificates.map((c) => c.subject.cn ?? c.subject.text).join(" ← ") });
    }
    if (tls.encrypted && !parts.length) parts.push("Application Data");
    if (tls.alerts.length) parts.push("Alert");
    d.info = parts.join(", ") || "TLS record (continuation)";
    d.layers.push({ label: "Transport Layer Security", value: d.info, range: [payloadOffset, end], children });
  } else {
    const name = WELL_KNOWN_PORTS[Math.min(sport, dport)] ?? WELL_KNOWN_PORTS[dport] ?? WELL_KNOWN_PORTS[sport];
    if (name) {
      d.protocol = name;
      if (name === "SSH" && payload[0] === 0x53 && payload[1] === 0x53 && payload[2] === 0x48) {
        const banner = String.fromCharCode(...payload.subarray(0, Math.min(payload.length, 120))).split("\r\n")[0];
        set("ssh.protocol", banner);
        d.info = banner;
      }
      if (["FTP", "SMTP", "POP3", "IMAP", "Telnet"].includes(name)) {
        const line = String.fromCharCode(...payload.subarray(0, Math.min(payload.length, 200))).split(/\r?\n/)[0];
        d.info = `${name}: ${line.replace(/^(PASS|pass)\s+.*/, "$1 ********").replace(/^(AUTH (PLAIN|LOGIN))\s+.*/i, "$1 ********")}`;
        set(name.toLowerCase(), true);
      }
    }
  }
}

function decodeUdp(frame: Uint8Array, o: number, end: number, d: Dissection, set: Setter) {
  const r = new Reader(frame, false);
  const sport = r.u16(o);
  const dport = r.u16(o + 2);
  const len = r.u16(o + 4);
  const payloadOffset = o + 8;
  const payloadEnd = Math.min(end, o + Math.max(8, len));
  d.transport = "UDP";
  d.protocol = "UDP";
  d.srcPort = sport;
  d.dstPort = dport;
  d.payloadOffset = payloadOffset;
  d.payloadLength = Math.max(0, payloadEnd - payloadOffset);
  d.info = `${sport} → ${dport} Len=${d.payloadLength}`;
  d.layers.push({ label: "User Datagram Protocol", value: `${sport} → ${dport}`, range: [o, o + 8], children: [{ label: "Source port", value: String(sport), range: [o, o + 2] }, { label: "Destination port", value: String(dport), range: [o + 2, o + 4] }, { label: "Length", value: String(len), range: [o + 4, o + 6] }] });
  set("udp", true);
  set("udp.srcport", sport);
  set("udp.dstport", dport);
  set("udp.port", sport);
  set("udp.port", dport);
  set("udp.length", len);
  const payload = frame.subarray(payloadOffset, payloadEnd);
  const has = (p: number) => sport === p || dport === p;
  try {
    if (has(53) || has(5353) || has(5355)) decodeDnsInto(payload, payloadOffset, d, set, has(5353) ? "mDNS" : has(5355) ? "LLMNR" : "DNS");
    else if ((has(67) || has(68)) && payload.length >= 240) decodeDhcp(payload, payloadOffset, d, set);
    else if (has(123) && payload.length >= 48) {
      d.protocol = "NTP";
      set("ntp", true);
      const mode = payload[0] & 7;
      d.info = `NTP ${["reserved", "symmetric active", "symmetric passive", "client", "server", "broadcast", "control", "private"][mode]}`;
    } else if (has(443) && payload.length > 20 && (payload[0] & 0xc0) === 0xc0) {
      d.protocol = "QUIC";
      set("quic", true);
      const version = new Reader(payload, false).u32(1);
      d.info = `QUIC long header, version 0x${version.toString(16)} (encrypted)`;
    } else if (has(1900)) {
      d.protocol = "SSDP";
      d.info = String.fromCharCode(...payload.subarray(0, Math.min(80, payload.length))).split("\r\n")[0];
    } else if (has(137)) d.protocol = "NetBIOS-NS";
  } catch {
    // leave as UDP
  }
}

function decodeDnsInto(payload: Uint8Array, base: number, d: Dissection, set: Setter, label = "DNS") {
  const msg = parseDns(payload);
  d.dns = msg;
  d.protocol = label;
  set("dns", true);
  set("dns.id", msg.id);
  set("dns.flags.response", msg.response);
  set("dns.flags.rcode", msg.rcode);
  for (const q of msg.questions) {
    set("dns.qry.name", q.name);
    set("dns.qry.type", q.type);
  }
  for (const a of msg.answers) {
    if (a.type === "A") set("dns.a", a.data);
    else if (a.type === "AAAA") set("dns.aaaa", a.data);
    else if (a.type === "CNAME") set("dns.cname", a.data);
    else if (a.type === "TXT") set("dns.txt", a.data);
  }
  const q = msg.questions[0];
  d.info = msg.response ? `Response 0x${msg.id.toString(16)} ${q ? `${q.type} ${q.name}` : ""} ${msg.rcode !== "NOERROR" ? msg.rcode : msg.answers.slice(0, 3).map((a) => `${a.type} ${a.data}`).join(" ")}` : `Query 0x${msg.id.toString(16)} ${q ? `${q.type} ${q.name}` : ""}`;
  d.layers.push({
    label: label === "DNS" ? "Domain Name System" : label,
    value: msg.response ? "response" : "query",
    range: [base, base + payload.length],
    children: [
      { label: "Transaction ID", value: `0x${msg.id.toString(16)}`, range: [base, base + 2] },
      { label: "Flags", value: `${msg.response ? "response" : "query"} ${msg.flags.join(" ")} ${msg.rcode}` },
      ...msg.questions.map((x) => ({ label: "Question", value: `${x.name} ${x.type}` })),
      ...msg.answers.slice(0, 30).map((a) => ({ label: `Answer ${a.type}`, value: `${a.name} → ${a.data} (TTL ${a.ttl})` })),
    ],
  });
}

function decodeDhcp(p: Uint8Array, base: number, d: Dissection, set: Setter) {
  const r = new Reader(p, false);
  if (r.u32(236) !== 0x63825363) return;
  const info: DhcpInfo = { op: p[0], xid: `0x${r.u32(4).toString(16)}`, clientMac: mac(p.subarray(28, 34)), yourIp: ipv4(p.subarray(16, 20)) };
  let o = 240;
  const text = (a: number, n: number) => new TextDecoder("utf-8", { fatal: false }).decode(p.subarray(a, a + n));
  while (o < p.length && p[o] !== 255) {
    const code = p[o];
    if (code === 0) {
      o++;
      continue;
    }
    const len = p[o + 1];
    const v = o + 2;
    if (v + len > p.length) break;
    if (code === 53) info.messageType = DHCP_TYPES[p[v]] ?? String(p[v]);
    else if (code === 12) info.hostname = text(v, len);
    else if (code === 50 && len === 4) info.requestedIp = ipv4(p.subarray(v, v + 4));
    else if (code === 54 && len === 4) info.serverId = ipv4(p.subarray(v, v + 4));
    else if (code === 60) info.vendorClass = text(v, len);
    else if (code === 55) info.parameterList = Array.from(p.subarray(v, v + len));
    o = v + len;
  }
  d.dhcp = info;
  d.protocol = "DHCP";
  set("dhcp", true);
  if (info.hostname) set("dhcp.option.hostname", info.hostname);
  if (info.messageType) set("dhcp.option.dhcp", info.messageType);
  d.info = `DHCP ${info.messageType ?? ""} ${info.xid}${info.hostname ? ` host ${info.hostname}` : ""}${info.yourIp !== "0.0.0.0" ? ` → ${info.yourIp}` : ""}`;
  d.layers.push({ label: "Dynamic Host Configuration Protocol", value: info.messageType, range: [base, base + p.length], children: Object.entries(info).filter(([, v]) => v !== undefined).map(([k, v]) => ({ label: k, value: Array.isArray(v) ? v.join(",") : String(v) })) });
}
