import type { FieldValue } from "./dissect";

// Display filters in a Wireshark-compatible subset:
//   ip.addr == 10.0.0.0/8 && tcp.port in {80 443}
//   dns.qry.name contains "update" || !tls
//   http.user_agent matches "(curl|python)"
// A bare field tests presence. `==` is true when any occurrence matches;
// `!=` is its negation. `contains` and `matches` are case-insensitive.

export class FilterError extends Error {
  constructor(
    message: string,
    readonly position: number
  ) {
    super(message);
    this.name = "FilterError";
  }
}

type Fields = Map<string, FieldValue[]>;
export type Predicate = (fields: Fields) => boolean;

interface Token {
  kind: "ident" | "string" | "op" | "lparen" | "rparen" | "lbrace" | "rbrace" | "value";
  text: string;
  pos: number;
}

const OPS: Record<string, string> = { "==": "==", eq: "==", "!=": "!=", ne: "!=", ">": ">", gt: ">", "<": "<", lt: "<", ">=": ">=", ge: ">=", "<=": "<=", le: "<=", contains: "contains", matches: "matches", "~": "matches", in: "in" };

export const FILTER_FIELDS: { field: string; description: string }[] = [
  { field: "frame.len", description: "Frame length in bytes" },
  { field: "frame.number", description: "Frame number" },
  { field: "eth.addr / eth.src / eth.dst", description: "MAC addresses" },
  { field: "vlan.id", description: "802.1Q VLAN ID" },
  { field: "arp / arp.opcode", description: "ARP presence, 1 request / 2 reply" },
  { field: "ip.addr / ip.src / ip.dst", description: "IPv4 or IPv6 address; accepts CIDR (ip.addr == 10.0.0.0/8)" },
  { field: "ip.ttl / ip.proto / ip.fragment", description: "IPv4 header fields" },
  { field: "tcp.port / tcp.srcport / tcp.dstport", description: "TCP ports" },
  { field: "tcp.flags.syn / .ack / .fin / .reset / .push", description: "TCP flags (true/false or 1/0)" },
  { field: "tcp.len / tcp.stream", description: "TCP payload length / conversation index" },
  { field: "udp.port / udp.srcport / udp.dstport", description: "UDP ports" },
  { field: "icmp.type / icmpv6.type", description: "ICMP message type" },
  { field: "dns.qry.name / dns.qry.type", description: "DNS question" },
  { field: "dns.a / dns.aaaa / dns.cname / dns.txt", description: "DNS answers" },
  { field: "dns.flags.rcode / dns.flags.response", description: "DNS response code (NXDOMAIN, …), response bit" },
  { field: "http.request.method / http.request.uri / http.host", description: "HTTP request line and Host" },
  { field: "http.user_agent / http.response.code / http.content_type", description: "HTTP headers and status" },
  { field: "tls.sni (tls.handshake.extensions_server_name)", description: "TLS server name" },
  { field: "tls.handshake.ja3 / tls.handshake.ja4 / tls.handshake.ja3s", description: "TLS fingerprints" },
  { field: "x509sat.commonName", description: "Certificate common names (TLS ≤ 1.2)" },
  { field: "dhcp.option.hostname", description: "DHCP client host name" },
  { field: "ssh.protocol", description: "SSH banner" },
  { field: "dns, http, tls, tcp, udp, icmp, arp, dhcp, ntp, quic, ipv6", description: "Protocol presence" },
];

function tokenize(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "(" || c === ")" || c === "{" || c === "}") {
      out.push({ kind: c === "(" ? "lparen" : c === ")" ? "rparen" : c === "{" ? "lbrace" : "rbrace", text: c, pos: i });
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      let s = "";
      while (j < src.length && src[j] !== c) {
        if (src[j] === "\\" && j + 1 < src.length) {
          s += src[j + 1];
          j += 2;
        } else s += src[j++];
      }
      if (j >= src.length) throw new FilterError("Unterminated string", i);
      out.push({ kind: "string", text: s, pos: i });
      i = j + 1;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (["==", "!=", ">=", "<=", "&&", "||"].includes(two)) {
      out.push({ kind: "op", text: two, pos: i });
      i += 2;
      continue;
    }
    if (c === ">" || c === "<" || c === "!" || c === "~" || c === ",") {
      out.push({ kind: "op", text: c, pos: i });
      i++;
      continue;
    }
    let j = i;
    while (j < src.length && /[A-Za-z0-9_.:/\-*]/.test(src[j])) j++;
    if (j === i) throw new FilterError(`Unexpected character '${c}'`, i);
    const word = src.slice(i, j);
    const lower = word.toLowerCase();
    if (["and", "or", "not", "eq", "ne", "gt", "lt", "ge", "le", "contains", "matches", "in"].includes(lower)) out.push({ kind: "op", text: lower, pos: i });
    else out.push({ kind: /^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)*$/i.test(word) && !/^\d/.test(word) ? "ident" : "value", text: word, pos: i });
    i = j;
  }
  return out;
}

function ipv4Num(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function valueMatcher(op: string, raw: string, pos: number): (v: FieldValue) => boolean {
  if (op === "matches") {
    let re: RegExp;
    try {
      re = new RegExp(raw, "i");
    } catch {
      throw new FilterError(`Invalid regular expression: ${raw}`, pos);
    }
    return (v) => re.test(String(v));
  }
  if (op === "contains") {
    const needle = raw.toLowerCase();
    return (v) => String(v).toLowerCase().includes(needle);
  }
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(raw);
  if (cidr && (op === "==" || op === "!=")) {
    const base = ipv4Num(cidr[1]);
    const bits = Number(cidr[2]);
    if (base === null || bits > 32) throw new FilterError(`Invalid CIDR ${raw}`, pos);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (v) => {
      const n = typeof v === "string" ? ipv4Num(v) : null;
      return n !== null && ((n & mask) >>> 0) === ((base & mask) >>> 0);
    };
  }
  const lower = raw.toLowerCase();
  const num = /^0x[0-9a-f]+$/i.test(raw) ? parseInt(raw, 16) : /^-?\d+(\.\d+)?$/.test(raw) ? Number(raw) : lower === "true" ? 1 : lower === "false" ? 0 : NaN;
  const cmp = (v: FieldValue): number | null => {
    const x = typeof v === "boolean" ? (v ? 1 : 0) : typeof v === "number" ? v : Number.isNaN(num) ? null : Number(v);
    if (x === null || Number.isNaN(x) || Number.isNaN(num)) return null;
    return x - num;
  };
  switch (op) {
    case "==":
    case "!=":
      return (v) => {
        const c = cmp(v);
        if (c !== null) return c === 0;
        return String(v).toLowerCase() === lower;
      };
    case ">":
      return (v) => (cmp(v) ?? -1) > 0;
    case "<":
      return (v) => (cmp(v) ?? 1) < 0;
    case ">=":
      return (v) => (cmp(v) ?? -1) >= 0;
    case "<=":
      return (v) => (cmp(v) ?? 1) <= 0;
  }
  throw new FilterError(`Unknown operator ${op}`, pos);
}

export function compileFilter(src: string): Predicate {
  const tokens = tokenize(src);
  let i = 0;
  const peek = () => tokens[i];
  const eat = () => tokens[i++];
  const isOp = (...ops: string[]) => peek()?.kind === "op" && ops.includes(peek().text);

  const parseOr = (): Predicate => {
    let left = parseAnd();
    while (isOp("or", "||")) {
      eat();
      const right = parseAnd();
      const l = left;
      left = (f) => l(f) || right(f);
    }
    return left;
  };
  const parseAnd = (): Predicate => {
    let left = parseNot();
    while (isOp("and", "&&")) {
      eat();
      const right = parseNot();
      const l = left;
      left = (f) => l(f) && right(f);
    }
    return left;
  };
  const parseNot = (): Predicate => {
    if (isOp("not", "!")) {
      eat();
      const inner = parseNot();
      return (f) => !inner(f);
    }
    return parsePrimary();
  };
  const parsePrimary = (): Predicate => {
    const t = peek();
    if (!t) throw new FilterError("Filter ends unexpectedly", src.length);
    if (t.kind === "lparen") {
      eat();
      const inner = parseOr();
      if (peek()?.kind !== "rparen") throw new FilterError("Missing ')'", peek()?.pos ?? src.length);
      eat();
      return inner;
    }
    if (t.kind !== "ident") throw new FilterError(`Expected a field name, found '${t.text}'`, t.pos);
    eat();
    const field = t.text.toLowerCase();
    const opTok = peek();
    if (!opTok || opTok.kind !== "op" || !OPS[opTok.text] || ["and", "or", "not", "&&", "||", "!"].includes(opTok.text)) {
      return (f) => (f.get(field)?.length ?? 0) > 0 && f.get(field)!.some((v) => v !== false);
    }
    eat();
    const op = OPS[opTok.text];
    if (op === "in") {
      if (peek()?.kind !== "lbrace") throw new FilterError("Expected '{' after 'in'", peek()?.pos ?? src.length);
      eat();
      const matchers: ((v: FieldValue) => boolean)[] = [];
      while (peek() && peek().kind !== "rbrace") {
        const v = eat();
        if (v.kind === "op" && v.text === ",") continue;
        if (v.kind !== "value" && v.kind !== "string" && v.kind !== "ident") throw new FilterError(`Unexpected '${v.text}' in set`, v.pos);
        matchers.push(valueMatcher("==", v.text, v.pos));
      }
      if (!peek()) throw new FilterError("Missing '}'", src.length);
      eat();
      return (f) => (f.get(field) ?? []).some((v) => matchers.some((m) => m(v)));
    }
    const vt = eat();
    if (!vt || (vt.kind !== "value" && vt.kind !== "string" && vt.kind !== "ident")) throw new FilterError(`Expected a value after '${opTok.text}'`, vt?.pos ?? src.length);
    const match = valueMatcher(op, vt.text, vt.pos);
    if (op === "!=") return (f) => !(f.get(field) ?? []).some(match);
    return (f) => (f.get(field) ?? []).some(match);
  };

  if (!tokens.length) return () => true;
  const pred = parseOr();
  if (i < tokens.length) throw new FilterError(`Unexpected '${tokens[i].text}'`, tokens[i].pos);
  return pred;
}
