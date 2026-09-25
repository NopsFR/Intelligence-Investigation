import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { analyzeCapture } from "./analyze";
import { readCapture } from "./capture";
import { dissect } from "./dissect";
import { FilterError, compileFilter } from "./filter";
import { parseDns } from "./proto/dns";
import { parseHttpStream } from "./proto/http";
import { isGrease, parseTlsStream } from "./proto/tls";
import { CLIENT_HELLO_TLS12, CLIENT_HELLO_TLS13, EXPECTED } from "./__fixtures__/client-hello";

const enc = (s: string) => new TextEncoder().encode(s);
const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));

interface Pkt {
  t: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto?: "tcp" | "udp";
  flags?: number;
  seq?: number;
  ack?: number;
  payload?: Uint8Array;
}

/** Ethernet / IPv4 / TCP-or-UDP frame. Checksums are left zero (not validated by the dissector). */
function frame(p: Pkt): Uint8Array {
  const payload = p.payload ?? new Uint8Array(0);
  const tcp = (p.proto ?? "tcp") === "tcp";
  const l4 = tcp ? 20 : 8;
  const b = new Uint8Array(14 + 20 + l4 + payload.length);
  const v = new DataView(b.buffer);
  b.set([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1], 0);
  v.setUint16(12, 0x0800);
  b[14] = 0x45;
  v.setUint16(16, 20 + l4 + payload.length);
  b[22] = 64;
  b[23] = tcp ? 6 : 17;
  b.set(p.src.split(".").map(Number), 26);
  b.set(p.dst.split(".").map(Number), 30);
  v.setUint16(34, p.sport);
  v.setUint16(36, p.dport);
  if (tcp) {
    v.setUint32(38, p.seq ?? 0);
    v.setUint32(42, p.ack ?? 0);
    b[46] = 0x50;
    b[47] = p.flags ?? 0x18;
    v.setUint16(48, 65535);
  } else v.setUint16(38, 8 + payload.length);
  b.set(payload, 14 + 20 + l4);
  return b;
}

function pcap(packets: Pkt[]): Uint8Array {
  const frames = packets.map(frame);
  const out = new Uint8Array(24 + frames.reduce((n, f) => n + 16 + f.length, 0));
  const v = new DataView(out.buffer);
  v.setUint32(0, 0xa1b2c3d4, true);
  v.setUint16(4, 2, true);
  v.setUint16(6, 4, true);
  v.setUint32(16, 65535, true);
  v.setUint32(20, 1, true);
  let o = 24;
  frames.forEach((f, i) => {
    const t = 1_700_000_000 + packets[i].t;
    v.setUint32(o, Math.floor(t), true);
    v.setUint32(o + 4, Math.round((t % 1) * 1e6), true);
    v.setUint32(o + 8, f.length, true);
    v.setUint32(o + 12, f.length, true);
    out.set(f, o + 16);
    o += 16 + f.length;
  });
  return out;
}

/** A TCP connection: handshake, client data, server data. */
function conversation(t: number, client: string, cport: number, server: string, sport: number, request: Uint8Array, response: Uint8Array): Pkt[] {
  const c = { src: client, dst: server, sport: cport, dport: sport };
  const s = { src: server, dst: client, sport, dport: cport };
  return [
    { ...c, t, flags: 0x02, seq: 1000 },
    { ...s, t: t + 0.001, flags: 0x12, seq: 5000, ack: 1001 },
    { ...c, t: t + 0.002, flags: 0x10, seq: 1001, ack: 5001 },
    { ...c, t: t + 0.003, flags: 0x18, seq: 1001, ack: 5001, payload: request },
    { ...s, t: t + 0.01, flags: 0x18, seq: 5001, ack: 1001 + request.length, payload: response },
    { ...c, t: t + 0.02, flags: 0x11, seq: 1001 + request.length, ack: 5001 + response.length },
  ];
}

const dnsQuery = (id: number, name: string) => {
  const q = [...name.split(".").flatMap((l) => [l.length, ...enc(l)]), 0, 0, 1, 0, 1];
  return Uint8Array.from([id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...q]);
};
const dnsResponse = (id: number, name: string, ip: number[] | null) => {
  const q = [...name.split(".").flatMap((l) => [l.length, ...enc(l)]), 0, 0, 1, 0, 1];
  const ans = ip ? [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip] : [];
  return Uint8Array.from([id >> 8, id & 255, 0x81, ip ? 0x80 : 0x83, 0, 1, 0, ip ? 1 : 0, 0, 0, 0, 0, ...q, ...ans]);
};

describe("capture container", () => {
  it("reads classic pcap frames and timestamps", () => {
    const cap = readCapture(pcap([{ t: 0.5, src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2 }]));
    expect(cap.format).toBe("pcap");
    expect(cap.frames).toHaveLength(1);
    expect(cap.frames[0].ts).toBe(1_700_000_000_500_000);
  });

  it("reads pcapng section, interface and enhanced packet blocks", () => {
    const f = frame({ t: 0, src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2 });
    const pad = (n: number) => (n + 3) & ~3;
    const shb = new Uint8Array(28);
    const sv = new DataView(shb.buffer);
    sv.setUint32(0, 0x0a0d0d0a, true);
    sv.setUint32(4, 28, true);
    sv.setUint32(8, 0x1a2b3c4d, true);
    sv.setUint16(12, 1, true);
    sv.setInt32(16, -1, true);
    sv.setInt32(20, -1, true);
    sv.setUint32(24, 28, true);
    const idb = new Uint8Array(20);
    const iv = new DataView(idb.buffer);
    iv.setUint32(0, 1, true);
    iv.setUint32(4, 20, true);
    iv.setUint16(8, 1, true);
    iv.setUint32(16, 20, true);
    const epbLen = 32 + pad(f.length);
    const epb = new Uint8Array(epbLen);
    const ev = new DataView(epb.buffer);
    ev.setUint32(0, 6, true);
    ev.setUint32(4, epbLen, true);
    const micros = BigInt(1_700_000_000_250_000);
    ev.setUint32(12, Number(micros >> BigInt(32)), true);
    ev.setUint32(16, Number(micros & BigInt(0xffffffff)), true);
    ev.setUint32(20, f.length, true);
    ev.setUint32(24, f.length, true);
    epb.set(f, 28);
    ev.setUint32(epbLen - 4, epbLen, true);
    const cap = readCapture(new Uint8Array([...shb, ...idb, ...epb]));
    expect(cap.format).toBe("pcapng");
    expect(cap.frames[0]).toMatchObject({ ts: 1_700_000_000_250_000, captured: f.length, linkType: 1 });
  });

  it("stops cleanly at a truncated record", () => {
    const full = pcap([
      { t: 0, src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2 },
      { t: 1, src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2 },
    ]);
    const cap = readCapture(full.subarray(0, full.length - 10));
    expect(cap.frames).toHaveLength(1);
    expect(cap.errors.join(" ")).toMatch(/truncated/);
  });

  it("rejects files that are not captures", () => {
    expect(() => readCapture(enc("definitely not a packet capture file"))).toThrow(/pcap/);
  });
});

describe("TLS fingerprints", () => {
  it("computes JA3 and JA4 identical to Wireshark for TLS 1.2 and 1.3 hellos", () => {
    for (const [hex, want] of [
      [CLIENT_HELLO_TLS12, EXPECTED.tls12],
      [CLIENT_HELLO_TLS13, EXPECTED.tls13],
    ] as const) {
      const hs = parseTlsStream(fromHex(hex));
      expect(hs.clientHello?.sni).toBe(want.sni);
      expect(hs.clientHello?.ja3Hash).toBe(want.ja3);
      expect(hs.clientHello?.ja4).toBe(want.ja4);
    }
  });

  it("recognises GREASE values", () => {
    expect(isGrease(0x0a0a)).toBe(true);
    expect(isGrease(0xfafa)).toBe(true);
    expect(isGrease(0x0a1a)).toBe(false);
    expect(isGrease(0x1301)).toBe(false);
  });
});

describe("DNS and HTTP parsers", () => {
  it("follows DNS compression pointers", () => {
    const m = parseDns(dnsResponse(7, "www.example.org", [192, 0, 2, 10]));
    expect(m.response).toBe(true);
    expect(m.questions[0]).toEqual({ name: "www.example.org", type: "A" });
    expect(m.answers[0]).toMatchObject({ name: "www.example.org", type: "A", data: "192.0.2.10" });
  });

  it("rejects DNS pointer loops", () => {
    const bad = Uint8Array.from([0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c]);
    expect(() => parseDns(bad)).toThrow();
  });

  it("de-chunks HTTP bodies and keeps message boundaries", () => {
    const stream = enc("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n");
    const [a, b] = parseHttpStream(stream);
    expect(new TextDecoder().decode(a.body)).toBe("hello world");
    expect(a.bodyComplete).toBe(true);
    expect(b.status).toBe(204);
  });
});

describe("display filters", () => {
  const f = (fields: Record<string, (string | number | boolean)[]>) => new Map(Object.entries(fields));
  const pkt = f({ ip: [true], "ip.addr": ["10.1.2.3", "8.8.8.8"], tcp: [true], "tcp.port": [51000, 443], "tls.sni": ["cdn.Example.com"] });

  it("evaluates comparisons, sets, CIDR and presence", () => {
    expect(compileFilter("ip.addr == 10.0.0.0/8")(pkt)).toBe(true);
    expect(compileFilter("ip.addr == 192.168.0.0/16")(pkt)).toBe(false);
    expect(compileFilter("tcp.port in {80 443}")(pkt)).toBe(true);
    expect(compileFilter('tls.sni contains "example"')(pkt)).toBe(true);
    expect(compileFilter("tls.sni matches \"^cdn\\\\.\"")(pkt)).toBe(true);
    expect(compileFilter("udp")(pkt)).toBe(false);
    expect(compileFilter("!udp && tcp.port > 1024")(pkt)).toBe(true);
  });

  it("gives && precedence over ||", () => {
    expect(compileFilter("udp && tcp || tls.sni")(pkt)).toBe(true);
    expect(compileFilter("udp && (tcp || tls.sni)")(pkt)).toBe(false);
  });

  it("treats != as 'no occurrence equals'", () => {
    expect(compileFilter("ip.addr != 8.8.8.8")(pkt)).toBe(false);
    expect(compileFilter("ip.addr != 1.1.1.1")(pkt)).toBe(true);
  });

  it("reports syntax errors with a position", () => {
    try {
      compileFilter("ip.addr == ");
      throw new Error("expected failure");
    } catch (err) {
      expect(err).toBeInstanceOf(FilterError);
      expect((err as FilterError).position).toBeGreaterThan(7);
    }
    expect(() => compileFilter("(tcp")).toThrow(FilterError);
    expect(() => compileFilter("tcp.port in {80")).toThrow(FilterError);
  });
});

describe("capture analysis", () => {
  const exe = new Uint8Array(512);
  exe.set(enc("MZ"), 0);
  exe.set(enc("This program cannot be run in DOS mode"), 0x4e);
  const exeResponse = new Uint8Array([...enc(`HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ${exe.length}\r\n\r\n`), ...exe]);
  const basic = `Basic ${Buffer.from("alice:hunter2-secret").toString("base64")}`;

  const packets: Pkt[] = [
    { t: 0, src: "10.0.0.5", dst: "10.0.0.53", sport: 40000, dport: 53, proto: "udp", payload: dnsQuery(1, "updates.bad-example.net") },
    { t: 0.01, src: "10.0.0.53", dst: "10.0.0.5", sport: 53, dport: 40000, proto: "udp", payload: dnsResponse(1, "updates.bad-example.net", [93, 184, 215, 14]) },
    ...conversation(1, "10.0.0.5", 50000, "93.184.215.14", 80, enc("GET /payload.exe HTTP/1.1\r\nHost: updates.bad-example.net\r\nUser-Agent: WindowsPowerShell/5.1\r\n\r\n"), exeResponse),
    ...conversation(2, "10.0.0.5", 50001, "23.215.0.136", 80, enc(`GET /admin HTTP/1.1\r\nHost: 23.215.0.136\r\nAuthorization: ${basic}\r\n\r\n`), enc("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
    // Beacon: eight connections, 30 s apart.
    ...Array.from({ length: 8 }, (_, i) => conversation(100 + i * 30, "10.0.0.5", 51000 + i, "192.0.2.200", 443, enc("\x17\x03\x03\x00\x05hello"), enc("\x17\x03\x03\x00\x02ok"))).flat(),
  ];
  const bytes = pcap(packets);

  it("builds flows, DNS transactions and HTTP objects", async () => {
    const r = await analyzeCapture(bytes, "test.pcap");
    expect(r.packets).toBe(packets.length);
    expect(r.dns[0]).toMatchObject({ name: "updates.bad-example.net", rcode: "NOERROR", answers: ["A 93.184.215.14"] });
    const dl = r.http.find((h) => h.uri === "/payload.exe")!;
    expect(dl.url).toBe("http://updates.bad-example.net/payload.exe");
    expect(dl.body?.type.id).toBe("pe");
    expect(dl.body?.sha256).toBe(createHash("sha256").update(exe).digest("hex"));
  });

  it("raises evidence-backed findings", async () => {
    const r = await analyzeCapture(bytes, "test.pcap");
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["http.executable-download", "traffic.cleartext-credentials", "traffic.beaconing", "http.ip-host"]));
    const beacon = r.findings.find((f) => f.id === "traffic.beaconing")!;
    expect(beacon.evidence[0]).toMatch(/every 30\.0 s/);
    expect(r.findings.find((f) => f.id === "http.executable-download")?.attack).toContain("T1105");
  });

  it("never exposes captured passwords", async () => {
    const r = await analyzeCapture(bytes, "test.pcap");
    const json = JSON.stringify(r, (_k, v) => (v instanceof Uint8Array ? undefined : v));
    expect(json).not.toContain("hunter2");
    expect(json).not.toContain(Buffer.from("alice:hunter2-secret").toString("base64"));
    expect(r.credentials[0]).toMatchObject({ protocol: "HTTP Basic", user: "alice" });
  });

  it("extracts public indicators and skips private addresses", async () => {
    const r = await analyzeCapture(bytes, "test.pcap");
    const values = r.indicators.map((i) => i.value);
    expect(values).toEqual(expect.arrayContaining(["93.184.215.14", "updates.bad-example.net", "http://updates.bad-example.net/payload.exe"]));
    expect(values).not.toContain("10.0.0.5");
  });

  it("dissects a frame into filterable fields", () => {
    const cap = readCapture(bytes);
    const d = dissect(bytes.subarray(cap.frames[0].offset, cap.frames[0].offset + cap.frames[0].captured), 1);
    expect(d.protocol).toBe("DNS");
    expect(compileFilter('dns.qry.name contains "bad-example" && udp.port == 53')(d.fields)).toBe(true);
  });
});
