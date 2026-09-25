import { describe, expect, it } from "vitest";
import { estimateRsaBits, parseDmarc, parseMtaStsPolicy, parseSpf, parseTagList } from "./email-parse";
import { decodeMessage, encodeQuery } from "./wire";

// Real RFC 8484 response for example.com A (AdGuard DoH, DO bit set): two A records + RRSIG, AD flag.
const ADGUARD_EXAMPLE_COM =
  "000081a00001000300000001076578616d706c6503636f6d0000010001c00c000100010000006a0004ac4293f3c00c000100010000006a00046814179ac00c002e00010000006a005f00010d020000012c6ab744186ab484f886c9076578616d706c6503636f6d0071c52c3dc66c1b1e8f8fe0a87fbac90d435f89b6b887ef7e951d92a1002f7549ef6877f94adc2e4d8861ed0fc208ce5c1fc08b24b9b2424f09982cea690b316f0000290000000000000000";

const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));

describe("DNS wire codec", () => {
  it("decodes a real compressed DNSSEC response", () => {
    const m = decodeMessage(hex(ADGUARD_EXAMPLE_COM));
    expect(m.flags.qr).toBe(true);
    expect(m.flags.ad).toBe(true);
    expect(m.rcode).toBe(0);
    expect(m.questions[0]).toEqual({ name: "example.com.", type: "A" });
    expect(m.answers.filter((a) => a.type === "A").map((a) => a.data)).toEqual(["172.66.147.243", "104.20.23.154"]);
    expect(m.answers.some((a) => a.type === "RRSIG")).toBe(true);
    expect(m.answers[0].ttl).toBe(106);
  });

  it("encodes a query with EDNS DO and round-trips the question", () => {
    const q = encodeQuery("example.com", "AAAA", { id: 0x1234, dnssecOk: true });
    const m = decodeMessage(q);
    expect(m.id).toBe(0x1234);
    expect(m.questions[0]).toEqual({ name: "example.com.", type: "AAAA" });
    // One additional record (EDNS OPT, which the decoder deliberately hides) with the DO bit set.
    expect((q[10] << 8) | q[11]).toBe(1);
    expect(m.additional).toEqual([]);
    expect(q[q.length - 4] & 0x80).toBe(0x80);
  });

  it("rejects oversized labels and truncated messages", () => {
    expect(() => encodeQuery(`${"a".repeat(64)}.com`, "A")).toThrow();
    expect(() => decodeMessage(hex(ADGUARD_EXAMPLE_COM).slice(0, 40))).toThrow();
  });
});

describe("email authentication parsers", () => {
  it("parses SPF terms and the all qualifier", () => {
    const spf = parseSpf("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com mx ~all");
    expect(spf.valid).toBe(true);
    expect(spf.all).toBe("~");
    expect(spf.terms.map((t) => t.mechanism)).toEqual(["ip4", "include", "mx", "all"]);
    expect(spf.terms[1].value).toBe("_spf.google.com");
    expect(parseSpf("v=spf2 foo").valid).toBe(false);
    expect(parseSpf("v=spf1 bogus:x -all").errors[0]).toMatch(/Unknown mechanism/);
    expect(parseSpf("v=spf1 redirect=_spf.example.com").redirect).toBe("_spf.example.com");
  });

  it("parses DMARC with defaults and validation", () => {
    const d = parseDmarc("v=DMARC1; p=quarantine; pct=50; rua=mailto:a@example.com,mailto:b@example.com; adkim=s");
    expect(d.valid).toBe(true);
    expect(d.policy).toBe("quarantine");
    expect(d.pct).toBe(50);
    expect(d.rua).toHaveLength(2);
    expect(d.adkim).toBe("s");
    expect(d.aspf).toBe("r");
    expect(parseDmarc("v=DMARC1; p=maybe").valid).toBe(false);
    expect(parseDmarc("p=reject").errors[0]).toMatch(/v=DMARC1/);
  });

  it("parses MTA-STS policies and tag lists", () => {
    const p = parseMtaStsPolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n");
    expect(p.errors).toEqual([]);
    expect(p.mx).toEqual(["mail.example.com", "*.example.net"]);
    expect(parseMtaStsPolicy("version: STSv1\nmode: enforce").errors.length).toBeGreaterThan(0);
    expect(parseTagList("v=BIMI1; l=https://x/logo.svg; a=")).toEqual({ v: "BIMI1", l: "https://x/logo.svg", a: "" });
  });

  it("estimates DKIM RSA key sizes from the public key length", () => {
    expect(estimateRsaBits("A".repeat(216))).toBe(1024);
    expect(estimateRsaBits("A".repeat(392))).toBe(2048);
    expect(estimateRsaBits("")).toBeNull();
  });
});
