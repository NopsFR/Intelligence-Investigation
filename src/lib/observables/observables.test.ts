import { describe, expect, it } from "vitest";
import { detectAs, detectObservable, hostnameInfo } from "./detect";
import { extractIndicators } from "./extract";
import { defang, refang } from "./fang";
import { classifyIp, formatIpv6, isPublicAddress, normalizeIpv6, parseIpv6, reverseDnsName } from "./ip";
import { analyzeUrl } from "./url";

describe("IP classification", () => {
  it.each([
    ["8.8.8.8", "public"],
    ["10.1.2.3", "private"],
    ["172.16.0.1", "private"],
    ["192.168.50.111", "private"],
    ["100.64.1.1", "shared"],
    ["127.0.0.1", "loopback"],
    ["169.254.169.254", "link-local"],
    ["192.0.2.10", "documentation"],
    ["224.0.0.1", "multicast"],
    ["255.255.255.255", "broadcast"],
    ["0.1.2.3", "this-network"],
    ["::1", "loopback"],
    ["fe80::1", "link-local"],
    ["fd00::1", "unique-local"],
    ["2001:db8::1", "documentation"],
    ["2606:4700:4700::1111", "public"],
  ])("%s is %s", (ip, scope) => {
    expect(classifyIp(ip)?.scope).toBe(scope);
  });

  it("treats IPv4-mapped and NAT64 forms as non-public and exposes the embedded address", () => {
    const mapped = classifyIp("::ffff:127.0.0.1");
    expect(mapped?.scope).toBe("ipv4-mapped");
    expect(mapped?.embeddedIpv4).toBe("127.0.0.1");
    expect(isPublicAddress("::ffff:8.8.8.8")).toBe(false);
    expect(classifyIp("64:ff9b::a9fe:a9fe")?.embeddedIpv4).toBe("169.254.169.254");
  });

  it("formats IPv6 canonically (RFC 5952)", () => {
    expect(normalizeIpv6("2001:0DB8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
    expect(formatIpv6(parseIpv6("0:0:0:0:0:0:0:0")!)).toBe("::");
    expect(normalizeIpv6("1::2::3")).toBeNull();
  });

  it("builds reverse lookup names", () => {
    expect(reverseDnsName("8.8.4.4")).toBe("4.4.8.8.in-addr.arpa");
    expect(reverseDnsName("2001:db8::1")).toMatch(/^1\.0\.0\.0\..*\.8\.b\.d\.0\.1\.0\.0\.2\.ip6\.arpa$/);
  });
});

describe("observable detection", () => {
  it.each([
    ["8.8.8.8", "IPV4", "8.8.8.8"],
    ["8.8.8.8:53", "IPV4", "8.8.8.8"],
    ["[2001:db8::1]", "IPV6", "2001:db8::1"],
    ["Example.COM", "DOMAIN", "example.com"],
    ["example[.]com", "DOMAIN", "example.com"],
    ["hxxps://login-verify[.]net/login", "URL", "https://login-verify.net/login"],
    ["login-verify.net/path?a=1", "URL", "http://login-verify.net/path?a=1"],
    ["cve-2021-44228", "CVE", "CVE-2021-44228"],
    ["ASN 13335", "ASN", "AS13335"],
    ["44D88612FEA8A8F36DE82E1278ABB02F", "MD5", "44d88612fea8a8f36de82e1278abb02f"],
    ["3395856ce81f2b7382dee72602f798b642f14140", "SHA1", "3395856ce81f2b7382dee72602f798b642f14140"],
    ["user@Example.com", "EMAIL", "user@example.com"],
  ])("%s → %s", (input, type, normalized) => {
    const d = detectObservable(input);
    expect(d?.type).toBe(type);
    expect(d?.normalized).toBe(normalized);
  });

  it("rejects things that are not investigable", () => {
    for (const bad of ["", "hello", "not a domain", "file:///etc/passwd", "javascript:alert(1)", "corp.local", "999.1.1.1", "AS0"]) {
      expect(detectObservable(bad)).toBeNull();
    }
  });

  it("offers alternatives and honours an explicit type", () => {
    const sha = "a".repeat(64);
    expect(detectObservable(sha)?.alternatives).toContain("CERT_SHA256");
    expect(detectAs(sha, "CERT_SHA256")?.type).toBe("CERT_SHA256");
    expect(detectAs("8.8.8.8", "DOMAIN")).toBeNull();
    expect(detectAs("user@example.com", "DOMAIN")?.normalized).toBe("example.com");
  });

  it("uses the Public Suffix List", () => {
    expect(hostnameInfo("a.b.example.co.uk").registrableDomain).toBe("example.co.uk");
    expect(hostnameInfo("someone.github.io").privateSuffix).toBe("github.io");
    expect(hostnameInfo("xn--80ak6aa92e.com").unicode).toBe("аррӏе.com");
  });
});

describe("fanging", () => {
  it("round-trips", () => {
    expect(defang("https://evil.example/a.exe")).toBe("hxxps://evil[.]example/a[.]exe");
    expect(refang("hxxps://evil[.]example/a[.]exe")).toBe("https://evil.example/a.exe");
    expect(refang("user[at]example(.)com")).toBe("user@example.com");
  });
});

describe("URL structure analysis", () => {
  const rules = (u: string) => analyzeUrl(u)?.findings.map((f) => f.rule) ?? [];
  it("flags classic obfuscation patterns", () => {
    expect(rules("http://paypal.com@198.51.100.7/login")).toEqual(expect.arrayContaining(["url.userinfo", "url.ip-host", "url.cleartext"]));
    expect(rules("https://example.com/download/invoice.exe")).toContain("url.executable-path");
    expect(rules("https://example.com/r?url=https://evil.test/")).toContain("url.embedded-redirect");
    expect(rules("https://xn--pypal-4ve.com/")).toContain("host.idn-mixed-script");
    expect(rules("https://example.com:8443/")).toContain("url.nonstandard-port");
  });
  it("stays quiet for an ordinary HTTPS URL", () => {
    expect(rules("https://www.example.com/about")).toEqual([]);
  });
});

describe("indicator extraction", () => {
  it("refangs, validates and deduplicates", () => {
    const text = "C2 hxxp://203[.]0.113[.]7/gate.php and 203.0.113.7 again, 203.0.113.7. Hash 44d88612fea8a8f36de82e1278abb02f. CVE-2024-3400. not.a.real.tld.zzzz";
    const found = extractIndicators(text);
    const values = found.map((f) => `${f.type}:${f.value}`);
    expect(values).toContain("URL:http://203.0.113.7/gate.php");
    expect(values).toContain("IPV4:203.0.113.7");
    expect(values).toContain("MD5:44d88612fea8a8f36de82e1278abb02f");
    expect(values).toContain("CVE:CVE-2024-3400");
    expect(values.some((v) => v.includes("zzzz"))).toBe(false);
    expect(found.find((f) => f.value === "203.0.113.7")?.occurrences).toBe(2);
  });
});
