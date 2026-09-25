import { describe, expect, it } from "vitest";
import { detectObservable } from "./detect";

describe("detectObservable", () => {
  it("detects IPv4 addresses", () => {
    expect(detectObservable("8.8.8.8")?.type).toBe("IPV4");
    expect(detectObservable("255.255.255.255")?.type).toBe("IPV4");
  });

  it("detects IPv6 addresses", () => {
    expect(detectObservable("2001:4860:4860::8888")?.type).toBe("IPV6");
    expect(detectObservable("::1")?.type).toBe("IPV6");
  });

  it("detects domains", () => {
    expect(detectObservable("example.com")?.type).toBe("DOMAIN");
    expect(detectObservable("sub.example.co.uk")?.type).toBe("DOMAIN");
  });

  it("normalizes domains to lowercase", () => {
    expect(detectObservable("Example.COM")?.normalized).toBe("example.com");
  });

  it("detects URLs and requires a scheme", () => {
    expect(detectObservable("https://example.com")?.type).toBe("URL");
    expect(detectObservable("http://example.com/path?x=1")?.type).toBe("URL");
  });

  it("detects MD5 hashes", () => {
    expect(detectObservable("d41d8cd98f00b204e9800998ecf8427e")?.type).toBe("MD5");
  });

  it("detects SHA1 hashes", () => {
    expect(detectObservable("da39a3ee5e6b4b0d3255bfef95601890afd80709")?.type).toBe("SHA1");
  });

  it("detects SHA256 hashes", () => {
    expect(
      detectObservable("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?.type
    ).toBe("SHA256");
  });

  it("detects CVE identifiers and uppercases them", () => {
    const result = detectObservable("cve-2026-12345");
    expect(result?.type).toBe("CVE");
    expect(result?.normalized).toBe("CVE-2026-12345");
  });

  it("detects ASN identifiers", () => {
    expect(detectObservable("AS12345")?.type).toBe("ASN");
    expect(detectObservable("as12345")?.normalized).toBe("AS12345");
  });

  it("returns null for empty or whitespace input", () => {
    expect(detectObservable("")).toBeNull();
    expect(detectObservable("   ")).toBeNull();
  });

  it("returns null for garbage input", () => {
    expect(detectObservable("!!!not-an-observable###")).toBeNull();
  });

  it("returns null for a malformed URL", () => {
    expect(detectObservable("ftp://example.com")).toBeNull();
  });

  it("returns null for an invalid hash length", () => {
    expect(detectObservable("d41d8cd98f00b204e9800998ecf8427")).toBeNull(); // 31 chars
  });

  it("returns null for an invalid CVE format", () => {
    expect(detectObservable("CVE-26-123")).toBeNull();
  });

  it("returns null for an invalid IPv4 address", () => {
    expect(detectObservable("999.999.999.999")).toBeNull();
  });

  it("does not misclassify a bare IPv4 address as a domain", () => {
    expect(detectObservable("192.168.1.1")?.type).toBe("IPV4");
  });
});
