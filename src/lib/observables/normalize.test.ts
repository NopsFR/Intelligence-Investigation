import { describe, expect, it } from "vitest";
import { normalizeObservable, normalizeCertName } from "./normalize";

describe("normalizeObservable", () => {
  it("lowercases and trims trailing dot from domains", () => {
    expect(normalizeObservable("Example.COM.", "DOMAIN")).toBe("example.com");
  });

  it("uppercases CVE ids", () => {
    expect(normalizeObservable("cve-2021-44228", "CVE")).toBe("CVE-2021-44228");
  });

  it("formats ASN with AS prefix", () => {
    expect(normalizeObservable("12345", "ASN")).toBe("AS12345");
    expect(normalizeObservable("AS 12345", "ASN")).toBe("AS12345");
  });

  it("lowercases hashes", () => {
    expect(normalizeObservable("ABCDEF1234567890ABCDEF1234567890", "MD5")).toBe(
      "abcdef1234567890abcdef1234567890"
    );
  });
});

describe("normalizeCertName", () => {
  it("strips wildcard prefixes", () => {
    expect(normalizeCertName("*.example.com")).toBe("example.com");
  });

  it("rejects names containing spaces or invalid characters", () => {
    expect(normalizeCertName("not a domain")).toBeNull();
    expect(normalizeCertName("user@example.com")).toBeNull();
  });

  it("lowercases names", () => {
    expect(normalizeCertName("API.Example.com")).toBe("api.example.com");
  });
});
