import { describe, expect, it } from "vitest";
import { investigateRequestSchema, cisaKevResponseSchema, abuseIpDbResponseSchema } from "./schemas";

describe("investigateRequestSchema", () => {
  it("accepts a valid request", () => {
    const result = investigateRequestSchema.safeParse({ observable: "8.8.8.8", mode: "QUICK" });
    expect(result.success).toBe(true);
  });

  it("defaults mode to QUICK when omitted", () => {
    const result = investigateRequestSchema.parse({ observable: "8.8.8.8" });
    expect(result.mode).toBe("QUICK");
  });

  it("rejects an empty observable", () => {
    expect(investigateRequestSchema.safeParse({ observable: "" }).success).toBe(false);
  });

  it("rejects an invalid mode", () => {
    expect(investigateRequestSchema.safeParse({ observable: "x", mode: "ULTRA" }).success).toBe(false);
  });
});

describe("cisaKevResponseSchema", () => {
  it("accepts a well-formed feed", () => {
    const result = cisaKevResponseSchema.safeParse({
      vulnerabilities: [{ cveID: "CVE-2021-44228", dateAdded: "2021-12-10" }],
    });
    expect(result.success).toBe(true);
  });

  it("rejects a feed missing required fields", () => {
    const result = cisaKevResponseSchema.safeParse({ vulnerabilities: [{ dateAdded: "2021-12-10" }] });
    expect(result.success).toBe(false);
  });
});

describe("abuseIpDbResponseSchema", () => {
  it("rejects a response missing the data envelope", () => {
    const result = abuseIpDbResponseSchema.safeParse({ ipAddress: "1.2.3.4" });
    expect(result.success).toBe(false);
  });
});
