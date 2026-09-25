import { describe, expect, it } from "vitest";
import { classifyError, ProviderHttpError } from "./base";
import { TimeoutError, ResponseTooLargeError } from "@/lib/security/safeFetch";

describe("classifyError", () => {
  it("classifies timeouts", () => {
    expect(classifyError(new TimeoutError()).status).toBe("TIMEOUT");
  });

  it("classifies oversized responses", () => {
    expect(classifyError(new ResponseTooLargeError()).status).toBe("INVALID_RESPONSE");
  });

  it("classifies 401/403 as auth failures", () => {
    expect(classifyError(new ProviderHttpError(401, "x")).status).toBe("AUTH_FAILED");
    expect(classifyError(new ProviderHttpError(403, "x")).status).toBe("AUTH_FAILED");
  });

  it("classifies 429 as rate limited", () => {
    expect(classifyError(new ProviderHttpError(429, "x")).status).toBe("RATE_LIMITED");
  });

  it("classifies 5xx as unavailable", () => {
    expect(classifyError(new ProviderHttpError(503, "x")).status).toBe("UNAVAILABLE");
  });

  it("classifies other 4xx as invalid response", () => {
    expect(classifyError(new ProviderHttpError(404, "x")).status).toBe("INVALID_RESPONSE");
  });

  it("classifies malformed JSON", () => {
    expect(classifyError(new Error("INVALID_JSON")).status).toBe("INVALID_RESPONSE");
  });

  it("classifies schema mismatches", () => {
    expect(classifyError(new Error("SCHEMA_MISMATCH")).status).toBe("INVALID_RESPONSE");
  });

  it("classifies generic errors as network errors", () => {
    expect(classifyError(new Error("boom")).status).toBe("NETWORK_ERROR");
  });

  it("classifies unknown throwables", () => {
    expect(classifyError("not an error").status).toBe("NETWORK_ERROR");
  });
});
