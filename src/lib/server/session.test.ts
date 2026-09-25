import { afterEach, describe, expect, it, vi } from "vitest";
import { issueSession, operatorConfigured, verifySession, verifyToken } from "./session";

afterEach(() => vi.unstubAllEnvs());

describe("operator session", () => {
  it("is disabled without a token", () => {
    vi.stubEnv("NOPS_ADMIN_TOKEN", "");
    expect(operatorConfigured()).toBe(false);
    expect(verifyToken("anything")).toBe(false);
    expect(issueSession()).toBeNull();
  });

  it("verifies the token and signed, expiring cookies", () => {
    vi.stubEnv("NOPS_ADMIN_TOKEN", "correct horse battery staple");
    expect(verifyToken("correct horse battery staple")).toBe(true);
    expect(verifyToken("correct horse battery stapl")).toBe(false);
    const cookie = issueSession()!;
    expect(verifySession(cookie)).toBe(true);
    const [v, exp, mac] = cookie.split(".");
    expect(verifySession(`${v}.${Number(exp) + 3600}.${mac}`)).toBe(false);
    expect(verifySession(`${v}.${exp}.${mac.slice(0, -2)}AA`)).toBe(false);
    expect(verifySession(cookie, Date.now() + 13 * 3600 * 1000)).toBe(false);
    expect(verifySession(undefined)).toBe(false);
  });

  it("rotating the token invalidates existing sessions", () => {
    vi.stubEnv("NOPS_ADMIN_TOKEN", "first-token-value");
    const cookie = issueSession()!;
    vi.stubEnv("NOPS_ADMIN_TOKEN", "second-token-value");
    expect(verifySession(cookie)).toBe(false);
  });
});
