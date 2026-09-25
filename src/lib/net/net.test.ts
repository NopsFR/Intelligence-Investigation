import { describe, expect, it } from "vitest";
import { assertHostnameAllowed, safeLookup } from "./policy";
import { TargetRequestError, assertTargetUrl, targetRequest } from "./target";

describe("SSRF policy", () => {
  it.each(["file:///etc/passwd", "gopher://example.com/", "ftp://example.com/", "http://example.com:22/", "http://example.com:6379/", "http://localhost/", "http://metadata.google.internal/", "http://printer.local/", "http://intranet/", "not a url"])("refuses %s", (url) => {
    expect(() => assertTargetUrl(url)).toThrow(TargetRequestError);
  });

  it("allows ordinary web targets and strips embedded credentials", () => {
    const u = assertTargetUrl("https://user:pass@example.com:8443/x");
    expect(u.username).toBe("");
    expect(u.password).toBe("");
    expect(() => assertHostnameAllowed("example.com")).not.toThrow();
  });

  it("refuses to connect when a name resolves to a non-public address (connect-time check)", async () => {
    const err = await new Promise<NodeJS.ErrnoException | null>((resolve) => safeLookup("localhost", { all: true }, (e) => resolve(e)));
    expect(err?.code).toBe("ENOTALLOWED");
  });

  it.each(["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://10.0.0.1/", "http://[::ffff:127.0.0.1]/", "http://2130706433/"])("never connects to %s", async (url) => {
    await expect(targetRequest(url, { timeoutMs: 1000 })).rejects.toMatchObject({ kind: "policy" });
  });
});
