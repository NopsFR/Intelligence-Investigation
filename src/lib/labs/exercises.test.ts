import { describe, expect, it } from "vitest";
import {
  deserializeProfileSafe,
  deserializeProfileVulnerable,
  escapeHtml,
  getInvoiceSafe,
  getInvoiceVulnerable,
  pingHostSafe,
  pingHostVulnerable,
  readUploadedFileSafe,
  readUploadedFileVulnerable,
  sqlLoginSafe,
  sqlLoginVulnerable,
} from "./exercises";

describe("SQL injection exercise", () => {
  it("logs in normally with correct credentials", () => {
    const r = sqlLoginVulnerable("alice", "alice-pw-2024");
    expect(r.matched?.username).toBe("alice");
  });

  it("rejects wrong credentials", () => {
    expect(sqlLoginVulnerable("alice", "wrong").matched).toBeNull();
    expect(sqlLoginSafe("alice", "wrong").matched).toBeNull();
  });

  it("bypasses auth with a comment-terminated injection, impersonating a specific user", () => {
    const r = sqlLoginVulnerable("admin' --", "anything");
    expect(r.matched?.username).toBe("admin");
  });

  it("bypasses auth with an OR-based injection once the password check is commented out", () => {
    const r = sqlLoginVulnerable("' OR '1'='1' --", "anything");
    expect(r.matched).not.toBeNull();
  });

  it("a bare OR payload does NOT bypass because AND binds tighter than OR (accurate precedence)", () => {
    const r = sqlLoginVulnerable("' OR '1'='1", "wrong-password");
    expect(r.matched).toBeNull();
  });

  it("the fixed version treats the injection string as a literal username and rejects it", () => {
    const r = sqlLoginSafe("admin' --", "anything");
    expect(r.matched).toBeNull();
  });
});

describe("path traversal exercise", () => {
  it("reads a legitimate file inside uploads", () => {
    const r = readUploadedFileVulnerable("readme.txt");
    expect(r.content).toContain("Welcome");
  });

  it("vulnerable version escapes the uploads root via ../..", () => {
    const r = readUploadedFileVulnerable("../etc/nops/secrets.env");
    expect(r.content).toContain("DATABASE_URL");
  });

  it("fixed version rejects the same traversal payload", () => {
    const r = readUploadedFileSafe("../etc/nops/secrets.env");
    expect(r.error).toMatch(/escapes/);
    expect(r.content).toBeUndefined();
  });

  it("fixed version still serves legitimate files", () => {
    const r = readUploadedFileSafe("avatar.png");
    expect(r.content).toBe("(binary image data)");
  });
});

describe("IDOR exercise", () => {
  it("vulnerable endpoint returns another user's invoice by ID alone", () => {
    const r = getInvoiceVulnerable(1002);
    expect("invoice" in r && r.invoice.description).toContain("ACME");
  });

  it("fixed endpoint forbids access to another user's invoice", () => {
    const r = getInvoiceSafe(1002);
    expect("error" in r && r.error).toMatch(/Forbidden/);
  });

  it("fixed endpoint allows access to the current user's own invoice", () => {
    const r = getInvoiceSafe(1001);
    expect("invoice" in r && r.invoice.id).toBe(1001);
  });
});

describe("insecure deserialization exercise", () => {
  it("vulnerable version grants admin from a client-tampered role field", () => {
    const r = deserializeProfileVulnerable(JSON.stringify({ username: "alice", role: "admin" }));
    expect("profile" in r && r.profile.role).toBe("admin");
  });

  it("fixed version ignores the client role and looks it up server-side", () => {
    const r = deserializeProfileSafe(JSON.stringify({ username: "alice", role: "admin" }));
    expect("profile" in r && r.profile.role).toBe("user");
  });

  it("rejects invalid JSON", () => {
    const r = deserializeProfileVulnerable("{not json");
    expect("error" in r).toBe(true);
  });
});

describe("command injection exercise", () => {
  it("vulnerable ping chains a second command after a semicolon", () => {
    const out = pingHostVulnerable("example.com; cat /etc/passwd");
    expect(out).toContain("root:x:0:0");
  });

  it("fixed ping rejects a hostname containing shell metacharacters", () => {
    const out = pingHostSafe("example.com; cat /etc/passwd");
    expect(out).toMatch(/Rejected/);
  });

  it("fixed ping still runs for a legitimate hostname", () => {
    const out = pingHostSafe("example.com");
    expect(out).toContain("PING example.com");
  });
});

describe("escapeHtml", () => {
  it("neutralises a script tag", () => {
    expect(escapeHtml("<script>alert(1)</script>")).toBe("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});
