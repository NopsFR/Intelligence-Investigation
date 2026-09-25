import { describe, expect, it } from "vitest";
import { detectTechnologies, parseSecurityTxt, parseSetCookie } from "./analyze";

describe("parseSetCookie", () => {
  it("extracts name and flags", () => {
    expect(parseSetCookie("session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")).toEqual({ raw: "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict", name: "session", secure: true, httpOnly: true, sameSite: "Strict" });
  });

  it("reports missing flags as false / undefined", () => {
    const c = parseSetCookie("tracker=xyz; Path=/");
    expect(c).toMatchObject({ name: "tracker", secure: false, httpOnly: false, sameSite: undefined });
  });
});

describe("parseSecurityTxt", () => {
  it("parses RFC 9116 fields, ignoring comments", () => {
    const fields = parseSecurityTxt("# comment\nContact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\nContact: https://example.com/report\n");
    expect(fields.Contact).toEqual(["mailto:security@example.com", "https://example.com/report"]);
    expect(fields.Expires).toEqual(["2027-01-01T00:00:00.000Z"]);
  });

  it("returns no fields for a body with none", () => {
    expect(parseSecurityTxt("# just a comment\n")).toEqual({});
  });
});

describe("detectTechnologies", () => {
  it("recognises servers, CDNs and frameworks from headers and body", () => {
    const tech = detectTechnologies({ server: "cloudflare", "cf-ray": "abc123-LHR" }, "<html></html>");
    expect(tech).toContain("Cloudflare");
  });

  it("recognises a framework from body markers", () => {
    expect(detectTechnologies({}, '<html><body><div id="app" data-reactroot=""></div><script src="/_next/static/x.js"></script></body></html>')).toEqual(expect.arrayContaining(["Next.js", "React"]));
  });

  it("recognises WordPress from asset paths", () => {
    expect(detectTechnologies({}, '<link rel="stylesheet" href="/wp-content/themes/x/style.css">')).toContain("WordPress");
  });

  it("returns nothing when no indicator matches", () => {
    expect(detectTechnologies({}, "<html><body>hello</body></html>")).toEqual([]);
  });
});
