import { describe, expect, it } from "vitest";
import { EVENT_ID_REFERENCE } from "./eventids";
import { compareHashSets, hashKind, parseHashList } from "./hashcompare";
import { parseProcessListing } from "./processtree";
import { buildTimeline } from "./timeline";

describe("hash compare", () => {
  it("identifies hash algorithms by length", () => {
    expect(hashKind("d41d8cd98f00b204e9800998ecf8427e")).toBe("MD5");
    expect(hashKind("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toBe("SHA-1");
    expect(hashKind("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).toBe("SHA-256");
    expect(hashKind("not-a-hash")).toBeNull();
  });

  it("parses mixed-format lists and dedupes", () => {
    const list = parseHashList("d41d8cd98f00b204e9800998ecf8427e\nlabel: D41D8CD98F00B204E9800998ECF8427E\nfoo,bar\nnot-a-hash\n");
    expect(list).toEqual(["d41d8cd98f00b204e9800998ecf8427e"]);
  });

  it("computes set membership across named sets", () => {
    const result = compareHashSets([
      { label: "A", values: ["h1", "h2"] },
      { label: "B", values: ["h2", "h3"] },
    ]);
    expect(result.setCount).toBe(2);
    expect(result.rows.find((r) => r.value === "h2")).toMatchObject({ count: 2, sets: expect.arrayContaining(["A", "B"]) });
    expect(result.inAll).toBe(1);
    expect(result.onlyOne).toBe(2);
  });

  it("ignores unlabeled sets", () => {
    const result = compareHashSets([
      { label: "", values: ["h1"] },
      { label: "B", values: ["h2"] },
    ]);
    expect(result.setCount).toBe(1);
    expect(result.rows.map((r) => r.value)).toEqual(["h2"]);
  });
});

describe("process tree", () => {
  it("parses a CSV table into a tree by pid/ppid", () => {
    const csv = "pid,ppid,name,commandline\n4,0,System,\n600,4,services.exe,\n1200,600,svchost.exe,svchost.exe -k netsvcs\n5000,1200,powershell.exe,powershell -enc AAA\n";
    const r = parseProcessListing(csv);
    expect(r.format).toBe("table");
    expect(r.total).toBe(4);
    expect(r.roots).toHaveLength(1);
    expect(r.roots[0].name).toBe("System");
    expect(r.roots[0].children[0].children[0].children[0].name).toBe("powershell.exe");
  });

  it("parses Sysmon-style ProcessId/ParentProcessId blocks", () => {
    const text = `
Process Create:
ProcessId: 5000
ParentProcessId: 1200
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell -enc AAA
User: CORP\\j.doe
UtcTime: 2026-09-25 09:12:04.550

Process Create:
ProcessId: 1200
ParentProcessId: 600
Image: C:\\Windows\\System32\\svchost.exe
CommandLine: svchost.exe -k netsvcs
`;
    const r = parseProcessListing(text);
    expect(r.format).toBe("sysmon");
    expect(r.total).toBe(2);
    // 5000's parent (1200) is present, so it nests; 1200's parent (600) is absent, so 1200 is an orphan root.
    expect(r.orphans.map((n) => n.pid)).toEqual(["1200"]);
    expect(r.orphans[0].children[0].pid).toBe("5000");
  });

  it("reports an unrecognised format instead of guessing", () => {
    const r = parseProcessListing("just some random text\nwith no structure\n");
    expect(r.format).toBe("unknown");
    expect(r.warnings.length).toBeGreaterThan(0);
  });

  it("flags duplicate PIDs", () => {
    const csv = "pid,ppid,name\n1,0,a\n1,0,b\n";
    const r = parseProcessListing(csv);
    expect(r.warnings.some((w) => /Duplicate/.test(w))).toBe(true);
  });
});

describe("timeline builder", () => {
  it("parses ISO, syslog and Apache-style timestamps and sorts chronologically", () => {
    const r = buildTimeline([
      { label: "edr", text: "2026-09-25T09:20:00.000Z alert fired\n2026-09-25T09:12:00.000Z process started" },
      { label: "web", text: "[25/Sep/2026:09:15:00 +0000] GET /admin 403" },
    ]);
    expect(r.events).toHaveLength(3);
    expect(r.events.map((e) => e.source)).toEqual(["edr", "web", "edr"]);
    expect(r.events[0].text).toBe("process started");
    expect(new Date(r.events[0].iso).getTime()).toBeLessThan(new Date(r.events[2].iso).getTime());
  });

  it("skips lines without a recognisable timestamp and counts them", () => {
    const r = buildTimeline([{ label: "log", text: "2026-09-25T09:12:00.000Z ok\nno timestamp here\n" }]);
    expect(r.events).toHaveLength(1);
    expect(r.skipped).toBe(1);
  });

  it("ignores sources with an empty label", () => {
    const r = buildTimeline([{ label: "", text: "2026-09-25T09:12:00.000Z ok" }]);
    expect(r.events).toHaveLength(0);
  });
});

describe("event ID reference", () => {
  it("has no duplicate (channel, id) pairs except intentional cross-references", () => {
    const seen = new Map<string, number>();
    for (const e of EVENT_ID_REFERENCE) {
      const key = `${e.channel}:${e.id}`;
      seen.set(key, (seen.get(key) ?? 0) + 1);
    }
    const dupes = [...seen.entries()].filter(([, n]) => n > 1);
    // 4738 is intentionally listed twice (account & group management, cross-referenced).
    expect(dupes.every(([k]) => k === "Security:4738")).toBe(true);
  });

  it("every entry has a non-empty description", () => {
    for (const e of EVENT_ID_REFERENCE) expect(e.description.length).toBeGreaterThan(10);
  });
});
