import { describe, expect, it } from "vitest";
import { SIGMA_EXAMPLES, SYNTHETIC_EVENTS } from "./samples";
import { SigmaError, convertSigma, evaluateSigma, expandValue, flattenEvent, parseEvents, parseSigma } from "./sigma";

describe("parseSigma", () => {
  it("parses the sample rules with no warnings", () => {
    for (const ex of SIGMA_EXAMPLES) {
      const [rule] = parseSigma(ex.source);
      expect(rule.title).toBeTruthy();
      expect(rule.warnings).toEqual([]);
    }
  });

  it("extracts ATT&CK technique tags", () => {
    const [rule] = parseSigma(SIGMA_EXAMPLES.find((e) => e.id === "encoded-ps")!.source);
    expect(rule.attack).toEqual(expect.arrayContaining(["T1059.001"]));
  });

  it("rejects a rule with no detection", () => {
    expect(() => parseSigma("title: x\nlogsource: {}\n")).toThrow(SigmaError);
  });

  it("rejects a rule with no condition", () => {
    expect(() => parseSigma("title: x\nlogsource: {}\ndetection:\n  sel:\n    Image: a\n")).toThrow(/condition/);
  });

  it("rejects an unknown modifier", () => {
    expect(() => parseSigma("title: x\nlogsource: {}\ndetection:\n  sel:\n    Image|nosuchmod: a\n  condition: sel\n")).toThrow(/modifier/);
  });

  it("rejects an unknown search identifier in the condition", () => {
    expect(() => parseSigma("title: x\nlogsource: {}\ndetection:\n  sel:\n    Image: a\n  condition: other\n")).toThrow(/Unknown search/);
  });

  it("rejects correlation and aggregation rules by name", () => {
    expect(() => parseSigma("title: x\ncorrelation:\n  type: event_count\n")).toThrow(/[Cc]orrelation/);
    expect(() => parseSigma("title: x\nlogsource: {}\ndetection:\n  sel:\n    Image: a\n  condition: sel | count() > 5\n")).toThrow(/aggregation/);
  });

  it("warns on a non-namespaced tag and non-UUID id", () => {
    const [rule] = parseSigma("title: x\nid: not-a-uuid\nlogsource: {}\ntags: [weird]\ndetection:\n  sel:\n    Image: a\n  condition: sel\n");
    expect(rule.warnings.some((w) => /UUID/.test(w))).toBe(true);
    expect(rule.warnings.some((w) => /Tag/.test(w))).toBe(true);
  });
});

describe("condition language", () => {
  const src = (cond: string) => `title: x\nlogsource: {}\ndetection:\n  a:\n    Image: 'x'\n  b:\n    User: 'y'\n  c:\n    Host: 'z'\n  condition: ${cond}\n`;
  const events = [{ Image: "x", User: "y", Host: "z" }];

  it("supports and / or / not with correct precedence (AND binds tighter than OR)", () => {
    // a is false, so "a and b" is false regardless of b; only the OR c=true saves it.
    const onlyC = [{ Image: "no", User: "no", Host: "z" }];
    expect(evaluateSigma(parseSigma(src("a and b or c"))[0], onlyC)).toHaveLength(1);
    // With explicit grouping, a is required, so no match even though c is true.
    expect(evaluateSigma(parseSigma(src("a and (b or c)"))[0], onlyC)).toHaveLength(0);
    expect(evaluateSigma(parseSigma(src("not a"))[0], events)).toHaveLength(0);
  });

  it("supports 1 of / all of with wildcard patterns", () => {
    expect(evaluateSigma(parseSigma(src("1 of a"))[0], events)).toHaveLength(1);
    expect(evaluateSigma(parseSigma(src("all of *"))[0], events)).toHaveLength(1);
    expect(evaluateSigma(parseSigma(src("all of *"))[0], [{ Image: "x" }])).toHaveLength(0);
  });
});

describe("field matching", () => {
  const rule = (detection: string) => parseSigma(`title: x\nlogsource: {}\ndetection:\n${detection}\n  condition: sel\n`)[0];

  it("matches wildcards, contains, startswith, endswith", () => {
    expect(evaluateSigma(rule("  sel:\n    Image|endswith: '\\\\cmd.exe'\n"), [{ Image: "C:\\\\Windows\\\\System32\\\\cmd.exe" }])).toHaveLength(1);
    expect(evaluateSigma(rule("  sel:\n    CommandLine|contains: 'whoami'\n"), [{ CommandLine: "cmd /c whoami /all" }])).toHaveLength(1);
    expect(evaluateSigma(rule("  sel:\n    Image: 'C:\\\\*\\\\cmd.exe'\n"), [{ Image: "C:\\\\Windows\\\\cmd.exe" }])).toHaveLength(1);
  });

  it("matches case-insensitively by default and honours |cased", () => {
    expect(evaluateSigma(rule("  sel:\n    User: 'Alice'\n"), [{ User: "alice" }])).toHaveLength(1);
    expect(evaluateSigma(rule("  sel:\n    User|cased: 'Alice'\n"), [{ User: "alice" }])).toHaveLength(0);
  });

  it("evaluates numeric comparisons", () => {
    expect(evaluateSigma(rule("  sel:\n    EventID|gte: 100\n"), [{ EventID: 150 }])).toHaveLength(1);
    expect(evaluateSigma(rule("  sel:\n    EventID|gte: 100\n"), [{ EventID: 50 }])).toHaveLength(0);
  });

  it("evaluates CIDR matches", () => {
    expect(evaluateSigma(rule("  sel:\n    DestinationIp|cidr: '10.0.0.0/8'\n"), [{ DestinationIp: "10.1.2.3" }])).toHaveLength(1);
    expect(evaluateSigma(rule("  sel:\n    DestinationIp|cidr: '10.0.0.0/8'\n"), [{ DestinationIp: "192.168.1.1" }])).toHaveLength(0);
  });

  it("evaluates regular expressions with the |re modifier (case-sensitive unless |i is added)", () => {
    expect(evaluateSigma(rule("  sel:\n    CommandLine|re: 'ex(pression|ec)'\n"), [{ CommandLine: "invoke-expression foo" }])).toHaveLength(1);
    expect(evaluateSigma(rule("  sel:\n    CommandLine|re: 'ex(pression|ec)'\n"), [{ CommandLine: "Invoke-Expression foo" }])).toHaveLength(0);
    expect(evaluateSigma(rule("  sel:\n    CommandLine|re|i: 'ex(pression|ec)'\n"), [{ CommandLine: "Invoke-Expression foo" }])).toHaveLength(1);
  });

  it("treats null as a match for a missing or empty field", () => {
    expect(evaluateSigma(rule("  sel:\n    ParentCommandLine: null\n"), [{}])).toHaveLength(1);
    expect(evaluateSigma(rule("  sel:\n    ParentCommandLine: null\n"), [{ ParentCommandLine: "x" }])).toHaveLength(0);
  });

  it("resolves Sysmon field aliases", () => {
    expect(evaluateSigma(rule("  sel:\n    Image|endswith: 'cmd.exe'\n"), [{ process: { executable: "C:\\\\Windows\\\\cmd.exe" } }])).toHaveLength(1);
  });

  it("evaluates keyword-only searches against the whole event", () => {
    const [r] = parseSigma("title: x\nlogsource: {}\ndetection:\n  kw:\n    - 'mimikatz'\n    - 'lsass'\n  condition: kw\n");
    expect(evaluateSigma(r, [{ CommandLine: "run mimikatz.exe" }])).toHaveLength(1);
    expect(evaluateSigma(r, [{ CommandLine: "run notepad.exe" }])).toHaveLength(0);
  });
});

describe("flattenEvent", () => {
  it("flattens nested objects and indexes EventData children by their own key", () => {
    const flat = flattenEvent({ EventData: { TargetFilename: "C:\\\\x" }, process: { pe: { original_file_name: "svchost.exe" } } });
    expect(flat.get("targetfilename")).toBe("C:\\\\x");
    expect(flat.get("eventdata.targetfilename")).toBe("C:\\\\x");
    expect(flat.get("process.pe.original_file_name")).toBe("svchost.exe");
  });
});

describe("expandValue", () => {
  it("produces windash variants", () => {
    expect(expandValue("run -enc", ["windash"])).toEqual(expect.arrayContaining(["run -enc", "run /enc", "run –enc"]));
  });
  it("base64-encodes with three offsets", () => {
    const v = expandValue("cmd", ["base64offset"]);
    expect(v).toHaveLength(3);
    expect(atob(v[0])).toContain("cmd");
  });
});

describe("parseEvents", () => {
  it("parses the bundled synthetic events as JSON", () => {
    const { events, format } = parseEvents(SYNTHETIC_EVENTS);
    expect(format).toBe("JSON array");
    expect(events.length).toBeGreaterThan(3);
  });

  it("parses NDJSON", () => {
    const { events, format } = parseEvents('{"a":1}\n{"a":2}\n');
    expect(format).toBe("NDJSON");
    expect(events).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("parses CSV with a header row", () => {
    const { events } = parseEvents("Image,User\nC:\\\\cmd.exe,alice\n");
    expect(events).toEqual([{ Image: "C:\\\\cmd.exe", User: "alice" }]);
  });

  it("parses Windows Event XML Data elements", () => {
    const xml = `<Event><System><EventID>4688</EventID><Computer>WS1</Computer></System><EventData><Data Name="Image">C:\\\\cmd.exe</Data><Data Name="CommandLine">cmd /c dir</Data></EventData></Event>`;
    const { events, format } = parseEvents(xml);
    expect(format).toMatch(/XML/);
    expect(events[0]).toMatchObject({ Image: "C:\\\\cmd.exe", CommandLine: "cmd /c dir", EventID: 4688 });
  });
});

describe("convertSigma", () => {
  it("produces a query for every backend without throwing", () => {
    for (const ex of SIGMA_EXAMPLES) {
      const [rule] = parseSigma(ex.source);
      for (const backend of ["splunk", "kql", "lucene"] as const) {
        const { query } = convertSigma(rule, backend);
        expect(query.length).toBeGreaterThan(0);
      }
    }
  });

  it("rejects Splunk conversion of a rule using |re (no safe inline equivalent)", () => {
    const [rule] = parseSigma("title: x\nlogsource: {}\ndetection:\n  sel:\n    CommandLine|re: 'a.*b'\n  condition: sel\n");
    expect(() => convertSigma(rule, "splunk")).toThrow(SigmaError);
    expect(convertSigma(rule, "kql").query).toContain("matches regex");
    expect(convertSigma(rule, "lucene").query).toContain("/a.*b/");
  });
});

describe("bundled examples end to end", () => {
  const { events } = parseEvents(SYNTHETIC_EVENTS);

  it("matches the expected synthetic events for each example rule", () => {
    const expected: Record<string, number> = { "encoded-ps": 1, "office-shell": 1, shadow: 1, "log-clear": 1 };
    for (const ex of SIGMA_EXAMPLES) {
      const [rule] = parseSigma(ex.source);
      const matches = evaluateSigma(rule, events);
      expect(matches.length, ex.id).toBe(expected[ex.id]);
    }
  });
});
