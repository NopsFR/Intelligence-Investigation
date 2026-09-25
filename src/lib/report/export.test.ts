import { describe, expect, it } from "vitest";
import type { InvestigationRecord } from "@/lib/core/types";
import { findingsCsv, reportMarkdown } from "./export";

const inv: InvestigationRecord = {
  id: "abc12345",
  createdAt: "2026-09-25T10:00:00.000Z",
  updatedAt: "2026-09-25T10:00:05.000Z",
  observable: "https://evil.com/x",
  observableType: "URL",
  normalizedObservable: "https://evil.com/x",
  mode: "QUICK",
  status: "COMPLETE",
  summary: "1 high finding",
  plan: [],
  providerResults: [],
  relationships: [],
  findings: [
    { id: "f1", rule: "r", severity: "HIGH", category: "c", title: "=HYPERLINK(\"http://x\")", description: "d", evidence: "seen at https://evil.com/x", source: "urlhaus", observedAt: "2026-09-25T10:00:01.000Z" },
  ],
};

describe("exports", () => {
  it("neutralises spreadsheet formulas in CSV", () => {
    const csv = findingsCsv(inv, {});
    expect(csv).toContain(`"'=HYPERLINK(""http://x"")"`);
  });
  it("defangs observables in Markdown reports", () => {
    const md = reportMarkdown(inv, { urlhaus: "URLhaus" });
    expect(md).toContain("hxxps://evil[.]com/x");
    expect(md).not.toMatch(/https:\/\/evil\.com/);
    expect(md).toContain("Source: URLhaus");
  });
});
