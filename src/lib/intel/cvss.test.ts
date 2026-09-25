import { describe, expect, it } from "vitest";
import { parseCvssVector, severityFromScore } from "./cvss";

describe("CVSS", () => {
  it("decodes v3.1 and v4.0 vectors", () => {
    const v3 = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(v3?.version).toBe("3.1");
    expect(v3?.metrics.find((m) => m.key === "AV")?.value).toBe("Network");
    const v4 = parseCvssVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(v4?.metrics.find((m) => m.key === "AT")?.metric).toBe("Attack requirements");
    expect(parseCvssVector("AV:N/AC:L/Au:N/C:P/I:P/A:P")?.version).toBe("2.0");
    expect(parseCvssVector("nonsense")).toBeNull();
  });

  it("maps scores to qualitative ratings", () => {
    expect(severityFromScore(10)).toBe("CRITICAL");
    expect(severityFromScore(7.5)).toBe("HIGH");
    expect(severityFromScore(4)).toBe("MEDIUM");
    expect(severityFromScore(0.1)).toBe("LOW");
    expect(severityFromScore(0)).toBe("NONE");
    expect(severityFromScore(9.3, "2.0")).toBe("HIGH");
  });
});
