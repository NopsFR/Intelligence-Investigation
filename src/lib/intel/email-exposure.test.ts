import { describe, expect, it } from "vitest";
import { isDisposableEmailDomain, summarizeExposure, type HibpAccountResult } from "./email-exposure";

describe("isDisposableEmailDomain", () => {
  it("flags a known disposable provider", () => {
    expect(isDisposableEmailDomain("mailinator.com")).toBe(true);
    expect(isDisposableEmailDomain("Mailinator.COM")).toBe(true);
  });

  it("does not flag an ordinary domain", () => {
    expect(isDisposableEmailDomain("gmail.com")).toBe(false);
    expect(isDisposableEmailDomain("example.com")).toBe(false);
  });
});

describe("summarizeExposure", () => {
  it("reports not-configured with zero breaches when HIBP has no key", () => {
    const account: HibpAccountResult = { status: "not-configured", breaches: [] };
    const overview = summarizeExposure(account);
    expect(overview.status).toBe("not-configured");
    expect(overview.breachCount).toBe(0);
    expect(overview.passwordExposed).toBe(false);
  });

  it("computes earliest/latest breach dates, data classes, and stealer-log count", () => {
    const account: HibpAccountResult = {
      status: "confirmed",
      breaches: [
        { Name: "A", Title: "Alpha", BreachDate: "2019-01-01", DataClasses: ["Email addresses", "Passwords"], IsStealerLog: false },
        { Name: "B", Title: "Beta", BreachDate: "2021-06-15", DataClasses: ["Usernames"], IsStealerLog: true },
        { Name: "C", Title: "Gamma", BreachDate: "2015-03-10", DataClasses: ["Email addresses"], IsStealerLog: false },
      ],
    };
    const overview = summarizeExposure(account);
    expect(overview.status).toBe("confirmed-exposure");
    expect(overview.breachCount).toBe(3);
    expect(overview.earliestBreach).toBe("2015-03-10");
    expect(overview.latestBreach).toBe("2021-06-15");
    expect(overview.dataClasses).toEqual(["Email addresses", "Passwords", "Usernames"]);
    expect(overview.stealerLogCount).toBe(1);
    expect(overview.passwordExposed).toBe(true);
  });

  it("reports no password exposure when no breach includes a password data class", () => {
    const account: HibpAccountResult = { status: "confirmed", breaches: [{ Name: "A", Title: "Alpha", DataClasses: ["Usernames"] }] };
    expect(summarizeExposure(account).passwordExposed).toBe(false);
  });
});
