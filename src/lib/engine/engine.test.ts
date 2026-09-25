import { describe, expect, it } from "vitest";
import type { PlanStep, ProviderOutcome } from "@/lib/core/types";
import { buildPlan, getProvider, planSkipReason } from "@/lib/providers/registry";
import { executePlan } from "./plan-runner";

const done = (provider: string): ProviderOutcome => ({ provider, status: "SUCCESS", latencyMs: 1, retrievedAt: new Date().toISOString() });

describe("plan runner", () => {
  it("honours dependencies and passes their outcomes", async () => {
    const order: string[] = [];
    const plan: PlanStep[] = [{ id: "c", dependsOn: ["a", "b"] }, { id: "a" }, { id: "b", dependsOn: ["a"] }];
    const seen = new Map<string, string[]>();
    await executePlan(plan, async (step, deps) => {
      order.push(step.id);
      seen.set(step.id, [...deps.keys()]);
      return done(step.id);
    });
    expect(order).toEqual(["a", "b", "c"]);
    expect(seen.get("c")?.sort()).toEqual(["a", "b"]);
  });

  it("never exceeds the concurrency bound", async () => {
    let active = 0;
    let peak = 0;
    const plan = Array.from({ length: 20 }, (_, i) => ({ id: `s${i}` }));
    await executePlan(
      plan,
      async (step) => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 5));
        active--;
        return done(step.id);
      },
      { concurrency: 4 }
    );
    expect(peak).toBe(4);
  });

  it("ignores dependencies that are not in the plan", async () => {
    const out = await executePlan([{ id: "x", dependsOn: ["missing"] }], async (s) => done(s.id));
    expect(out.has("x")).toBe(true);
  });
});

describe("registry planning", () => {
  it("quick scans stay passive: no step contacts the target", () => {
    for (const type of ["DOMAIN", "URL", "IPV4", "EMAIL"] as const) {
      const active = buildPlan(type, "QUICK").filter((s) => getProvider(s.id)?.active);
      expect(active).toEqual([]);
    }
  });

  it("deep investigations add direct probes for domains", () => {
    const ids = buildPlan("DOMAIN", "DEEP").map((s) => s.id);
    expect(ids).toEqual(expect.arrayContaining(["tls", "http", "dnssec", "crtsh"]));
  });

  it("wires correlation after every other step and drops unplannable dependencies", () => {
    const plan = buildPlan("CVE", "QUICK");
    const correlation = plan.find((s) => s.id === "correlation")!;
    expect(correlation.dependsOn?.sort()).toEqual(plan.filter((s) => s.id !== "correlation").map((s) => s.id).sort());
    for (const s of plan) for (const d of s.dependsOn ?? []) expect(plan.some((p) => p.id === d)).toBe(true);
  });

  it("never sends non-public addresses to external sources", () => {
    expect(planSkipReason(getProvider("otx")!, "10.0.0.5", "IPV4")).toMatch(/private/);
    expect(planSkipReason(getProvider("otx")!, "http://192.168.1.1/admin", "URL")).toMatch(/private/);
    expect(planSkipReason(getProvider("otx")!, "8.8.8.8", "IPV4")).toBeNull();
    expect(planSkipReason(getProvider("address-context")!, "10.0.0.5", "IPV4")).toBeNull();
  });

  it("every provider has a unique id and provenance code", () => {
    const plans = (["IPV4", "IPV6", "DOMAIN", "URL", "EMAIL", "MD5", "SHA1", "SHA256", "CVE", "ASN", "CERT_SHA256"] as const).flatMap((t) => buildPlan(t, "DEEP"));
    const ids = new Set(plans.map((p) => p.id));
    const codes = [...ids].map((id) => getProvider(id)!.code);
    expect(new Set(codes).size).toBe(codes.length);
  });
});
