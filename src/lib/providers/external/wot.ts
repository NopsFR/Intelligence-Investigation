import "server-only";
import { z } from "zod";
import type { NormalizedFinding, ObservableType, Severity } from "@/lib/core/types";
import { fact, facts, plural } from "../helpers";
import { ProviderSkip } from "../runtime";
import type { ProviderDefinition } from "../types";

const wotTarget = z
  .object({
    target: z.string().optional(),
    safety: z.object({ status: z.string().optional(), reputations: z.number().nullable().optional(), confidence: z.number().nullable().optional() }).passthrough().optional(),
    childSafety: z.object({ reputations: z.number().nullable().optional(), confidence: z.number().nullable().optional() }).passthrough().optional(),
    categories: z.array(z.object({ id: z.number().optional(), name: z.string().optional(), confidence: z.number().nullable().optional() }).passthrough()).optional(),
    blackList: z.array(z.string()).optional(),
  })
  .passthrough();

const wotResponse = z.array(wotTarget);

function targetFor(type: ObservableType, observable: string): string {
  if (type === "URL") {
    try {
      return new URL(observable).hostname;
    } catch {
      return observable;
    }
  }
  return observable;
}

const RISKY_CATEGORIES = new Set(["phishing", "scam", "malware", "spyware", "spam", "browser exploit"]);

export const wot: ProviderDefinition = {
  id: "wot",
  code: "WOT",
  name: "Web of Trust (WOT)",
  vendor: "WOT Services",
  category: "reputation",
  kind: "external",
  description: "Crowd-sourced domain/URL safety reputation — status, score, confidence, and risk categories (phishing, scam, malware) with a blocklist flag where applicable.",
  homepage: "https://www.mywot.com",
  docs: "https://support.mywot.com/hc/en-us/articles/360024398673",
  auth: { type: "required", env: ["WOT_API_KEY"], header: "x-api-key", signup: "https://www.mywot.com/developer" },
  endpoint: "REST · JSON · scorecard.api.mywot.com/v3/targets",
  limits: "Plans are limited to 10 targets per request (this integration queries one at a time) and require both a WOT_API_KEY and a WOT_USER_ID.",
  terms: "Crowd-sourced reputation data; abide by WOT's API terms of use.",
  supports: ["DOMAIN", "URL"],
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 10_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    const userId = process.env.WOT_USER_ID?.trim();
    if (!userId) throw new ProviderSkip("WOT_USER_ID is not configured alongside WOT_API_KEY — both are required.");

    const target = targetFor(ctx.type, ctx.observable);
    const { data } = await ctx.json(`https://scorecard.api.mywot.com/v3/targets?t=${encodeURIComponent(target)}`, wotResponse, {
      headers: { "x-user-id": userId, "x-api-key": ctx.apiKey! },
      maxBytes: 512 * 1024,
    });

    const entry = data[0];
    if (!entry || !entry.safety) {
      return { summary: "No WOT reputation data for this target", facts: [], empty: true, listed: false, raw: entry ?? null };
    }

    const status = (entry.safety.status ?? "UNKNOWN").toUpperCase();
    const categories = (entry.categories ?? []).filter((c) => c.name).map((c) => ({ name: c.name!, confidence: c.confidence ?? 0 }));
    const riskyCategories = categories.filter((c) => RISKY_CATEGORIES.has(c.name.toLowerCase()));
    const blacklisted = entry.blackList ?? [];

    const findings: NormalizedFinding[] = [];
    if (status === "NOT_SAFE" || status === "SUSPICIOUS" || riskyCategories.length || blacklisted.length) {
      const severity: Severity = status === "NOT_SAFE" || blacklisted.length ? "HIGH" : "MEDIUM";
      findings.push({
        rule: "reputation.wot.risky",
        severity,
        category: "reputation",
        title: `WOT reports ${status.replace("_", " ").toLowerCase()}${riskyCategories.length ? ` (${riskyCategories.map((c) => c.name).join(", ")})` : ""}`,
        description: `Web of Trust's crowd-sourced reputation for ${target} is ${status.replace("_", " ").toLowerCase()}${blacklisted.length ? `, and it appears on the blocklist categories: ${blacklisted.join(", ")}` : ""}.`,
        rationale: "WOT scores are crowd-sourced and community-voted, not a definitive verdict — treat this as corroborating signal alongside other reputation sources, not sole grounds for action.",
        evidence: `Safety score ${entry.safety.reputations ?? "?"}/100 (confidence ${entry.safety.confidence ?? "?"}/100)${categories.length ? `; categories: ${categories.map((c) => `${c.name} (${c.confidence})`).join(", ")}` : ""}`,
        evidenceData: { status, score: entry.safety.reputations ?? null, confidence: entry.safety.confidence ?? null, categories: categories.map((c) => `${c.name} (${c.confidence})`), blacklisted },
        confidence: "Crowd-sourced",
        remediation: status === "NOT_SAFE" ? "Corroborate with an independent source (VirusTotal, OTX) before blocking; WOT alone is not authoritative." : undefined,
        references: [{ label: "WOT reputation data", url: "https://www.mywot.com" }],
      });
    }

    return {
      summary: `WOT: ${status.replace("_", " ").toLowerCase()}${entry.safety.reputations !== undefined && entry.safety.reputations !== null ? ` (${entry.safety.reputations}/100)` : ""}`,
      listed: status !== "SAFE" && status !== "UNKNOWN",
      facts: facts(
        fact("status", "Safety status", status, "text", true),
        fact("score", "Safety score", entry.safety.reputations ?? undefined, "number", true),
        fact("confidence", "Confidence", entry.safety.confidence ?? undefined, "number"),
        fact("categories", "Risk categories", categories.map((c) => `${c.name} (${c.confidence})`), "list", true),
        fact("blacklist", `Blocklist${plural(blacklisted.length, "")}`, blacklisted, "list"),
        fact("childSafety", "Child safety score", entry.childSafety?.reputations ?? undefined, "number")
      ),
      data: { kind: "wot", target, status, score: entry.safety.reputations ?? null, confidence: entry.safety.confidence ?? null, categories, blacklisted, childSafety: entry.childSafety ?? null },
      findings,
      raw: entry,
    };
  },
};
