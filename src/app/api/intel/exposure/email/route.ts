import type { NextRequest } from "next/server";
import { detectObservable, registrableDomain } from "@/lib/observables/detect";
import { hibpBreachCatalogueFeed } from "@/lib/intel/feeds";
import { DISPOSABLE_DOMAIN_COUNT, hibpAccountBreaches, isDisposableEmailDomain, summarizeExposure } from "@/lib/intel/email-exposure";
import { ApiError, enforceLimits, handler, json } from "@/lib/server/api";
import { exposureEmailSchema } from "@/lib/server/schemas";

/**
 * Email exposure intelligence: treats an email address as an investigable
 * observable — breach history, exposed data categories, and domain-level
 * mail-security context — never a people-search or PII-enrichment lookup.
 * Every section reports NOT_CONFIGURED / NO_RESULT / RATE_LIMITED honestly
 * rather than inferring exposure that wasn't actually confirmed.
 */
export const GET = handler(async (req: NextRequest) => {
  const { email } = exposureEmailSchema.parse(Object.fromEntries(req.nextUrl.searchParams));
  await enforceLimits(req, [{ name: "exposure-email", limit: 20, windowSeconds: 60, scope: "client" }]);

  const detected = detectObservable(email.toLowerCase());
  if (!detected || detected.type !== "EMAIL") throw new ApiError(422, "invalid-email", "Enter a valid email address.");
  const normalized = detected.normalized;
  const domain = normalized.split("@")[1];
  const registrable = registrableDomain(domain) ?? domain;

  const [account, catalogue] = await Promise.all([
    hibpAccountBreaches(normalized),
    hibpBreachCatalogueFeed.get().catch(() => null),
  ]);

  const overview = summarizeExposure(account);
  const domainBreaches = catalogue?.value.byDomain.get(registrable) ?? [];

  const timeline = [
    ...account.breaches.map((b) => ({ date: b.BreachDate, label: b.Title, kind: "account-breach" as const, stealerLog: Boolean(b.IsStealerLog) })),
  ]
    .filter((e) => e.date)
    .sort((a, b) => (a.date! < b.date! ? -1 : 1));

  return json({
    email: normalized,
    domain: registrable,
    exposureOverview: overview,
    breaches: account.breaches.map((b) => ({
      name: b.Name,
      title: b.Title,
      domain: b.Domain,
      breachDate: b.BreachDate,
      addedDate: b.AddedDate,
      modifiedDate: b.ModifiedDate,
      pwnCount: b.PwnCount,
      dataClasses: b.DataClasses ?? [],
      verified: b.IsVerified,
      sensitive: b.IsSensitive,
      retired: b.IsRetired,
      spamList: b.IsSpamList,
      malware: b.IsMalware,
      stealerLog: b.IsStealerLog,
      description: b.Description,
    })),
    credentialExposure: {
      status: account.status,
      passwordExposed: overview.passwordExposed,
      stealerLogCount: overview.stealerLogCount,
      pasteExposure: { status: "unsupported" as const, note: "HIBP's paste-search API is not available on all key tiers; not queried to avoid an unreliable partial result." },
    },
    emailIntelligence: {
      domain: registrable,
      disposable: isDisposableEmailDomain(registrable),
      disposableListSize: DISPOSABLE_DOMAIN_COUNT,
      provider: "Have I Been Pwned",
    },
    domainExposure: {
      status: catalogue ? (domainBreaches.length ? "confirmed-exposure" : "no-result") : "provider-unavailable",
      breachCount: domainBreaches.length,
      breaches: domainBreaches.map((b) => ({ name: b.Name, title: b.Title, breachDate: b.BreachDate, dataClasses: b.DataClasses, pwnCount: b.PwnCount })),
      note: "Domain-wide breach attribution from HIBP's catalogue — this does not mean this specific address was in the breach, only that the domain was affected by at least one.",
    },
    timeline,
    evidence: [
      { source: "Have I Been Pwned — breachedaccount API", status: account.status, retrievedAt: new Date().toISOString(), configured: account.status !== "not-configured" },
      { source: "Have I Been Pwned — public breach catalogue", status: catalogue ? "ok" : "provider-unavailable", retrievedAt: catalogue ? new Date(catalogue.fetchedAt).toISOString() : new Date().toISOString() },
      { source: "Disposable-email curated list (local, static)", status: "ok", retrievedAt: new Date().toISOString() },
    ],
    methodology:
      "Exposure is never inferred from domain-wide breach attribution alone — a domain appearing in a breach does not imply a specific address was affected. \"No result\" means this address was not found in the queried source's index, not that it has never been exposed anywhere.",
  });
});
