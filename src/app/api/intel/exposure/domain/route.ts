import type { NextRequest } from "next/server";
import { registrableDomain } from "@/lib/observables/detect";
import { hibpBreachCatalogueFeed } from "@/lib/intel/feeds";
import { ApiError, enforceLimits, handler, json } from "@/lib/server/api";
import { exposureDomainSchema } from "@/lib/server/schemas";

/**
 * Breach exposure for a domain, from HIBP's public (keyless) breach
 * catalogue. This reports confirmed breaches HIBP has *attributed to this
 * domain*; it says nothing about individual email addresses, and an empty
 * result means no attributed breach was found, not that the domain is safe.
 */
export const GET = handler(async (req: NextRequest) => {
  const { domain } = exposureDomainSchema.parse(Object.fromEntries(req.nextUrl.searchParams));
  await enforceLimits(req, [{ name: "exposure-domain", limit: 60, windowSeconds: 60, scope: "client" }]);
  const registrable = registrableDomain(domain.toLowerCase().replace(/^\*\.|\.$/g, ""));
  if (!registrable) throw new ApiError(422, "invalid-domain", "Enter a valid registrable domain, e.g. example.com.");
  let catalogue;
  try {
    catalogue = await hibpBreachCatalogueFeed.get();
  } catch (err) {
    throw new ApiError(502, "provider-unavailable", `HIBP breach catalogue is unavailable: ${err instanceof Error ? err.message : String(err)}`);
  }
  const breaches = catalogue.value.byDomain.get(registrable) ?? [];
  return json({
    domain: registrable,
    status: breaches.length ? "confirmed-exposure" : "no-result",
    note: breaches.length ? undefined : "No breach in HIBP's public catalogue is attributed to this domain. This is not proof the domain has never been affected — HIBP does not index every breach, and some breaches omit a domain.",
    fetchedAt: new Date(catalogue.fetchedAt).toISOString(),
    source: "Have I Been Pwned — public breach catalogue",
    breaches: breaches.map((b) => ({ name: b.Name, title: b.Title, breachDate: b.BreachDate, addedDate: b.AddedDate, pwnCount: b.PwnCount, dataClasses: b.DataClasses, verified: b.IsVerified, sensitive: b.IsSensitive, retired: b.IsRetired, description: b.Description })),
  });
});
