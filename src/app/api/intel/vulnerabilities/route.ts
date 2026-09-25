import type { NextRequest } from "next/server";
import { epssTopFeed, kevFeed, nvdRecentFeed } from "@/lib/intel/feeds";
import { enforceLimits, handler, json } from "@/lib/server/api";

/** KEV catalogue, recently published CVEs and the EPSS top-100 exploit-probability ranking. */
export const GET = handler(async (req: NextRequest) => {
  await enforceLimits(req, [{ name: "intel-vulnerabilities", limit: 60, windowSeconds: 60, scope: "client" }]);
  const [kev, recent, epss] = await Promise.allSettled([kevFeed.get(), nvdRecentFeed.get(), epssTopFeed.get()]);
  const epssIndex = epss.status === "fulfilled" ? epss.value.value.index : new Map();
  return json({
    kev:
      kev.status === "fulfilled"
        ? { fetchedAt: new Date(kev.value.fetchedAt).toISOString(), catalogVersion: kev.value.value.catalogVersion, dateReleased: kev.value.value.dateReleased, count: kev.value.value.vulnerabilities.length, entries: kev.value.value.vulnerabilities.slice(0, 60) }
        : { error: (kev.reason as Error)?.message ?? "CISA KEV feed unavailable" },
    recent:
      recent.status === "fulfilled"
        ? { fetchedAt: new Date(recent.value.fetchedAt).toISOString(), totalResults: recent.value.value.totalResults, entries: recent.value.value.entries.map((e) => ({ ...e, epss: epssIndex.get(e.id.toUpperCase()) })) }
        : { error: (recent.reason as Error)?.message ?? "NVD recent-CVE feed unavailable" },
    epss: epss.status === "fulfilled" ? { fetchedAt: new Date(epss.value.fetchedAt).toISOString(), entries: epss.value.value.entries } : { error: (epss.reason as Error)?.message ?? "EPSS feed unavailable" },
  });
});
