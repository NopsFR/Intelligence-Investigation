import type { NextRequest } from "next/server";
import { bazaarRecentFeed, feodoFeed, threatFoxRecentFeed, urlhausRecentFeed } from "@/lib/intel/feeds";
import { enforceLimits, handler, json } from "@/lib/server/api";

/** Aggregated live threat feed: abuse.ch ThreatFox IOCs, URLhaus URLs, MalwareBazaar samples and Feodo C2 IPs, each with source and timestamp. */
export const GET = handler(async (req: NextRequest) => {
  await enforceLimits(req, [{ name: "intel-feed", limit: 60, windowSeconds: 60, scope: "client" }]);
  const [threatfox, urlhaus, bazaar, feodo] = await Promise.allSettled([threatFoxRecentFeed.get(), urlhausRecentFeed.get(), bazaarRecentFeed.get(), feodoFeed.get()]);
  const pack = <T>(r: PromiseSettledResult<{ value: T; fetchedAt: number }>, name: string) =>
    r.status === "fulfilled" ? { source: name, fetchedAt: new Date(r.value.fetchedAt).toISOString(), ...r.value.value } : { source: name, error: (r.reason as Error)?.message ?? `${name} unavailable` };
  return json({
    threatfox: pack(threatfox, "abuse.ch ThreatFox"),
    urlhaus: pack(urlhaus, "abuse.ch URLhaus"),
    bazaar: pack(bazaar, "abuse.ch MalwareBazaar"),
    feodo: feodo.status === "fulfilled" ? { source: "abuse.ch Feodo Tracker", fetchedAt: new Date(feodo.value.fetchedAt).toISOString(), entries: feodo.value.value.entries, count: feodo.value.value.entries.length } : { source: "abuse.ch Feodo Tracker", error: (feodo.reason as Error)?.message ?? "unavailable" },
  });
});
