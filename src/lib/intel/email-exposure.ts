import "server-only";
import { z } from "zod";
import { ProviderRequestError, providerJson } from "@/lib/net/provider-fetch";

// Email exposure intelligence: treats an email address as an investigable
// observable (like an IP, domain, or hash) rather than a person to look up.
// Every field here comes from an official, authenticated provider API
// response — nothing is scraped, inferred, or fabricated. A domain being
// breached is never treated as evidence that a specific address was.

// ---------------------------------------------------------------- Disposable email domains

// A static, hand-curated list of well-known disposable/temporary-mail
// providers. This is intentionally not exhaustive — new disposable domains
// appear constantly — so a "no" result means "not in this curated list",
// never "confirmed legitimate".
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "guerrillamail.info",
  "guerrillamail.biz",
  "guerrillamail.org",
  "10minutemail.com",
  "10minutemail.net",
  "temp-mail.org",
  "tempmail.com",
  "tempmail.net",
  "throwawaymail.com",
  "yopmail.com",
  "yopmail.fr",
  "getnada.com",
  "trashmail.com",
  "trashmail.net",
  "dispostable.com",
  "fakeinbox.com",
  "sharklasers.com",
  "grr.la",
  "spam4.me",
  "mailnesia.com",
  "mytemp.email",
  "moakt.com",
  "mail-temporaire.fr",
  "maildrop.cc",
  "mintemail.com",
  "emailondeck.com",
  "tempinbox.com",
  "spambog.com",
  "spamgourmet.com",
  "burnermail.io",
  "mohmal.com",
  "tempr.email",
  "discard.email",
  "discardmail.com",
  "mailcatch.com",
  "inboxbear.com",
  "33mail.com",
  "anonaddy.com",
  "simplelogin.io",
  "mailsac.com",
  "crazymailing.com",
  "tempmailo.com",
  "luxusmail.org",
  "fakemail.net",
  "instant-mail.de",
  "byom.de",
  "einrot.com",
  "kurzepost.de",
  "trbvm.com",
  "wegwerfmail.de",
  "wegwerfmail.net",
  "wegwerfmail.org",
]);

export function isDisposableEmailDomain(domain: string): boolean {
  return DISPOSABLE_DOMAINS.has(domain.toLowerCase());
}

export const DISPOSABLE_DOMAIN_COUNT = DISPOSABLE_DOMAINS.size;

// ---------------------------------------------------------------- HIBP breach-by-account (keyed)

const hibpAccountBreachSchema = z.object({
  Name: z.string(),
  Title: z.string(),
  Domain: z.string().optional(),
  BreachDate: z.string().optional(),
  AddedDate: z.string().optional(),
  ModifiedDate: z.string().optional(),
  PwnCount: z.number().optional(),
  Description: z.string().optional(),
  DataClasses: z.array(z.string()).optional(),
  IsVerified: z.boolean().optional(),
  IsFabricated: z.boolean().optional(),
  IsSensitive: z.boolean().optional(),
  IsRetired: z.boolean().optional(),
  IsSpamList: z.boolean().optional(),
  IsMalware: z.boolean().optional(),
  IsSubscriptionFree: z.boolean().optional(),
  IsStealerLog: z.boolean().optional(),
  LogoPath: z.string().optional(),
});
export type HibpAccountBreach = z.infer<typeof hibpAccountBreachSchema>;

export type HibpAccountStatus = "not-configured" | "confirmed" | "no-result" | "rate-limited" | "provider-unavailable";

export interface HibpAccountResult {
  status: HibpAccountStatus;
  breaches: HibpAccountBreach[];
  retryAfterSeconds?: number;
  message?: string;
}

/**
 * HIBP breachedaccount lookup — requires a subscribed API key (hibp-api-key
 * header). Without HIBP_API_KEY configured, this is reported as
 * not-configured rather than silently skipped or faked.
 */
export async function hibpAccountBreaches(email: string): Promise<HibpAccountResult> {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) return { status: "not-configured", breaches: [] };
  try {
    const { data } = await providerJson(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      z.array(hibpAccountBreachSchema),
      { timeoutMs: 15_000, maxBytes: 2 * 1024 * 1024, headers: { "hibp-api-key": apiKey, "user-agent": "NOPS-Cyber-Intelligence" } }
    );
    return { status: "confirmed", breaches: data };
  } catch (err) {
    if (err instanceof ProviderRequestError) {
      if (err.kind === "http" && err.status === 404) return { status: "no-result", breaches: [] };
      if (err.kind === "http" && err.status === 429) return { status: "rate-limited", breaches: [], retryAfterSeconds: err.retryAfterSeconds };
      if (err.kind === "http" && (err.status === 401 || err.status === 403)) {
        return { status: "provider-unavailable", breaches: [], message: "HIBP rejected the configured API key (unauthorized) — check HIBP_API_KEY." };
      }
    }
    return { status: "provider-unavailable", breaches: [], message: err instanceof Error ? err.message : String(err) };
  }
}

export interface ExposureOverview {
  status: "confirmed-exposure" | "no-result" | "not-configured" | "rate-limited" | "provider-unavailable";
  breachCount: number;
  earliestBreach?: string;
  latestBreach?: string;
  dataClasses: string[];
  stealerLogCount: number;
  passwordExposed: boolean;
}

export function summarizeExposure(account: HibpAccountResult): ExposureOverview {
  const dates = account.breaches.map((b) => b.BreachDate).filter((d): d is string => Boolean(d)).sort();
  const dataClasses = [...new Set(account.breaches.flatMap((b) => b.DataClasses ?? []))].sort();
  return {
    status: account.status === "confirmed" ? "confirmed-exposure" : (account.status as ExposureOverview["status"]),
    breachCount: account.breaches.length,
    earliestBreach: dates[0],
    latestBreach: dates[dates.length - 1],
    dataClasses,
    stealerLogCount: account.breaches.filter((b) => b.IsStealerLog).length,
    passwordExposed: account.breaches.some((b) => (b.DataClasses ?? []).some((c) => c.toLowerCase().includes("password"))),
  };
}
