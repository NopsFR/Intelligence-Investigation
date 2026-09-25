import type { ObservableType } from "@/types/observable";
import type { Provider } from "@/types/provider";
import { rdapProvider } from "./rdap";
import { crtShProvider } from "./crtsh";
import { cloudflareDnsProvider, googleDnsProvider } from "./dnsProviders";
import { nvdProvider } from "./nvd";
import { cisaKevProvider } from "./cisaKev";
import { abuseIpDbProvider } from "./abuseipdb";
import { virusTotalProvider } from "./virustotal";
import { threatFoxProvider } from "./threatfox";
import { urlhausProvider } from "./urlhaus";
import { malwareBazaarProvider } from "./malwarebazaar";

export const PROVIDERS: Provider[] = [
  rdapProvider,
  crtShProvider,
  cloudflareDnsProvider,
  googleDnsProvider,
  nvdProvider,
  cisaKevProvider,
  abuseIpDbProvider,
  virusTotalProvider,
  threatFoxProvider,
  urlhausProvider,
  malwareBazaarProvider,
];

export function providersFor(type: ObservableType, mode: "QUICK" | "DEEP"): Provider[] {
  const supporting = PROVIDERS.filter((p) => p.supports(type));
  if (mode === "DEEP") return supporting;

  // Quick Scan prioritizes fast, high-signal sources per observable type
  // rather than the full provider set.
  const quickPriority: Record<ObservableType, string[]> = {
    IPV4: ["abuseipdb", "virustotal", "rdap", "threatfox"],
    IPV6: ["abuseipdb", "virustotal", "rdap"],
    DOMAIN: ["cloudflare-dns", "rdap", "virustotal"],
    URL: ["urlhaus", "virustotal"],
    MD5: ["malwarebazaar", "virustotal"],
    SHA1: ["malwarebazaar", "virustotal"],
    SHA256: ["malwarebazaar", "virustotal", "threatfox"],
    CVE: ["nvd", "cisa-kev"],
    ASN: ["rdap"],
  };

  const priorityIds = quickPriority[type] ?? [];
  const prioritized = priorityIds
    .map((id) => supporting.find((p) => p.meta.id === id))
    .filter((p): p is Provider => Boolean(p));
  const rest = supporting.filter((p) => !priorityIds.includes(p.meta.id));
  return [...prioritized, ...rest].slice(0, mode === "QUICK" ? 4 : undefined);
}

export function getProvider(id: string): Provider | undefined {
  return PROVIDERS.find((p) => p.meta.id === id);
}
