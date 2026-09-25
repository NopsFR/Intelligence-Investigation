import "server-only";
import type { InvestigationMode, ObservableType, PlanStep } from "@/lib/core/types";
import { classifyIp } from "@/lib/observables/ip";
import { attackMapping } from "./derived/attack";
import { correlation } from "./derived/correlation";
import { kevExposure } from "./derived/exposure";
import { hosting } from "./derived/hosting";
import { feodoTracker, malwareBazaar, threatFox, urlhaus, yaraify } from "./external/abusech";
import { certSpotter, crtSh } from "./external/certificates";
import { circlHashlookup } from "./external/circl";
import { abuseIpDb, greyNoise, internetDb } from "./external/ip-intel";
import { otx } from "./external/otx";
import { mnemonicPassiveDns, urlscanSearch } from "./external/passivedns";
import { rdap } from "./external/rdap";
import { ripeStat } from "./external/ripestat";
import { virusTotal } from "./external/virustotal";
import { cisaKev, cveOrg, epss, nvd } from "./external/vulnerability";
import { dnsRecords, dnssec, reverseDns } from "./native/dns";
import { emailSecurity } from "./native/email";
import { httpInspection } from "./native/http";
import { addressContext, hostnameAnalysis, urlAnalysis } from "./native/structure";
import { tlsInspection } from "./native/tls";
import type { ProviderDefinition } from "./types";

/** Every analyser, in display order within its category. */
export const PROVIDERS: ProviderDefinition[] = [
  // Native analysers
  addressContext,
  hostnameAnalysis,
  urlAnalysis,
  dnsRecords,
  dnssec,
  reverseDns,
  emailSecurity,
  tlsInspection,
  httpInspection,
  // Registration & routing
  rdap,
  ripeStat,
  mnemonicPassiveDns,
  urlscanSearch,
  // Certificates
  certSpotter,
  crtSh,
  // Threat intelligence & reputation
  virusTotal,
  abuseIpDb,
  greyNoise,
  otx,
  threatFox,
  urlhaus,
  feodoTracker,
  internetDb,
  // Malware
  malwareBazaar,
  yaraify,
  circlHashlookup,
  // Vulnerability
  cveOrg,
  nvd,
  cisaKev,
  epss,
  // Derived
  hosting,
  kevExposure,
  attackMapping,
  correlation,
];

const BY_ID = new Map(PROVIDERS.map((p) => [p.id, p]));

export function getProvider(id: string): ProviderDefinition | undefined {
  return BY_ID.get(id);
}

export function externalProviders(): ProviderDefinition[] {
  return PROVIDERS.filter((p) => p.kind === "external");
}

function runsInMode(def: ProviderDefinition, type: ObservableType, mode: InvestigationMode): boolean {
  if (mode === "DEEP" || def.quick === undefined) return true;
  return def.quick !== "none" && def.quick.includes(type);
}

/**
 * Selects the analysers for an observable and wires their dependencies.
 * Dependencies on steps that are not in the plan are dropped, and "*" means
 * "every other step".
 */
export function buildPlan(type: ObservableType, mode: InvestigationMode): PlanStep[] {
  const candidates = PROVIDERS.filter((def) => def.supports.includes(type) && runsInMode(def, type, mode));
  const candidateIds = new Set(candidates.map((d) => d.id));
  // A derived step whose inputs are all absent has nothing to work with.
  const selected = candidates.filter(
    (def) => def.kind !== "derived" || !def.dependsOn?.length || def.dependsOn.includes("*") || def.dependsOn.some((d) => candidateIds.has(d))
  );
  const ids = new Set(selected.map((d) => d.id));
  return selected.map((def) => {
    const deps = def.dependsOn?.includes("*") ? selected.filter((d) => d.id !== def.id).map((d) => d.id) : (def.dependsOn ?? []).filter((d) => ids.has(d));
    return deps.length ? { id: def.id, dependsOn: deps } : { id: def.id };
  });
}

/**
 * Reason to not run a step at all for this observable, decided before any
 * network activity. External sources hold nothing meaningful for non-public
 * address space, and querying them would leak internal addressing.
 */
export function planSkipReason(def: ProviderDefinition, observable: string, type: ObservableType): string | null {
  if (def.kind !== "external") return null;
  let address: string | null = null;
  if (type === "IPV4" || type === "IPV6") address = observable;
  else if (type === "URL") {
    try {
      address = new URL(observable).hostname.replace(/^\[|\]$/g, "");
    } catch {
      address = null;
    }
  }
  if (address) {
    const c = classifyIp(address);
    if (c && c.scope !== "public") return `Not queried: ${c.address} is ${c.scope.replace(/-/g, " ")} address space (${c.range}); external sources hold no meaningful data for it and the address is not disclosed to third parties.`;
  }
  return null;
}
