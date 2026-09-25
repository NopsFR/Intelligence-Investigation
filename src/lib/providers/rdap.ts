import { requestJson, timed, successOutcome, failureOutcome } from "./base";
import { rdapResponseSchema } from "@/lib/validation/schemas";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["DOMAIN", "IPV4", "IPV6", "ASN"];

function endpointFor(observable: string, type: ObservableType): string {
  switch (type) {
    case "DOMAIN":
      return `https://rdap.org/domain/${encodeURIComponent(observable)}`;
    case "IPV4":
    case "IPV6":
      return `https://rdap.org/ip/${encodeURIComponent(observable)}`;
    case "ASN":
      return `https://rdap.org/autnum/${encodeURIComponent(observable.replace(/^AS/i, ""))}`;
    default:
      throw new Error("Unsupported observable type for RDAP");
  }
}

export const rdapProvider: Provider = {
  meta: {
    id: "rdap",
    name: "RDAP",
    description: "Registration Data Access Protocol — registrar, registry, and IP allocation data.",
    availability: "no-key",
    homepage: "https://rdap.org",
    supports: SUPPORTED,
  },
  isConfigured: () => true,
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const start = Date.now();
    try {
      const { result, latencyMs } = await timed(() =>
        requestJson(endpointFor(ctx.observable, ctx.type), rdapResponseSchema)
      );

      const entities = Array.isArray(result.entities) ? result.entities : [];
      const events = Array.isArray(result.events)
        ? (result.events as { eventAction?: string; eventDate?: string }[])
        : [];
      const registration = events.find((e) => e.eventAction === "registration");
      const expiration = events.find((e) => e.eventAction === "expiration");
      const lastChanged = events.find((e) => e.eventAction === "last changed");

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: result.name ?? result.ldhName ?? result.handle ?? ctx.observable,
          fields: {
            handle: result.handle,
            name: result.ldhName ?? result.name,
            status: result.status,
            registered: registration?.eventDate,
            expires: expiration?.eventDate,
            lastChanged: lastChanged?.eventDate,
            nameservers: (result.nameservers as { ldhName?: string }[] | undefined)
              ?.map((ns) => ns.ldhName)
              .filter(Boolean),
            entityCount: entities.length,
            country: result.country,
            ipRange:
              result.startAddress && result.endAddress
                ? `${result.startAddress} - ${result.endAddress}`
                : undefined,
          },
        },
        result
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    try {
      const { latencyMs } = await timed(() =>
        requestJson("https://rdap.org/ip/1.1.1.1", rdapResponseSchema)
      );
      return successOutcome(this.meta.id, latencyMs, { summary: "RDAP reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, 0, err);
    }
  },
};
