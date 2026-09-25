import { requestJson } from "@/lib/providers/base";
import { dohResponseSchema } from "@/lib/validation/schemas";

export type DnsRecordType = "A" | "AAAA" | "MX" | "NS" | "TXT" | "CNAME" | "SOA" | "CAA";

export interface DnsAnswer {
  name: string;
  type: DnsRecordType;
  data: string;
  ttl?: number;
}

export interface DnsLookupResult {
  resolver: "Cloudflare" | "Google";
  status: number;
  answers: DnsAnswer[];
}

const TYPE_NUM: Record<DnsRecordType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
};
const NUM_TYPE = Object.fromEntries(Object.entries(TYPE_NUM).map(([k, v]) => [v, k])) as Record<
  number,
  DnsRecordType
>;

export async function resolveViaCloudflare(name: string, type: DnsRecordType): Promise<DnsLookupResult> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  const result = await requestJson(url, dohResponseSchema, {
    headers: { accept: "application/dns-json" },
    timeoutMs: 6000,
  });
  return {
    resolver: "Cloudflare",
    status: result.Status,
    answers: (result.Answer ?? []).map((a) => ({
      name: a.name,
      type: NUM_TYPE[a.type] ?? type,
      data: a.data,
      ttl: a.TTL,
    })),
  };
}

export async function resolveViaGoogle(name: string, type: DnsRecordType): Promise<DnsLookupResult> {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
  const result = await requestJson(url, dohResponseSchema, { timeoutMs: 6000 });
  return {
    resolver: "Google",
    status: result.Status,
    answers: (result.Answer ?? []).map((a) => ({
      name: a.name,
      type: NUM_TYPE[a.type] ?? type,
      data: a.data,
      ttl: a.TTL,
    })),
  };
}

/** Resolves a record type via Cloudflare, falling back to Google on failure. */
export async function resolveWithFallback(name: string, type: DnsRecordType): Promise<DnsLookupResult> {
  try {
    return await resolveViaCloudflare(name, type);
  } catch {
    return await resolveViaGoogle(name, type);
  }
}
