import "server-only";
import { z } from "zod";
import { ProviderRequestError, providerJson, providerRequest } from "@/lib/net/provider-fetch";
import { RCODE_NAMES, RR_TYPES, base64UrlEncode, decodeMessage, encodeQuery, typeName, type RecordType } from "./wire";

export type { RecordType } from "./wire";

export interface DnsAnswer {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

export interface DnsResponse {
  resolver: ResolverId;
  rcode: number;
  rcodeName: string;
  /** Resolver validated the answer with DNSSEC (AD bit). */
  authenticated: boolean;
  answers: DnsAnswer[];
  latencyMs: number;
}

export type ResolverId = "cloudflare" | "google" | "dnssb";

export const RESOLVERS: Record<ResolverId, { name: string; protocol: string; endpoint: string }> = {
  cloudflare: { name: "Cloudflare", protocol: "DoH · JSON", endpoint: "https://cloudflare-dns.com/dns-query" },
  google: { name: "Google Public DNS", protocol: "DoH · JSON", endpoint: "https://dns.google/resolve" },
  dnssb: { name: "DNS.SB", protocol: "DoH · RFC 8484 wire format", endpoint: "https://doh.dns.sb/dns-query" },
};

const jsonSchema = z.object({
  Status: z.number(),
  AD: z.boolean().optional(),
  Answer: z
    .array(z.object({ name: z.string(), type: z.number(), TTL: z.number().optional(), data: z.string() }))
    .optional(),
});

/** Reassembles presentation-format character-strings: "v=spf1 " "include:x" -> v=spf1 include:x */
export function joinCharacterStrings(data: string): string {
  const trimmed = data.trim();
  if (!trimmed.startsWith('"')) return trimmed;
  const parts: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(trimmed))) {
    parts.push(m[1].replace(/\\(\d{3})/g, (_, d) => String.fromCharCode(Number(d))).replace(/\\(.)/g, "$1"));
  }
  return parts.length ? parts.join("") : trimmed;
}

/** Decodes RFC 3597 generic rdata ("\# 22 00 05 69 73 ...") for CAA records. */
function decodeGenericCaa(data: string): string {
  const match = data.match(/^\\#\s+\d+\s+([0-9a-f\s]+)$/i);
  if (!match) return data;
  const bytes = match[1].replace(/\s+/g, "").match(/.{2}/g)?.map((h) => parseInt(h, 16)) ?? [];
  if (bytes.length < 2) return data;
  const tagLen = bytes[1];
  const tag = String.fromCharCode(...bytes.slice(2, 2 + tagLen));
  const value = String.fromCharCode(...bytes.slice(2 + tagLen));
  return `${bytes[0]} ${tag} "${value}"`;
}

function normalizeAnswer(type: string, name: string, ttl: number, data: string): DnsAnswer {
  let value = data;
  if (type === "TXT") value = joinCharacterStrings(data);
  else if (type === "CAA") value = decodeGenericCaa(data);
  else if (["NS", "CNAME", "PTR"].includes(type)) value = data.replace(/\.$/, "").toLowerCase();
  else if (type === "MX") value = data.replace(/\.$/, "").toLowerCase();
  return { name: name.replace(/\.$/, "").toLowerCase(), type, ttl, data: value };
}

async function queryJson(resolver: "cloudflare" | "google", name: string, type: RecordType, signal?: AbortSignal): Promise<DnsResponse> {
  const started = Date.now();
  const base = RESOLVERS[resolver].endpoint;
  const url = `${base}?name=${encodeURIComponent(name)}&type=${type}&do=1`;
  const { data } = await providerJson(url, jsonSchema, {
    headers: { accept: "application/dns-json" },
    timeoutMs: 5000,
    signal,
  });
  return {
    resolver,
    rcode: data.Status,
    rcodeName: RCODE_NAMES[data.Status] ?? `RCODE${data.Status}`,
    authenticated: Boolean(data.AD),
    answers: (data.Answer ?? []).map((a) => normalizeAnswer(typeName(a.type), a.name, a.TTL ?? 0, a.data)),
    latencyMs: Date.now() - started,
  };
}

async function queryWire(name: string, type: RecordType, signal?: AbortSignal): Promise<DnsResponse> {
  const started = Date.now();
  const q = encodeQuery(name, type, { dnssecOk: true });
  const url = `${RESOLVERS.dnssb.endpoint}?dns=${base64UrlEncode(q)}`;
  const response = await providerRequest(url, {
    headers: { accept: "application/dns-message" },
    timeoutMs: 5000,
    signal,
    maxBytes: 64 * 1024,
  });
  let message;
  try {
    message = decodeMessage(response.body);
  } catch (err) {
    throw new ProviderRequestError(`Malformed DNS message: ${(err as Error).message}`, "schema");
  }
  return {
    resolver: "dnssb",
    rcode: message.rcode,
    rcodeName: RCODE_NAMES[message.rcode] ?? `RCODE${message.rcode}`,
    authenticated: message.flags.ad,
    answers: message.answers.map((a) => normalizeAnswer(a.type, a.name, a.ttl, a.data)),
    latencyMs: Date.now() - started,
  };
}

export async function query(resolver: ResolverId, name: string, type: RecordType, signal?: AbortSignal): Promise<DnsResponse> {
  if (resolver === "dnssb") return queryWire(name, type, signal);
  return queryJson(resolver, name, type, signal);
}

const FALLBACK_ORDER: ResolverId[] = ["cloudflare", "google", "dnssb"];

/** Resolves with automatic fallback across resolvers; throws only if all fail. */
export async function resolve(name: string, type: RecordType, signal?: AbortSignal): Promise<DnsResponse> {
  let lastError: unknown;
  for (const resolver of FALLBACK_ORDER) {
    try {
      return await query(resolver, name, type, signal);
    } catch (err) {
      lastError = err;
      if (signal?.aborted) break;
    }
  }
  throw lastError ?? new Error("All resolvers failed");
}

/** Answer data of a given type, or [] for NXDOMAIN / no data. */
export async function lookup(name: string, type: RecordType, signal?: AbortSignal): Promise<string[]> {
  const response = await resolve(name, type, signal);
  return response.answers.filter((a) => a.type === type).map((a) => a.data);
}

export const SUPPORTED_RECORD_TYPES = Object.keys(RR_TYPES) as RecordType[];
