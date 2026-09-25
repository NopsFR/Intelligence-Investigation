import { z } from "zod";
import { OBSERVABLE_TYPES, SEVERITIES } from "@/lib/core/types";

export const observableTypeSchema = z.enum(OBSERVABLE_TYPES);

export const investigateSchema = z.object({
  observable: z.string().trim().min(1, "Enter an observable").max(2048, "Observables are limited to 2048 characters"),
  type: observableTypeSchema.optional(),
  mode: z.enum(["QUICK", "DEEP"]).default("QUICK"),
  fresh: z.boolean().optional(),
});

export const listSchema = z.object({
  q: z.string().trim().max(200).optional(),
  type: observableTypeSchema.optional(),
  status: z.enum(["PENDING", "RUNNING", "COMPLETE", "PARTIAL", "FAILED"]).optional(),
  severity: z.enum(SEVERITIES as [string, ...string[]]).optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  cursor: z.string().max(40).optional(),
});

export const idSchema = z.string().regex(/^[a-z0-9]{8,40}$/i, "Invalid id");

const tag = z.string().trim().min(1).max(40);

export const iocCreateSchema = z.object({
  entries: z
    .array(
      z.object({
        value: z.string().trim().min(1).max(2048),
        type: observableTypeSchema.optional(),
        tags: z.array(tag).max(20).optional(),
        notes: z.string().max(4000).optional(),
        investigationId: idSchema.optional(),
      })
    )
    .min(1)
    .max(1000),
  source: z.string().max(200).optional(),
});

export const iocPatchSchema = z.object({ tags: z.array(tag).max(20).optional(), notes: z.string().max(4000).nullable().optional() });
export const iocDeleteSchema = z.object({ ids: z.array(idSchema).min(1).max(1000) });

export const sessionSchema = z.object({ token: z.string().min(1).max(512) });

export const dnsToolSchema = z.object({
  name: z.string().trim().min(1).max(253),
  type: z.enum(["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "PTR", "DS", "DNSKEY", "SRV", "HTTPS"]).default("A"),
  resolver: z.enum(["cloudflare", "google", "dnssb"]).default("cloudflare"),
});

export const osvQuerySchema = z.object({
  packages: z
    .array(z.object({ name: z.string().min(1).max(300), version: z.string().min(1).max(200), ecosystem: z.enum(["npm", "PyPI", "Go", "crates.io", "Packagist", "RubyGems", "Maven"]) }))
    .min(1)
    .max(1000),
});

export const exposureDomainSchema = z.object({ domain: z.string().trim().min(1).max(253) });
export const exposurePasswordSchema = z.object({ prefix: z.string().trim().regex(/^[0-9A-Fa-f]{5}$/, "prefix must be exactly 5 hex characters") });

export const webSecuritySchema = z.object({ url: z.string().trim().min(1).max(2048) });
