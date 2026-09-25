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
export const exposureEmailSchema = z.object({ email: z.string().trim().min(3).max(254) });

export const webSecuritySchema = z.object({ url: z.string().trim().min(1).max(2048) });

export const caseCreateSchema = z.object({
  title: z.string().trim().min(1).max(300),
  description: z.string().trim().max(10_000).optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).optional(),
  tags: z.array(tag).max(20).optional(),
});
export const casePatchSchema = z.object({
  title: z.string().trim().min(1).max(300).optional(),
  description: z.string().trim().max(10_000).nullable().optional(),
  status: z.enum(["OPEN", "CLOSED", "ARCHIVED"]).optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).nullable().optional(),
  tags: z.array(tag).max(20).optional(),
});

const caseNoteData = z.object({ text: z.string().trim().min(1).max(20_000) });
const caseEvidenceData = z.object({ label: z.string().trim().min(1).max(300), sha256: z.string().trim().regex(/^[a-f0-9]{64}$/i).optional(), sha1: z.string().trim().regex(/^[a-f0-9]{40}$/i).optional(), md5: z.string().trim().regex(/^[a-f0-9]{32}$/i).optional(), description: z.string().trim().max(4000).optional(), source: z.string().trim().max(300).optional() });
const caseCustodyData = z.object({ action: z.string().trim().min(1).max(200), handler: z.string().trim().min(1).max(200), detail: z.string().trim().max(2000).optional() });
const caseEventData = z.object({ occurredAt: z.string().trim().min(1).max(64), title: z.string().trim().min(1).max(300), detail: z.string().trim().max(4000).optional(), source: z.string().trim().max(300).optional() });
const caseLinkData = z.object({ refType: z.enum(["investigation", "ioc"]), refId: idSchema, label: z.string().trim().max(300).optional() });

export const caseItemCreateSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("NOTE"), data: caseNoteData }),
  z.object({ kind: z.literal("EVIDENCE"), data: caseEvidenceData }),
  z.object({ kind: z.literal("CUSTODY"), data: caseCustodyData }),
  z.object({ kind: z.literal("EVENT"), data: caseEventData }),
  z.object({ kind: z.literal("LINK"), data: caseLinkData }),
]);
