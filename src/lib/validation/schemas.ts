import { z } from "zod";

export const investigateRequestSchema = z.object({
  observable: z.string().trim().min(1).max(2048),
  mode: z.enum(["QUICK", "DEEP"]).default("QUICK"),
});

export const iocCreateSchema = z.object({
  value: z.string().trim().min(1).max(2048),
  notes: z.string().max(4000).optional(),
  tags: z.array(z.string().max(64)).max(32).optional(),
  source: z.string().max(256).optional(),
});

export const iocUpdateSchema = z.object({
  notes: z.string().max(4000).optional(),
  tags: z.array(z.string().max(64)).max(32).optional(),
});

// --- Third-party response validation -------------------------------------
// Every provider adapter validates the shape of what it gets back before
// treating it as trustworthy. These are intentionally permissive (providers
// change fields over time) but they catch outright malformed payloads.

export const rdapResponseSchema = z
  .object({
    handle: z.string().optional(),
    ldhName: z.string().optional(),
    name: z.string().optional(),
    entities: z.array(z.unknown()).optional(),
    events: z.array(z.unknown()).optional(),
    nameservers: z.array(z.unknown()).optional(),
    status: z.array(z.string()).optional(),
    remarks: z.array(z.unknown()).optional(),
    startAddress: z.string().optional(),
    endAddress: z.string().optional(),
    country: z.string().optional(),
  })
  .passthrough();

export const crtShEntrySchema = z.object({
  issuer_ca_id: z.number().optional(),
  issuer_name: z.string().optional(),
  common_name: z.string().optional(),
  name_value: z.string(),
  not_before: z.string().optional(),
  not_after: z.string().optional(),
  serial_number: z.string().optional(),
});
export const crtShResponseSchema = z.array(crtShEntrySchema);

export const dohResponseSchema = z.object({
  Status: z.number(),
  Answer: z
    .array(
      z.object({
        name: z.string(),
        type: z.number(),
        TTL: z.number().optional(),
        data: z.string(),
      })
    )
    .optional(),
});

export const nvdCveResponseSchema = z.object({
  vulnerabilities: z
    .array(
      z.object({
        cve: z.object({
          id: z.string(),
          published: z.string().optional(),
          lastModified: z.string().optional(),
          descriptions: z
            .array(z.object({ lang: z.string(), value: z.string() }))
            .optional(),
          metrics: z.record(z.string(), z.unknown()).optional(),
          weaknesses: z.array(z.unknown()).optional(),
          references: z.array(z.unknown()).optional(),
          configurations: z.array(z.unknown()).optional(),
        }),
      })
    )
    .optional(),
});

export const cisaKevResponseSchema = z.object({
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vendorProject: z.string().optional(),
      product: z.string().optional(),
      vulnerabilityName: z.string().optional(),
      dateAdded: z.string().optional(),
      shortDescription: z.string().optional(),
      requiredAction: z.string().optional(),
      dueDate: z.string().optional(),
      knownRansomwareCampaignUse: z.string().optional(),
    })
  ),
});

export const abuseIpDbResponseSchema = z.object({
  data: z.object({
    ipAddress: z.string(),
    abuseConfidenceScore: z.number(),
    countryCode: z.string().nullable().optional(),
    usageType: z.string().nullable().optional(),
    isp: z.string().nullable().optional(),
    domain: z.string().nullable().optional(),
    totalReports: z.number().optional(),
    lastReportedAt: z.string().nullable().optional(),
    isTor: z.boolean().optional(),
  }),
});

export const virusTotalResponseSchema = z.object({
  data: z.object({
    id: z.string(),
    type: z.string(),
    attributes: z.record(z.string(), z.unknown()),
  }),
});

export const threatFoxResponseSchema = z.object({
  query_status: z.string(),
  data: z.union([z.array(z.record(z.string(), z.unknown())), z.string()]).optional(),
});

export const urlhausResponseSchema = z.object({
  query_status: z.string(),
  url: z.string().optional(),
  url_status: z.string().optional(),
  threat: z.string().nullable().optional(),
  tags: z.array(z.string()).nullable().optional(),
  payloads: z.array(z.record(z.string(), z.unknown())).nullable().optional(),
});

export const malwareBazaarResponseSchema = z.object({
  query_status: z.string(),
  data: z.array(z.record(z.string(), z.unknown())).nullable().optional(),
});
