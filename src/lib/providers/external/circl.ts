import "server-only";
import { z } from "zod";
import { fact, facts } from "../helpers";
import type { ProviderDefinition } from "../types";

const hashlookupResponse = z
  .object({
    FileName: z.string().optional(),
    FileSize: z.union([z.string(), z.number()]).optional(),
    MD5: z.string().optional(),
    "SHA-1": z.string().optional(),
    "SHA-256": z.string().optional(),
    "SHA-512": z.string().optional(),
    SSDEEP: z.string().optional(),
    TLSH: z.string().optional(),
    ProductCode: z.unknown().optional(),
    OpSystemCode: z.unknown().optional(),
    source: z.string().optional(),
    db: z.string().optional(),
    "hashlookup:trust": z.number().optional(),
    "hashlookup:parent-total": z.number().optional(),
    parents: z.array(z.record(z.string(), z.unknown())).optional(),
    message: z.string().optional(),
  })
  .passthrough();

export const circlHashlookup: ProviderDefinition = {
  id: "circl-hashlookup",
  code: "CIR",
  name: "CIRCL hashlookup",
  vendor: "CIRCL (Luxembourg CERT)",
  category: "malware",
  kind: "external",
  description: "Known-file database built from NIST NSRL and major software distributions; identifies benign files.",
  homepage: "https://hashlookup.circl.lu",
  docs: "https://www.circl.lu/services/hashlookup/",
  auth: { type: "none" },
  endpoint: "REST · JSON · hashlookup.circl.lu/lookup",
  limits: "Public service, fair use.",
  supports: ["MD5", "SHA1", "SHA256"],
  cacheTtlSeconds: 24 * 60 * 60,
  timeoutMs: 8_000,
  healthCheck: { observable: "3f64c98f22da277a07cab248c44c56eedb796a81", type: "SHA1" },
  async run(ctx) {
    const algo = ctx.type === "MD5" ? "md5" : ctx.type === "SHA1" ? "sha1" : "sha256";
    const response = await ctx.request(`https://hashlookup.circl.lu/lookup/${algo}/${ctx.observable}`, { acceptStatus: [404] });
    const d = ctx.parse(response, hashlookupResponse);
    if (response.status === 404) {
      return { summary: "Not a known software file", facts: [], empty: true, listed: false, raw: d };
    }
    const trust = d["hashlookup:trust"];
    const source = d.db ?? d.source;
    return {
      summary: `Known file${d.FileName ? `: ${d.FileName}` : ""}${source ? ` · ${source}` : ""}`,
      listed: true,
      facts: facts(
        fact("fileName", "Known file name", d.FileName, "mono", true),
        fact("source", "Source dataset", source, "text", true),
        fact("trust", "hashlookup trust", trust !== undefined ? trust / 100 : undefined, "percent", true),
        fact("size", "File size", d.FileSize !== undefined ? Number(d.FileSize) : undefined, "bytes"),
        fact("parents", "Parent packages", d["hashlookup:parent-total"], "number"),
        fact("md5", "MD5", d.MD5?.toLowerCase(), "mono"),
        fact("sha1", "SHA-1", d["SHA-1"]?.toLowerCase(), "mono"),
        fact("sha256", "SHA-256", d["SHA-256"]?.toLowerCase(), "mono")
      ),
      data: { kind: "circl-hashlookup", trust, fileName: d.FileName, source },
      findings: [
        {
          rule: "malware.hashlookup.known-file",
          severity: "INFO",
          category: "malware",
          title: `Hash matches a known software file${d.FileName ? ` (${d.FileName})` : ""}`,
          description: `CIRCL hashlookup lists this file in ${source ?? "its known-file database"}${trust !== undefined ? ` with a trust score of ${trust}/100` : ""}.`,
          rationale:
            "Known-file databases (such as NIST NSRL) catalogue files shipped with legitimate software. A match strongly suggests the file is benign — but legitimate binaries are also abused (LOLBins), so context still matters.",
          evidence: `${d.FileName ?? "file"} · ${source ?? "hashlookup"}`,
          evidenceData: { fileName: d.FileName ?? null, source: source ?? null, trust: trust ?? null },
          references: [{ label: "hashlookup record", url: `https://hashlookup.circl.lu/lookup/${algo}/${ctx.observable}` }],
        },
      ],
      raw: { ...d, parents: d.parents?.slice(0, 5) },
    };
  },
};
