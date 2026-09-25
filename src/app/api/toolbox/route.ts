import { NextResponse } from "next/server";
import { z } from "zod";
import { resolveWithFallback, type DnsRecordType } from "@/lib/dns/resolve";
import { inspectSecurityHeaders } from "@/lib/headers/inspect";
import { inspectTls, TlsInspectionError } from "@/lib/tls/inspect";
import { parseUrl } from "@/lib/observables/url";
import { getProvider } from "@/lib/providers/registry";
import { rateLimit, clientKeyFrom } from "@/lib/security/rateLimit";

export const runtime = "nodejs";

const requestSchema = z.discriminatedUnion("tool", [
  z.object({ tool: z.literal("dns"), name: z.string().min(1).max(253), recordType: z.enum(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]) }),
  z.object({ tool: z.literal("headers"), url: z.string().min(1).max(2048) }),
  z.object({ tool: z.literal("tls"), hostname: z.string().min(1).max(253) }),
  z.object({ tool: z.literal("url-parse"), url: z.string().min(1).max(2048) }),
  z.object({ tool: z.literal("rdap"), value: z.string().min(1).max(253), type: z.enum(["DOMAIN", "IPV4", "IPV6", "ASN"]) }),
  z.object({ tool: z.literal("crtsh"), domain: z.string().min(1).max(253) }),
]);

export async function POST(request: Request) {
  const key = clientKeyFrom(request);
  const limited = rateLimit(`toolbox:${key}`, 40, 60_000);
  if (!limited.allowed) {
    return NextResponse.json({ error: "Rate limit exceeded. Try again shortly." }, { status: 429 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = requestSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request", details: parsed.error.flatten() }, { status: 400 });
  }

  const input = parsed.data;
  try {
    switch (input.tool) {
      case "dns": {
        const result = await resolveWithFallback(input.name, input.recordType as DnsRecordType);
        return NextResponse.json({ result });
      }
      case "headers": {
        const result = await inspectSecurityHeaders(input.url);
        return NextResponse.json({ result });
      }
      case "tls": {
        try {
          const result = await inspectTls(input.hostname);
          return NextResponse.json({ result });
        } catch (err) {
          const message = err instanceof TlsInspectionError ? err.message : "TLS inspection failed";
          return NextResponse.json({ error: message }, { status: 502 });
        }
      }
      case "url-parse": {
        const result = parseUrl(input.url);
        if (!result) return NextResponse.json({ error: "Could not parse this URL." }, { status: 422 });
        return NextResponse.json({ result });
      }
      case "rdap": {
        const provider = getProvider("rdap");
        if (!provider) return NextResponse.json({ error: "RDAP provider unavailable" }, { status: 500 });
        const signal = AbortSignal.timeout(15000);
        const outcome = await provider.investigate({ observable: input.value, type: input.type, signal });
        return NextResponse.json({ result: outcome });
      }
      case "crtsh": {
        const provider = getProvider("crtsh");
        if (!provider) return NextResponse.json({ error: "crt.sh provider unavailable" }, { status: 500 });
        const signal = AbortSignal.timeout(15000);
        const outcome = await provider.investigate({ observable: input.domain, type: "DOMAIN", signal });
        return NextResponse.json({ result: outcome });
      }
    }
  } catch (err) {
    console.error("Toolbox request failed", err);
    return NextResponse.json({ error: "The tool request failed unexpectedly." }, { status: 500 });
  }
}
