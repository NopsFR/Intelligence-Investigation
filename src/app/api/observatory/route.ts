import { NextResponse } from "next/server";
import { PROVIDERS } from "@/lib/providers/registry";
import { prisma } from "@/lib/db/client";

export const runtime = "nodejs";

export async function GET() {
  const health = await prisma.apiProviderHealth.findMany();
  const healthById = new Map(health.map((h) => [h.provider, h]));

  const providers = PROVIDERS.map((p) => {
    const h = healthById.get(p.meta.id);
    return {
      id: p.meta.id,
      name: p.meta.name,
      description: p.meta.description,
      availability: p.meta.availability,
      homepage: p.meta.homepage,
      supports: p.meta.supports,
      configured: p.isConfigured(),
      lastCheckedAt: h?.lastCheckedAt?.toISOString() ?? null,
      lastStatus: h?.lastStatus ?? null,
      lastLatencyMs: h?.lastLatencyMs ?? null,
      lastError: h?.lastError ?? null,
    };
  });

  return NextResponse.json({ providers });
}
