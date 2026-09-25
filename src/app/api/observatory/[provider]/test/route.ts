import { NextResponse } from "next/server";
import { getProvider } from "@/lib/providers/registry";
import { prisma } from "@/lib/db/client";
import { rateLimit, clientKeyFrom } from "@/lib/security/rateLimit";

export const runtime = "nodejs";

export async function POST(request: Request, { params }: { params: Promise<{ provider: string }> }) {
  const key = clientKeyFrom(request);
  const limited = rateLimit(`observatory-test:${key}`, 30, 60_000);
  if (!limited.allowed) {
    return NextResponse.json({ error: "Rate limit exceeded. Try again shortly." }, { status: 429 });
  }

  const { provider: providerId } = await params;
  const provider = getProvider(providerId);
  if (!provider) {
    return NextResponse.json({ error: "Unknown provider" }, { status: 404 });
  }

  const outcome = await provider.healthCheck();

  await prisma.apiProviderHealth.upsert({
    where: { provider: providerId },
    create: {
      provider: providerId,
      configured: provider.isConfigured(),
      lastCheckedAt: new Date(),
      lastStatus: outcome.status,
      lastLatencyMs: outcome.latencyMs,
      lastError: outcome.errorMessage ?? null,
    },
    update: {
      configured: provider.isConfigured(),
      lastCheckedAt: new Date(),
      lastStatus: outcome.status,
      lastLatencyMs: outcome.latencyMs,
      lastError: outcome.errorMessage ?? null,
    },
  });

  return NextResponse.json({ outcome });
}
