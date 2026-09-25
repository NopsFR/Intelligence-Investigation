import type { NextRequest } from "next/server";
import { testProvider } from "@/lib/db/health";
import { getProvider } from "@/lib/providers/registry";
import { ApiError, assertSameOrigin, enforceLimits, handler, json } from "@/lib/server/api";

type Ctx = { params: Promise<{ provider: string }> };

export const maxDuration = 60;

export const POST = handler(async (req: NextRequest, { params }: Ctx) => {
  assertSameOrigin(req, { requireJson: false });
  const def = getProvider((await params).provider);
  if (!def) throw new ApiError(404, "not-found", "Unknown provider.");
  if (!def.healthCheck) throw new ApiError(400, "not-testable", `${def.name} is derived from other sources and has no connection of its own to test.`);
  await enforceLimits(req, [
    { name: "provider-test", limit: 20, windowSeconds: 300, scope: "client" },
    { name: `provider-test:${def.id}`, limit: 30, windowSeconds: 3600, scope: "global" },
  ]);
  return json(await testProvider(def));
});
