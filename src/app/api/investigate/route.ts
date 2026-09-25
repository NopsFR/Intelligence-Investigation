import { NextResponse } from "next/server";
import { investigateRequestSchema } from "@/lib/validation/schemas";
import { runInvestigation, UnrecognizedObservableError } from "@/lib/investigation/orchestrator";
import { saveInvestigation, listInvestigations } from "@/lib/db/investigations";
import { rateLimit, clientKeyFrom } from "@/lib/security/rateLimit";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const key = clientKeyFrom(request);
  const limited = rateLimit(`investigate:${key}`, 20, 60_000);
  if (!limited.allowed) {
    return NextResponse.json({ error: "Rate limit exceeded. Try again shortly." }, { status: 429 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = investigateRequestSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request", details: parsed.error.flatten() }, { status: 400 });
  }

  try {
    const result = await runInvestigation(parsed.data.observable, parsed.data.mode);
    const saved = await saveInvestigation(result);
    return NextResponse.json({ investigation: saved }, { status: 201 });
  } catch (err) {
    if (err instanceof UnrecognizedObservableError) {
      return NextResponse.json({ error: err.message }, { status: 422 });
    }
    console.error("Investigation failed", err);
    return NextResponse.json({ error: "Investigation failed unexpectedly." }, { status: 500 });
  }
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const limit = Math.min(Number(url.searchParams.get("limit")) || 25, 100);
  const offset = Number(url.searchParams.get("offset")) || 0;
  const search = url.searchParams.get("search") ?? undefined;
  const observableType = url.searchParams.get("type") ?? undefined;

  const { items, total } = await listInvestigations({ limit, offset, search, observableType });
  return NextResponse.json({ items, total });
}
