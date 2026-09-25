import { NextResponse } from "next/server";
import { iocCreateSchema } from "@/lib/validation/schemas";
import { detectObservable } from "@/lib/observables/detect";
import { prisma } from "@/lib/db/client";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search")?.trim();
  const tag = url.searchParams.get("tag")?.trim();

  const entries = await prisma.iocEntry.findMany({
    where: search ? { value: { contains: search } } : undefined,
    orderBy: { updatedAt: "desc" },
    take: 200,
  });

  const filtered = tag
    ? entries.filter((e) => (e.tags ? (JSON.parse(e.tags) as string[]).includes(tag) : false))
    : entries;

  return NextResponse.json({
    items: filtered.map((e) => ({
      ...e,
      tags: e.tags ? JSON.parse(e.tags) : [],
      investigationRefIds: e.investigationRefIds ? JSON.parse(e.investigationRefIds) : [],
      createdAt: e.createdAt.toISOString(),
      updatedAt: e.updatedAt.toISOString(),
    })),
  });
}

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = iocCreateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request", details: parsed.error.flatten() }, { status: 400 });
  }

  const detected = detectObservable(parsed.data.value);
  if (!detected) {
    return NextResponse.json({ error: "Could not detect a supported observable type for this value." }, { status: 422 });
  }

  const entry = await prisma.iocEntry.upsert({
    where: { value_type: { value: detected.normalized, type: detected.type } },
    create: {
      value: detected.normalized,
      type: detected.type,
      notes: parsed.data.notes,
      tags: parsed.data.tags ? JSON.stringify(parsed.data.tags) : null,
      source: parsed.data.source ?? "Manual entry",
    },
    update: {
      notes: parsed.data.notes,
      tags: parsed.data.tags ? JSON.stringify(parsed.data.tags) : undefined,
    },
  });

  return NextResponse.json({ item: entry }, { status: 201 });
}
