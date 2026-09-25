import { NextResponse } from "next/server";
import { iocUpdateSchema } from "@/lib/validation/schemas";
import { prisma } from "@/lib/db/client";

export const runtime = "nodejs";

export async function PATCH(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = iocUpdateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request", details: parsed.error.flatten() }, { status: 400 });
  }

  try {
    const item = await prisma.iocEntry.update({
      where: { id },
      data: {
        notes: parsed.data.notes,
        tags: parsed.data.tags ? JSON.stringify(parsed.data.tags) : undefined,
      },
    });
    return NextResponse.json({ item });
  } catch {
    return NextResponse.json({ error: "IOC not found" }, { status: 404 });
  }
}

export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    await prisma.iocEntry.delete({ where: { id } });
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "IOC not found" }, { status: 404 });
  }
}
