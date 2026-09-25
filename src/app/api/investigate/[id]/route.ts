import { NextResponse } from "next/server";
import { getInvestigation, deleteInvestigation } from "@/lib/db/investigations";

export const runtime = "nodejs";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const investigation = await getInvestigation(id);
  if (!investigation) {
    return NextResponse.json({ error: "Investigation not found" }, { status: 404 });
  }
  return NextResponse.json({ investigation });
}

export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    await deleteInvestigation(id);
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "Investigation not found" }, { status: 404 });
  }
}
