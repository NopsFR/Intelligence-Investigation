import { NextResponse } from "next/server";
import { dashboardStats } from "@/lib/db/investigations";

export const runtime = "nodejs";

export async function GET() {
  const stats = await dashboardStats();
  return NextResponse.json(stats);
}
