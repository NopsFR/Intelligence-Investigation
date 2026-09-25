import { dashboardData } from "@/lib/db/dashboard";
import { handler, json } from "@/lib/server/api";

export const GET = handler(async () => json(await dashboardData()));
