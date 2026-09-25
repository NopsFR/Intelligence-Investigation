import { observatorySnapshot } from "@/lib/db/health";
import { handler, json } from "@/lib/server/api";

export const GET = handler(async () => json(await observatorySnapshot()));
