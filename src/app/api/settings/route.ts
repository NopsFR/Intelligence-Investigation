import { settingsData } from "@/lib/db/settings";
import { handler, isOperator, json } from "@/lib/server/api";

export const GET = handler(async () => json(await settingsData(await isOperator())));
