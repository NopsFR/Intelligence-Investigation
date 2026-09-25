import type { NextRequest } from "next/server";
import { attackDetails, loadAttack } from "@/lib/intel/attack";
import { ApiError, handler, json } from "@/lib/server/api";

type Ctx = { params: Promise<{ id: string }> };

export const GET = handler(async (_req: NextRequest, { params }: Ctx) => {
  const id = (await params).id.toUpperCase();
  if (!/^(TA|T|G|S|C|M)\d{4}(\.\d{3})?$/.test(id)) throw new ApiError(400, "invalid-id", "Not an ATT&CK identifier.");
  const index = await loadAttack();
  const details = attackDetails(index, id);
  if (!details) throw new ApiError(404, "not-found", `${id} is not in ATT&CK Enterprise ${index.meta.version}.`);
  return json({ ...details, version: index.meta.version });
});
