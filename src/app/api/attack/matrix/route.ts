import { attackMatrix, loadAttack } from "@/lib/intel/attack";
import { handler, json } from "@/lib/server/api";

export const GET = handler(async () => {
  const index = await loadAttack();
  return json({ matrix: attackMatrix(index), meta: index.meta });
});
