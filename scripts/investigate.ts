/**
 * Command-line investigation runner (no database required).
 *
 *   npm run investigate -- <observable> [--deep] [--type IPV4] [--json] [--out file.json]
 *
 * Runs the same plan, providers and correlation as the web app, with API keys
 * read from the environment. --json/--out emit a capture that
 * scripts/import-investigation.ts can load into a database.
 */
import { writeFileSync } from "node:fs";
import { SEVERITY_RANK, STATUS_LABELS, type ProviderOutcome } from "@/lib/core/types";
import { executePlan } from "@/lib/engine/plan-runner";
import { stepRunner } from "@/lib/engine/step";
import { finalStatus, summarize } from "@/lib/engine/summary";
import { detectAs } from "@/lib/observables/detect";
import { buildPlan, getProvider } from "@/lib/providers/registry";
import type { ObservableType } from "@/lib/core/types";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const input = process.argv.slice(2).find((a, i, all) => !a.startsWith("--") && !["--type", "--out"].includes(all[i - 1] ?? ""));
  if (!input) {
    console.error("usage: npm run investigate -- <observable> [--deep] [--type TYPE] [--json] [--out file]");
    process.exit(2);
  }
  const detected = detectAs(input, arg("type") as ObservableType | undefined);
  if (!detected) {
    console.error(`Not a recognised observable: ${input}`);
    process.exit(2);
  }
  const mode = process.argv.includes("--deep") ? "DEEP" : "QUICK";
  const plan = buildPlan(detected.type, mode);
  const startedAt = new Date();
  const log = (message: string, meta?: Record<string, unknown>) => console.error(`[warn] ${message} ${meta ? JSON.stringify(meta) : ""}`);
  const outcomes = await executePlan(plan, stepRunner({ observable: detected.normalized, type: detected.type, mode, services: { catalog: getProvider, logger: log } }), {
    onOutcome: (o) => {
      if (!process.argv.includes("--json")) console.error(`  ${o.provider.padEnd(18)} ${STATUS_LABELS[o.status].padEnd(22)} ${String(o.latencyMs).padStart(6)} ms  ${o.result?.summary ?? o.errorMessage ?? ""}`);
    },
  });
  const all = plan.map((s) => outcomes.get(s.id)).filter((o): o is ProviderOutcome => Boolean(o));
  const capture = {
    format: "nops-capture",
    version: 1,
    observable: input,
    normalized: detected.normalized,
    type: detected.type,
    mode,
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    status: finalStatus(all),
    summary: summarize(all),
    plan,
    outcomes: all,
  };
  const out = arg("out");
  if (out) writeFileSync(out, JSON.stringify(capture, null, 2));
  if (process.argv.includes("--json")) {
    process.stdout.write(JSON.stringify(capture, null, 2));
    return;
  }
  console.log(`\n${detected.type} ${detected.normalized} · ${mode} · ${capture.status}`);
  console.log(capture.summary);
  const findings = all.flatMap((o) => (o.result?.findings ?? []).map((f) => ({ ...f, source: o.provider }))).sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  for (const f of findings) console.log(`  [${f.severity.padEnd(8)}] ${f.title}  (${f.source})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
