import Link from "next/link";
import { notFound } from "next/navigation";
import { OBSERVABLE_LABELS, SEVERITY_RANK, STATUS_LABELS, type FactValue } from "@/lib/core/types";
import { getInvestigation } from "@/lib/db/investigations";
import { defang } from "@/lib/observables/fang";
import { PROVIDERS } from "@/lib/providers/registry";
import { PrintButton } from "@/components/investigation/PrintButton";

export const metadata = { title: "Investigation report" };

const NAMES = Object.fromEntries(PROVIDERS.map((p) => [p.id, p.name]));
const SEV_COLOR: Record<string, string> = { CRITICAL: "#b3121c", HIGH: "#c2521a", MEDIUM: "#9a6b00", LOW: "#2f5f86", INFO: "#555" };

function v(value: FactValue): string {
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return value === null ? "—" : String(value);
}

/** Paper-oriented report: light, dense, defanged. Printing from the browser produces the PDF. */
export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[a-z0-9]{8,40}$/i.test(id)) notFound();
  const inv = await getInvestigation(id);
  if (!inv) notFound();
  const findings = [...inv.findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  return (
    <div className="mx-auto max-w-[900px] px-4 py-6">
      <div className="no-print mb-4 flex items-center justify-between gap-3">
        <Link href={`/investigations/${inv.id}`} className="btn btn-ghost btn-sm">
          ← Back to investigation
        </Link>
        <PrintButton />
      </div>
      <article className="report rounded-[3px] bg-[#fbfbf9] px-10 py-9 text-[13px] leading-relaxed text-[#1b1b1b] shadow-[0_0_0_1px_#2a2d32] print:rounded-none print:px-0 print:py-0 print:shadow-none">
        <header className="mb-6 border-b-2 border-[#1b1b1b] pb-4">
          <div className="flex items-center justify-between text-[10px] font-semibold tracking-[0.18em] uppercase" style={{ fontStretch: "80%" }}>
            <span>NOPS / Cyber Intelligence — Investigation report</span>
            <span className="mono tracking-normal normal-case">{inv.id}</span>
          </div>
          <h1 className="mono mt-3 text-[20px] font-semibold break-all">{defang(inv.normalizedObservable)}</h1>
          <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-0.5 text-[11.5px] text-[#444] sm:grid-cols-4">
            <span>Type: {OBSERVABLE_LABELS[inv.observableType]}</span>
            <span>Mode: {inv.mode === "DEEP" ? "Deep investigation" : "Quick scan"}</span>
            <span>Status: {inv.status}</span>
            <span>Started: {inv.createdAt.replace("T", " ").slice(0, 19)} UTC</span>
          </div>
          <p className="mt-3 font-medium">{inv.summary}</p>
        </header>

        <section className="mb-6">
          <h2 className="mb-2 text-[11px] font-bold tracking-[0.12em] uppercase">Findings ({findings.length})</h2>
          {!findings.length && <p>No findings were produced. Absence of findings is not proof that the observable is safe.</p>}
          {findings.map((f) => (
            <div key={f.id} className="mb-3 break-inside-avoid border-l-[3px] py-1 pl-3" style={{ borderColor: SEV_COLOR[f.severity] }}>
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="text-[10px] font-bold tracking-wider" style={{ color: SEV_COLOR[f.severity] }}>
                  {f.severity}
                </span>
                <span className="font-semibold">{f.title}</span>
              </div>
              <p>{f.description}</p>
              {f.rationale && <p className="text-[#444]">Why it matters: {f.rationale}</p>}
              <p className="mono text-[11px] break-words text-[#333]">Evidence: {defang(f.evidence)}</p>
              {f.remediation && <p className="text-[#333]">Remediation: {f.remediation}</p>}
              <p className="text-[10.5px] text-[#666]">
                Source: {NAMES[f.source] ?? f.source} · rule {f.rule} · observed {f.observedAt.replace("T", " ").slice(0, 19)} UTC
              </p>
            </div>
          ))}
        </section>

        <section className="mb-6 break-inside-avoid">
          <h2 className="mb-2 text-[11px] font-bold tracking-[0.12em] uppercase">Sources</h2>
          <table className="w-full border-collapse text-[11px]">
            <thead>
              <tr className="border-b border-[#1b1b1b] text-left">
                <th className="py-1 pr-2">Source</th>
                <th className="py-1 pr-2">State</th>
                <th className="py-1 pr-2">Retrieved (UTC)</th>
                <th className="py-1">Result</th>
              </tr>
            </thead>
            <tbody>
              {inv.providerResults.map((o) => (
                <tr key={o.provider} className="border-b border-[#ddd] align-top">
                  <td className="py-1 pr-2 whitespace-nowrap">{NAMES[o.provider] ?? o.provider}</td>
                  <td className="py-1 pr-2 whitespace-nowrap">{STATUS_LABELS[o.status]}</td>
                  <td className="mono py-1 pr-2 whitespace-nowrap">{o.retrievedAt.replace("T", " ").slice(0, 19)}</td>
                  <td className="py-1">{defang(o.result?.summary ?? o.errorMessage ?? "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section className="mb-6">
          <h2 className="mb-2 text-[11px] font-bold tracking-[0.12em] uppercase">Evidence detail</h2>
          {inv.providerResults
            .filter((o) => o.result?.facts.length)
            .map((o) => (
              <div key={o.provider} className="mb-3 break-inside-avoid">
                <h3 className="text-[12px] font-semibold">{NAMES[o.provider] ?? o.provider}</h3>
                <dl className="grid grid-cols-[180px_1fr] gap-x-3 text-[11px]">
                  {o.result!.facts.map((f) => (
                    <div key={f.key} className="contents">
                      <dt className="text-[#555]">{f.label}</dt>
                      <dd className="mono break-words">{defang(v(f.value))}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            ))}
        </section>

        <footer className="border-t border-[#bbb] pt-3 text-[10px] text-[#666]">
          Generated {new Date().toISOString().replace("T", " ").slice(0, 19)} UTC. Findings are evidence-based and cite their source; observables are defanged. MITRE ATT&CK® content © The MITRE Corporation.
        </footer>
      </article>
    </div>
  );
}
