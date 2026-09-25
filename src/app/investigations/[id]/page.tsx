import { notFound } from "next/navigation";
import { getInvestigation } from "@/lib/db/investigations";
import { InvestigationStatusBadge } from "@/components/Badges";
import { FindingsList } from "@/components/FindingsList";
import { ProviderResultsGrid } from "@/components/ProviderResultsGrid";
import { InvestigationGraph } from "@/components/InvestigationGraph";
import { ExportBar } from "@/components/ExportBar";
import { OBSERVABLE_LABELS } from "@/types/observable";
import { format } from "date-fns";

export default async function InvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const investigation = await getInvestigation(id);
  if (!investigation) notFound();

  return (
    <div className="mx-auto max-w-[1200px] px-4 md:px-6 py-10 space-y-10">
      <header className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-1">
              {OBSERVABLE_LABELS[investigation.observableType]} · {investigation.mode === "DEEP" ? "Deep investigation" : "Quick scan"}
            </p>
            <h1 className="text-2xl md:text-[28px] font-medium text-[var(--nops-text)] break-all">
              {investigation.observable}
            </h1>
          </div>
          <InvestigationStatusBadge status={investigation.status} />
        </div>
        <p className="text-sm text-[var(--nops-text-dim)] max-w-3xl">{investigation.summary}</p>
        <p className="font-mono text-[11px] text-[var(--nops-text-faint)]">
          Investigated {format(new Date(investigation.createdAt), "yyyy-MM-dd HH:mm 'UTC'")}
        </p>
        <ExportBar investigation={investigation} />
      </header>

      <Section title="Findings" count={investigation.findings.length}>
        <FindingsList findings={investigation.findings} />
      </Section>

      <Section title="Intelligence" subtitle="Provider results" count={investigation.providerResults.length}>
        <ProviderResultsGrid results={investigation.providerResults} />
      </Section>

      <Section title="Relationship graph">
        <InvestigationGraph root={investigation.normalizedObservable} relationships={investigation.relationships} />
      </Section>
    </div>
  );
}

function Section({
  title,
  subtitle,
  count,
  children,
}: {
  title: string;
  subtitle?: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="flex items-baseline gap-2 mb-4 border-b border-[var(--nops-border)] pb-2">
        <h2 className="font-mono text-sm uppercase tracking-wider text-[var(--nops-text)]">{title}</h2>
        {subtitle && <span className="font-mono text-xs text-[var(--nops-text-faint)]">/ {subtitle}</span>}
        {typeof count === "number" && (
          <span className="ml-auto font-mono text-xs text-[var(--nops-text-faint)]">{count}</span>
        )}
      </div>
      {children}
    </section>
  );
}
