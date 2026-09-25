"use client";

import { ArrowRight, Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, ApiClientError } from "@/lib/client/api";
import { useLiveInvestigation } from "@/lib/client/investigation";
import type { InvestigationRecord } from "@/lib/core/types";
import { STATUS_LABELS } from "@/lib/core/types";
import { ErrorNote, Panel } from "@/components/ui/primitives";
import { FactsGrid } from "../investigation/Facts";
import { Chip } from "../analysis/common";

interface SectionSpec {
  provider: string;
  title: string;
}

const SECTIONS: SectionSpec[] = [
  { provider: "rdap", title: "RDAP" },
  { provider: "email-security", title: "DNS · SPF/DKIM/DMARC/MTA-STS" },
  { provider: "certspotter", title: "Certificates (Cert Spotter)" },
  { provider: "crtsh", title: "Certificates (crt.sh)" },
  { provider: "hosting", title: "Hosting infrastructure" },
  { provider: "wot", title: "Reputation (WOT)" },
  { provider: "otx", title: "AlienVault OTX" },
  { provider: "threatfox", title: "ThreatFox" },
  { provider: "urlhaus", title: "URLhaus" },
  { provider: "malwarebazaar", title: "MalwareBazaar" },
];

const STATUS_TONE: Record<string, "ok" | "warn" | "err" | "neutral"> = {
  SUCCESS: "ok",
  PARTIAL: "warn",
  EMPTY: "neutral",
  NOT_CONFIGURED: "neutral",
  RATE_LIMITED: "warn",
  AUTH_FAILED: "err",
  TIMEOUT: "warn",
  NETWORK_ERROR: "warn",
  SCHEMA_ERROR: "err",
  POLICY_BLOCKED: "err",
  SKIPPED: "neutral",
  ERROR: "err",
};

/** Starts (or reuses) a QUICK domain investigation and shows selected provider results inline. */
export function EmbeddedDomainIntel({ domain }: { domain: string }) {
  const [initial, setInitial] = useState<InvestigationRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const start = await api<{ id: string }>("/api/investigations", { method: "POST", json: { observable: domain, type: "DOMAIN", mode: "QUICK" } });
        if (cancelled) return;
        const rec = await api<{ investigation: InvestigationRecord }>(`/api/investigations/${start.id}`);
        if (!cancelled) setInitial(rec.investigation);
      } catch (err) {
        if (!cancelled) setError((err as ApiClientError).message);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [domain]);

  if (error) return <ErrorNote title="Could not start the domain investigation">{error}</ErrorNote>;
  if (!initial) {
    return (
      <div className="flex items-center gap-2 p-[var(--panel-pad)] text-sm text-fg-3" aria-busy="true">
        <Loader2 size={14} className="animate-spin" /> Starting domain investigation for {domain}…
      </div>
    );
  }
  return <Live initial={initial} />;
}

function Live({ initial }: { initial: InvestigationRecord }) {
  const { inv } = useLiveInvestigation(initial);
  const byId = new Map(inv.providerResults.map((o) => [o.provider, o]));

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        {inv.status === "RUNNING" && <Loader2 size={13} className="animate-spin text-fg-3" />}
        <span className="text-xs text-fg-3">{inv.status === "RUNNING" ? "Running…" : inv.summary}</span>
        <Link href={`/investigations/${inv.id}`} className="btn btn-ghost btn-sm ml-auto">
          Full investigation &amp; evidence graph <ArrowRight size={12} />
        </Link>
      </div>
      {SECTIONS.map(({ provider, title }) => {
        const outcome = byId.get(provider);
        if (!outcome) return null;
        const facts = outcome.result?.facts ?? [];
        return (
          <Panel key={provider} title={title} meta={<Chip tone={STATUS_TONE[outcome.status] ?? "neutral"}>{STATUS_LABELS[outcome.status] ?? outcome.status}</Chip>} bodyClassName="p-0">
            {facts.length > 0 ? (
              <FactsGrid facts={facts} className="px-[var(--panel-pad)] py-2.5" />
            ) : (
              <p className="px-[var(--panel-pad)] py-3 text-xs text-fg-4">{outcome.result?.summary || outcome.errorMessage || "No details."}</p>
            )}
          </Panel>
        );
      })}
    </div>
  );
}
