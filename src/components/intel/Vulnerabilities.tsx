"use client";

import { AlertOctagon, ExternalLink, Radar, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { useInvestigate } from "@/lib/client/investigate";
import { api, ApiClientError } from "@/lib/client/api";
import { ErrorNote, Panel, Stat } from "@/components/ui/primitives";
import { Chip, DataTable, Mono } from "../analysis/common";
import { Time } from "../ui/Time";

interface KevEntry {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}
interface RecentCve {
  id: string;
  published?: string;
  status?: string;
  description?: string;
  cvss?: { score: number; severity?: string; vector?: string; version: string };
  cwes: string[];
  epss?: { epss: number; percentile: number };
}
interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
}

interface Payload {
  kev: { fetchedAt?: string; catalogVersion?: string; count?: number; entries?: KevEntry[]; error?: string };
  recent: { fetchedAt?: string; totalResults?: number; entries?: RecentCve[]; error?: string };
  epss: { fetchedAt?: string; entries?: EpssEntry[]; error?: string };
}

const cvssTone = (score?: number) => (score === undefined ? "neutral" : score >= 9 ? "err" : score >= 7 ? "err" : score >= 4 ? "warn" : "neutral");

export function Vulnerabilities() {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"kev" | "recent" | "epss">("kev");
  const { start, pending } = useInvestigate();

  const load = () => {
    api<Payload>("/api/intel/vulnerabilities")
      .then(setData)
      .catch((e: ApiClientError) => setError(e.message));
  };
  useEffect(() => {
    setTimeout(load, 0);
  }, []);

  if (error) return <ErrorNote title="Could not load vulnerability feeds" action={<button type="button" className="btn btn-sm" onClick={load}>Retry</button>}>{error}</ErrorNote>;
  if (!data) return <Panel><div className="flex flex-col gap-2 p-2" aria-busy="true"><div className="skeleton h-4 w-1/3" /><div className="skeleton h-4 w-1/2" /><div className="skeleton h-4 w-2/5" /></div></Panel>;

  const kevError = data.kev.error;
  const recentError = data.recent.error;
  const epssError = data.epss.error;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-px bg-line-1 sm:grid-cols-3">
        <div className="panel bg-ink-1 p-[var(--panel-pad)]">
          <Stat label="CISA KEV catalogue" value={kevError ? "—" : (data.kev.count ?? 0).toLocaleString()} sub={kevError ? kevError : `Version ${data.kev.catalogVersion ?? "?"} · confirmed active exploitation`} />
        </div>
        <div className="panel bg-ink-1 p-[var(--panel-pad)]">
          <Stat label="Published, last 8 days" value={recentError ? "—" : (data.recent.totalResults ?? data.recent.entries?.length ?? 0).toLocaleString()} sub={recentError ? recentError : "NVD"} />
        </div>
        <div className="panel bg-ink-1 p-[var(--panel-pad)]">
          <Stat label="EPSS ranked" value={epssError ? "—" : (data.epss.entries?.length ?? 0).toLocaleString()} sub={epssError ? epssError : "Highest exploit-prediction scores"} />
        </div>
      </div>

      <section className="panel">
        <div className="flex flex-wrap items-center gap-1.5 border-b border-line-1 px-2 py-2">
          {(
            [
              ["kev", "Known Exploited (KEV)", AlertOctagon],
              ["recent", "Recently published", Radar],
              ["epss", "Highest EPSS", RefreshCw],
            ] as const
          ).map(([id, label, Icon]) => (
            <button key={id} type="button" onClick={() => setTab(id)} className={`btn btn-sm ${tab === id ? "btn-primary" : "btn-ghost"}`}>
              <Icon size={13} /> {label}
            </button>
          ))}
          <span className="ml-auto text-xs text-fg-4">{data[tab].fetchedAt && <>Fetched <Time iso={data[tab].fetchedAt} /></>}</span>
        </div>

        {tab === "kev" &&
          (kevError ? (
            <ErrorNote title="CISA KEV unavailable">{kevError}</ErrorNote>
          ) : (
            <DataTable
              rows={data.kev.entries ?? []}
              columns={[
                { key: "c", label: "CVE", render: (e) => <button type="button" className="mono link text-[12px]" disabled={pending} onClick={() => void start(e.cveID, "QUICK", { type: "CVE" })}>{e.cveID}</button>, sort: (e) => e.cveID },
                { key: "n", label: "Vulnerability", render: (e) => <span className="text-fg-1">{e.vulnerabilityName ?? e.shortDescription}</span> },
                { key: "p", label: "Product", render: (e) => <span className="text-xs text-fg-3">{[e.vendorProject, e.product].filter(Boolean).join(" / ")}</span> },
                { key: "r", label: "Ransomware use", render: (e) => (e.knownRansomwareCampaignUse === "Known" ? <Chip tone="err">Known</Chip> : <span className="text-xs text-fg-4">{e.knownRansomwareCampaignUse ?? "Unknown"}</span>) },
                { key: "a", label: "Added", render: (e) => <Mono className="text-fg-3">{e.dateAdded}</Mono>, sort: (e) => e.dateAdded ?? "" },
                { key: "d", label: "Remediation due", render: (e) => <Mono className="text-fg-3">{e.dueDate}</Mono>, sort: (e) => e.dueDate ?? "" },
              ]}
            />
          ))}

        {tab === "recent" &&
          (recentError ? (
            <ErrorNote title="NVD recent CVEs unavailable">{recentError}</ErrorNote>
          ) : (
            <DataTable
              rows={data.recent.entries ?? []}
              columns={[
                { key: "c", label: "CVE", render: (e) => <button type="button" className="mono link text-[12px]" disabled={pending} onClick={() => void start(e.id, "QUICK", { type: "CVE" })}>{e.id}</button>, sort: (e) => e.id },
                { key: "d", label: "Description", render: (e) => <span className="line-clamp-2 max-w-lg text-xs text-fg-2">{e.description}</span> },
                { key: "cv", label: "CVSS", render: (e) => e.cvss ? <Chip tone={cvssTone(e.cvss.score)}>{`${e.cvss.score} ${e.cvss.severity ?? ""} (v${e.cvss.version})`}</Chip> : <span className="text-xs text-fg-4">unscored</span>, sort: (e) => e.cvss?.score ?? -1 },
                { key: "e", label: "EPSS", render: (e) => (e.epss ? <Mono>{(e.epss.epss * 100).toFixed(1)}% · p{(e.epss.percentile * 100).toFixed(0)}</Mono> : ""), sort: (e) => e.epss?.epss ?? -1 },
                { key: "w", label: "CWE", render: (e) => <span className="text-xs text-fg-3">{e.cwes.slice(0, 2).join(", ")}</span> },
                { key: "p", label: "Published", render: (e) => <Time iso={e.published} className="text-xs text-fg-4" />, sort: (e) => e.published ?? "" },
              ]}
            />
          ))}

        {tab === "epss" &&
          (epssError ? (
            <ErrorNote title="EPSS unavailable">{epssError}</ErrorNote>
          ) : (
            <DataTable
              rows={data.epss.entries ?? []}
              columns={[
                { key: "c", label: "CVE", render: (e) => <button type="button" className="mono link text-[12px]" disabled={pending} onClick={() => void start(e.cve, "QUICK", { type: "CVE" })}>{e.cve}</button>, sort: (e) => e.cve },
                { key: "e", label: "EPSS (exploit probability, 30 days)", render: (e) => <Chip tone={e.epss > 0.5 ? "err" : e.epss > 0.1 ? "warn" : "neutral"}>{(e.epss * 100).toFixed(2)}%</Chip>, sort: (e) => e.epss },
                { key: "p", label: "Percentile", render: (e) => <Mono>{(e.percentile * 100).toFixed(1)}</Mono>, sort: (e) => e.percentile },
                { key: "l", label: "", render: (e) => <a className="link inline-flex items-center gap-1 text-xs" href={`https://nvd.nist.gov/vuln/detail/${e.cve}`} target="_blank" rel="noopener noreferrer nofollow">NVD <ExternalLink size={11} /></a> },
              ]}
            />
          ))}
      </section>
    </div>
  );
}
