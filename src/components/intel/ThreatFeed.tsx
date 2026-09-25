"use client";

import { Bug, Globe, Link2, Server } from "lucide-react";
import { useEffect, useState } from "react";
import { api, ApiClientError } from "@/lib/client/api";
import { useInvestigate } from "@/lib/client/investigate";
import type { ObservableType } from "@/lib/core/types";
import { ErrorNote, Panel } from "@/components/ui/primitives";
import { TypeTag } from "@/components/ui/badges";
import { Chip, DataTable, Mono } from "../analysis/common";
import { Time } from "../ui/Time";

interface ThreatFoxEntry {
  ioc: string;
  ioc_type: string;
  threat_type?: string | null;
  malware_printable?: string | null;
  confidence_level?: number | null;
  first_seen_utc?: string | null;
  reference?: string | null;
  tags?: string[] | null;
}
interface UrlhausEntry {
  id: string;
  url: string;
  url_status?: string | null;
  threat?: string | null;
  host?: string | null;
  date_added?: string | null;
  tags?: string[] | null;
}
interface BazaarEntry {
  firstSeen: string;
  sha256: string;
  fileName: string;
  fileType: string;
  signature: string;
  tags: string[];
}
interface FeodoEntry {
  ip_address: string;
  port?: number | null;
  status?: string | null;
  malware?: string | null;
  country?: string | null;
  first_seen?: string | null;
}

interface Payload {
  threatfox: { source: string; fetchedAt?: string; entries?: ThreatFoxEntry[]; count?: number; error?: string };
  urlhaus: { source: string; fetchedAt?: string; entries?: UrlhausEntry[]; count?: number; error?: string };
  bazaar: { source: string; fetchedAt?: string; entries?: BazaarEntry[]; count?: number; error?: string };
  feodo: { source: string; fetchedAt?: string; entries?: FeodoEntry[]; count?: number; error?: string };
}

const iocType = (t: string): ObservableType => (t === "domain" ? "DOMAIN" : t.startsWith("ip") ? "IPV4" : t === "url" ? "URL" : t === "md5_hash" ? "MD5" : t === "sha256_hash" ? "SHA256" : "DOMAIN");

export function ThreatFeed() {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"threatfox" | "urlhaus" | "bazaar" | "feodo">("threatfox");
  const { start, pending } = useInvestigate();

  const load = () => {
    api<Payload>("/api/intel/feed")
      .then(setData)
      .catch((e: ApiClientError) => setError(e.message));
  };
  useEffect(() => {
    setTimeout(load, 0);
  }, []);

  if (error) return <ErrorNote title="Could not load the threat feed" action={<button type="button" className="btn btn-sm" onClick={load}>Retry</button>}>{error}</ErrorNote>;
  if (!data) return <Panel><div className="flex flex-col gap-2 p-2" aria-busy="true"><div className="skeleton h-4 w-1/3" /><div className="skeleton h-4 w-1/2" /><div className="skeleton h-4 w-2/5" /></div></Panel>;

  const tabs = [
    { id: "threatfox" as const, label: "ThreatFox IOCs", icon: Link2, feed: data.threatfox },
    { id: "urlhaus" as const, label: "URLhaus URLs", icon: Globe, feed: data.urlhaus },
    { id: "bazaar" as const, label: "MalwareBazaar samples", icon: Bug, feed: data.bazaar },
    { id: "feodo" as const, label: "Feodo C2 servers", icon: Server, feed: data.feodo },
  ];
  const active = tabs.find((t) => t.id === tab)!;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-px bg-line-1 sm:grid-cols-2 xl:grid-cols-4">
        {tabs.map((t) => (
          <div key={t.id} className="panel bg-ink-1 p-[var(--panel-pad)]">
            <div className="label mb-1 flex items-center gap-1.5">
              <t.icon size={12} /> {t.label}
            </div>
            <div className="display text-xl text-fg-1">{t.feed.error ? "—" : (t.feed.count ?? t.feed.entries?.length ?? 0).toLocaleString()}</div>
            <div className="mt-0.5 text-xs text-fg-3">{t.feed.error ?? (t.feed.fetchedAt ? <>fetched <Time iso={t.feed.fetchedAt} /></> : null)}</div>
          </div>
        ))}
      </div>

      <section className="panel">
        <div className="flex flex-wrap items-center gap-1.5 border-b border-line-1 px-2 py-2">
          {tabs.map((t) => (
            <button key={t.id} type="button" onClick={() => setTab(t.id)} className={`btn btn-sm ${tab === t.id ? "btn-primary" : "btn-ghost"}`}>
              <t.icon size={13} /> {t.label}
            </button>
          ))}
          <span className="ml-auto text-xs text-fg-4">{active.feed.source}</span>
        </div>

        {active.feed.error ? (
          <ErrorNote title={`${active.label} unavailable`}>{active.feed.error}</ErrorNote>
        ) : tab === "threatfox" ? (
          <DataTable
            rows={data.threatfox.entries ?? []}
            columns={[
              { key: "i", label: "Indicator", render: (e) => <button type="button" className="mono link max-w-[280px] truncate text-left text-[12px]" disabled={pending} onClick={() => void start(e.ioc, "QUICK", { type: iocType(e.ioc_type) })}>{e.ioc}</button> },
              { key: "t", label: "Type", render: (e) => <TypeTag type={iocType(e.ioc_type)} /> },
              { key: "m", label: "Malware", render: (e) => <span className="text-fg-1">{e.malware_printable ?? "—"}</span> },
              { key: "th", label: "Threat type", render: (e) => <Chip>{e.threat_type ?? "?"}</Chip> },
              { key: "c", label: "Confidence", render: (e) => <Mono>{e.confidence_level ?? ""}</Mono>, sort: (e) => e.confidence_level ?? 0 },
              { key: "f", label: "First seen", render: (e) => <Time iso={e.first_seen_utc ?? undefined} className="text-xs text-fg-4" />, sort: (e) => e.first_seen_utc ?? "" },
            ]}
          />
        ) : tab === "urlhaus" ? (
          <DataTable
            rows={data.urlhaus.entries ?? []}
            columns={[
              { key: "u", label: "URL", render: (e) => <button type="button" className="mono link max-w-[360px] truncate text-left text-[12px]" disabled={pending} onClick={() => void start(e.url, "QUICK", { type: "URL" })}>{e.url}</button> },
              { key: "s", label: "Status", render: (e) => <Chip tone={e.url_status === "online" ? "err" : "neutral"}>{e.url_status ?? "?"}</Chip> },
              { key: "t", label: "Threat", render: (e) => <span className="text-fg-1">{e.threat ?? ""}</span> },
              { key: "h", label: "Host", render: (e) => <Mono className="text-fg-3">{e.host ?? ""}</Mono> },
              { key: "d", label: "Added", render: (e) => <Time iso={e.date_added ?? undefined} className="text-xs text-fg-4" />, sort: (e) => e.date_added ?? "" },
            ]}
          />
        ) : tab === "bazaar" ? (
          <DataTable
            rows={data.bazaar.entries ?? []}
            columns={[
              { key: "h", label: "SHA-256", render: (e) => <button type="button" className="mono link text-[11px]" disabled={pending} onClick={() => void start(e.sha256, "QUICK", { type: "SHA256" })}>{e.sha256.slice(0, 20)}…</button> },
              { key: "n", label: "File name", render: (e) => <span className="text-fg-1">{e.fileName || "—"}</span> },
              { key: "t", label: "Type", render: (e) => <Chip>{e.fileType}</Chip> },
              { key: "s", label: "Signature", render: (e) => <span className="text-xs text-fg-3">{e.signature || ""}</span> },
              { key: "g", label: "Tags", render: (e) => <span className="flex flex-wrap gap-1">{e.tags.slice(0, 3).map((t) => <Chip key={t} tone="warn">{t}</Chip>)}</span> },
              { key: "f", label: "First seen", render: (e) => <Mono className="text-xs text-fg-4">{e.firstSeen}</Mono>, sort: (e) => e.firstSeen },
            ]}
          />
        ) : (
          <DataTable
            rows={data.feodo.entries ?? []}
            columns={[
              { key: "i", label: "IP", render: (e) => <button type="button" className="mono link text-[12px]" disabled={pending} onClick={() => void start(e.ip_address, "QUICK", { type: "IPV4" })}>{e.ip_address}</button>, sort: (e) => e.ip_address },
              { key: "p", label: "Port", render: (e) => <Mono>{e.port ?? ""}</Mono> },
              { key: "s", label: "Status", render: (e) => <Chip tone={e.status === "online" ? "err" : "neutral"}>{e.status ?? "?"}</Chip> },
              { key: "m", label: "Malware", render: (e) => <span className="text-fg-1">{e.malware ?? ""}</span> },
              { key: "c", label: "Country", render: (e) => <span className="text-xs text-fg-3">{e.country ?? ""}</span> },
              { key: "f", label: "First seen", render: (e) => <Mono className="text-xs text-fg-4">{e.first_seen ?? ""}</Mono> },
            ]}
          />
        )}
      </section>
    </div>
  );
}
