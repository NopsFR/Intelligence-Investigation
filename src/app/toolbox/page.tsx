"use client";

import { useState } from "react";

type Tool = "dns" | "headers" | "tls" | "url-parse" | "rdap" | "crtsh";

const TOOLS: { id: Tool; label: string; category: string }[] = [
  { id: "dns", label: "DNS lookup", category: "Network" },
  { id: "rdap", label: "RDAP lookup", category: "Domain" },
  { id: "crtsh", label: "Certificate transparency", category: "Domain" },
  { id: "tls", label: "TLS inspection", category: "Web" },
  { id: "headers", label: "Security headers", category: "Web" },
  { id: "url-parse", label: "URL parser", category: "Web" },
];

export default function ToolboxPage() {
  const [active, setActive] = useState<Tool>("dns");

  return (
    <div className="mx-auto max-w-[1200px] px-4 md:px-6 py-10 space-y-6">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-1">
          Security utilities
        </p>
        <h1 className="text-2xl font-medium text-[var(--nops-text)]">Toolbox</h1>
      </div>

      <div className="flex flex-wrap gap-2">
        {TOOLS.map((t) => (
          <button
            key={t.id}
            onClick={() => setActive(t.id)}
            className={`rounded border px-3 py-1.5 font-mono text-xs uppercase tracking-wider transition-colors ${
              active === t.id
                ? "border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)] text-[var(--nops-text)]"
                : "border-transparent text-[var(--nops-text-faint)] hover:text-[var(--nops-text-dim)]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] p-5">
        {active === "dns" && <DnsTool />}
        {active === "headers" && <HeadersTool />}
        {active === "tls" && <TlsTool />}
        {active === "url-parse" && <UrlParseTool />}
        {active === "rdap" && <RdapTool />}
        {active === "crtsh" && <CrtShTool />}
      </div>
    </div>
  );
}

function useToolRunner<T>() {
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function run(payload: Record<string, unknown>) {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/toolbox", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Request failed");
      } else {
        setResult(data.result);
      }
    } catch {
      setError("Could not reach the toolbox service.");
    } finally {
      setLoading(false);
    }
  }

  return { result, error, loading, run };
}

function ResultPanel({ error, loading, result }: { error: string | null; loading: boolean; result: unknown }) {
  if (loading) return <p className="font-mono text-xs text-[var(--nops-text-faint)]">Running…</p>;
  if (error) return <p className="font-mono text-xs text-[var(--nops-red)]">{error}</p>;
  if (result === null) return null;
  return (
    <pre className="max-h-96 overflow-auto rounded bg-[var(--nops-bg)] p-3 font-mono text-[11px] text-[var(--nops-text-dim)]">
      {JSON.stringify(result, null, 2)}
    </pre>
  );
}

function ToolInput({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-wrap gap-2 mb-4">{children}</div>;
}

const inputClass =
  "rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-3 py-2 font-mono text-sm text-[var(--nops-text)] outline-none focus:border-[var(--nops-red-dim)]";
const buttonClass =
  "rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-4 py-2 font-mono text-xs uppercase tracking-wider text-[var(--nops-text)] hover:border-[var(--nops-text-faint)]";

function DnsTool() {
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const { result, error, loading, run } = useToolRunner();
  return (
    <div>
      <ToolInput>
        <input className={inputClass} placeholder="example.com" value={name} onChange={(e) => setName(e.target.value)} />
        <select className={inputClass} value={type} onChange={(e) => setType(e.target.value)}>
          {["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"].map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        <button className={buttonClass} onClick={() => run({ tool: "dns", name, recordType: type })} disabled={!name || loading}>
          Resolve
        </button>
      </ToolInput>
      <ResultPanel error={error} loading={loading} result={result} />
    </div>
  );
}

function HeadersTool() {
  const [url, setUrl] = useState("");
  const { result, error, loading, run } = useToolRunner();
  return (
    <div>
      <ToolInput>
        <input className={`${inputClass} flex-1 min-w-[240px]`} placeholder="https://example.com" value={url} onChange={(e) => setUrl(e.target.value)} />
        <button className={buttonClass} onClick={() => run({ tool: "headers", url })} disabled={!url || loading}>
          Inspect
        </button>
      </ToolInput>
      <ResultPanel error={error} loading={loading} result={result} />
    </div>
  );
}

function TlsTool() {
  const [hostname, setHostname] = useState("");
  const { result, error, loading, run } = useToolRunner();
  return (
    <div>
      <ToolInput>
        <input className={inputClass} placeholder="example.com" value={hostname} onChange={(e) => setHostname(e.target.value)} />
        <button className={buttonClass} onClick={() => run({ tool: "tls", hostname })} disabled={!hostname || loading}>
          Inspect certificate
        </button>
      </ToolInput>
      <ResultPanel error={error} loading={loading} result={result} />
    </div>
  );
}

function UrlParseTool() {
  const [url, setUrl] = useState("");
  const { result, error, loading, run } = useToolRunner();
  return (
    <div>
      <ToolInput>
        <input className={`${inputClass} flex-1 min-w-[240px]`} placeholder="https://example.com/path?x=1" value={url} onChange={(e) => setUrl(e.target.value)} />
        <button className={buttonClass} onClick={() => run({ tool: "url-parse", url })} disabled={!url || loading}>
          Parse
        </button>
      </ToolInput>
      <ResultPanel error={error} loading={loading} result={result} />
    </div>
  );
}

function RdapTool() {
  const [value, setValue] = useState("");
  const [type, setType] = useState<"DOMAIN" | "IPV4" | "IPV6" | "ASN">("DOMAIN");
  const { result, error, loading, run } = useToolRunner();
  return (
    <div>
      <ToolInput>
        <select className={inputClass} value={type} onChange={(e) => setType(e.target.value as typeof type)}>
          <option value="DOMAIN">Domain</option>
          <option value="IPV4">IPv4</option>
          <option value="IPV6">IPv6</option>
          <option value="ASN">ASN</option>
        </select>
        <input className={inputClass} placeholder="example.com" value={value} onChange={(e) => setValue(e.target.value)} />
        <button className={buttonClass} onClick={() => run({ tool: "rdap", value, type })} disabled={!value || loading}>
          Lookup
        </button>
      </ToolInput>
      <ResultPanel error={error} loading={loading} result={result} />
    </div>
  );
}

function CrtShTool() {
  const [domain, setDomain] = useState("");
  const { result, error, loading, run } = useToolRunner();
  return (
    <div>
      <ToolInput>
        <input className={inputClass} placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <button className={buttonClass} onClick={() => run({ tool: "crtsh", domain })} disabled={!domain || loading}>
          Search
        </button>
      </ToolInput>
      <ResultPanel error={error} loading={loading} result={result} />
    </div>
  );
}
