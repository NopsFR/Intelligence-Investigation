"use client";

import { Printer, FileJson, FileText, FileSpreadsheet } from "lucide-react";
import type { Investigation } from "@/types/investigation";
import { toReportCsv, toReportJson, toReportMarkdown, downloadFile } from "@/lib/reporting/export";

export function ExportBar({ investigation }: { investigation: Investigation }) {
  const base = investigation.normalizedObservable.replace(/[^a-z0-9.-]/gi, "_");

  return (
    <div className="no-print flex flex-wrap gap-2">
      <ExportButton
        icon={<FileJson size={13} />}
        label="JSON"
        onClick={() => downloadFile(`${base}.json`, toReportJson(investigation), "application/json")}
      />
      <ExportButton
        icon={<FileText size={13} />}
        label="Markdown"
        onClick={() => downloadFile(`${base}.md`, toReportMarkdown(investigation), "text/markdown")}
      />
      <ExportButton
        icon={<FileSpreadsheet size={13} />}
        label="CSV"
        onClick={() => downloadFile(`${base}-findings.csv`, toReportCsv(investigation), "text/csv")}
      />
      <ExportButton icon={<Printer size={13} />} label="Print / PDF" onClick={() => window.print()} />
    </div>
  );
}

function ExportButton({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-2.5 py-1.5 font-mono text-[11px] uppercase tracking-wider text-[var(--nops-text-dim)] hover:text-[var(--nops-text)] hover:border-[var(--nops-text-faint)] transition-colors"
    >
      {icon}
      {label}
    </button>
  );
}
