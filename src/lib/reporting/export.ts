import type { Investigation } from "@/types/investigation";
import { PROVIDER_STATUS_LABELS } from "@/types/provider";

export function toReportJson(investigation: Investigation): string {
  return JSON.stringify(investigation, null, 2);
}

export function toReportMarkdown(investigation: Investigation): string {
  const lines: string[] = [];
  lines.push(`# Investigation report — ${investigation.observable}`);
  lines.push("");
  lines.push(`- **Observable type:** ${investigation.observableType}`);
  lines.push(`- **Mode:** ${investigation.mode}`);
  lines.push(`- **Status:** ${investigation.status}`);
  lines.push(`- **Created:** ${investigation.createdAt}`);
  lines.push(`- **Summary:** ${investigation.summary}`);
  lines.push("");

  lines.push("## Findings");
  if (investigation.findings.length === 0) {
    lines.push("No findings were generated for this investigation.");
  } else {
    for (const f of investigation.findings) {
      lines.push(`### [${f.severity}] ${f.title}`);
      lines.push(f.description);
      lines.push(`- **Evidence:** ${f.evidence}`);
      lines.push(`- **Source:** ${f.source}`);
      lines.push(`- **Observed:** ${f.observedAt}`);
      lines.push("");
    }
  }

  lines.push("## Provider results");
  for (const p of investigation.providerResults) {
    lines.push(`### ${p.provider} — ${PROVIDER_STATUS_LABELS[p.status]}`);
    if (p.normalized?.summary) lines.push(p.normalized.summary);
    if (p.errorMessage) lines.push(`Error: ${p.errorMessage}`);
    lines.push(`- Latency: ${p.latencyMs}ms`);
    lines.push(`- Retrieved: ${p.retrievedAt}`);
    lines.push("");
  }

  lines.push("## Infrastructure relationships");
  if (investigation.relationships.length === 0) {
    lines.push("No evidence-backed relationships were discovered.");
  } else {
    for (const r of investigation.relationships) {
      lines.push(`- \`${r.sourceNode}\` → \`${r.targetNode}\` (${r.relationType}) — source: ${r.sourceProvider}`);
    }
  }
  lines.push("");

  lines.push("## Methodology and limitations");
  lines.push(
    "This investigation represents information returned by the configured providers at the time of investigation. " +
      "Absence of an indicator does not prove absence of malicious activity. Provider availability, rate limits, " +
      "coverage, and data freshness may affect these results."
  );

  return lines.join("\n");
}

export function toReportCsv(investigation: Investigation): string {
  const header = ["severity", "category", "title", "description", "evidence", "source", "observedAt"];
  const rows = investigation.findings.map((f) => [
    f.severity,
    f.category,
    f.title,
    f.description,
    f.evidence,
    f.source,
    f.observedAt,
  ]);

  const escape = (value: string) => `"${value.replace(/"/g, '""')}"`;
  return [header, ...rows].map((row) => row.map((cell) => escape(String(cell))).join(",")).join("\n");
}

export function downloadFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
