// CVSS vector string parsing into labelled metrics (v2.0, v3.0/3.1, v4.0).

export interface CvssMetric {
  key: string;
  metric: string;
  value: string;
  raw: string;
}

export interface ParsedCvss {
  version: string;
  metrics: CvssMetric[];
}

type Table = Record<string, { name: string; values: Record<string, string> }>;

const V3: Table = {
  AV: { name: "Attack vector", values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  AC: { name: "Attack complexity", values: { L: "Low", H: "High" } },
  PR: { name: "Privileges required", values: { N: "None", L: "Low", H: "High" } },
  UI: { name: "User interaction", values: { N: "None", R: "Required" } },
  S: { name: "Scope", values: { U: "Unchanged", C: "Changed" } },
  C: { name: "Confidentiality", values: { N: "None", L: "Low", H: "High" } },
  I: { name: "Integrity", values: { N: "None", L: "Low", H: "High" } },
  A: { name: "Availability", values: { N: "None", L: "Low", H: "High" } },
  E: { name: "Exploit maturity", values: { X: "Not defined", U: "Unproven", P: "Proof-of-concept", F: "Functional", H: "High" } },
  RL: { name: "Remediation level", values: { X: "Not defined", O: "Official fix", T: "Temporary fix", W: "Workaround", U: "Unavailable" } },
  RC: { name: "Report confidence", values: { X: "Not defined", U: "Unknown", R: "Reasonable", C: "Confirmed" } },
};

const V4: Table = {
  AV: { name: "Attack vector", values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  AC: { name: "Attack complexity", values: { L: "Low", H: "High" } },
  AT: { name: "Attack requirements", values: { N: "None", P: "Present" } },
  PR: { name: "Privileges required", values: { N: "None", L: "Low", H: "High" } },
  UI: { name: "User interaction", values: { N: "None", P: "Passive", A: "Active" } },
  VC: { name: "Vulnerable system confidentiality", values: { H: "High", L: "Low", N: "None" } },
  VI: { name: "Vulnerable system integrity", values: { H: "High", L: "Low", N: "None" } },
  VA: { name: "Vulnerable system availability", values: { H: "High", L: "Low", N: "None" } },
  SC: { name: "Subsequent system confidentiality", values: { H: "High", L: "Low", N: "None" } },
  SI: { name: "Subsequent system integrity", values: { H: "High", L: "Low", N: "None", S: "Safety" } },
  SA: { name: "Subsequent system availability", values: { H: "High", L: "Low", N: "None", S: "Safety" } },
  E: { name: "Exploit maturity", values: { X: "Not defined", A: "Attacked", P: "Proof-of-concept", U: "Unreported" } },
};

const V2: Table = {
  AV: { name: "Access vector", values: { N: "Network", A: "Adjacent network", L: "Local" } },
  AC: { name: "Access complexity", values: { L: "Low", M: "Medium", H: "High" } },
  Au: { name: "Authentication", values: { N: "None", S: "Single", M: "Multiple" } },
  C: { name: "Confidentiality", values: { N: "None", P: "Partial", C: "Complete" } },
  I: { name: "Integrity", values: { N: "None", P: "Partial", C: "Complete" } },
  A: { name: "Availability", values: { N: "None", P: "Partial", C: "Complete" } },
};

export function parseCvssVector(vector: string | undefined | null): ParsedCvss | null {
  if (!vector) return null;
  const parts = vector.trim().split("/");
  let version = "2.0";
  let table = V2;
  if (parts[0].startsWith("CVSS:")) {
    version = parts.shift()!.slice(5);
    table = version.startsWith("4") ? V4 : V3;
  }
  const metrics: CvssMetric[] = [];
  for (const part of parts) {
    const [key, value] = part.split(":");
    if (!key || value === undefined) continue;
    const def = table[key];
    if (!def) continue;
    metrics.push({ key, metric: def.name, value: def.values[value] ?? value, raw: value });
  }
  return metrics.length ? { version, metrics } : null;
}

export function severityFromScore(score: number, version = "3.1"): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" {
  if (version.startsWith("2")) return score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";
  if (score === 0) return "NONE";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}
