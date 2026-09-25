import type { ObservableType, Severity } from "@/lib/core/types";
import { API_CATEGORY_LABEL, apiInfo, matchCapabilities, type ApiCategory } from "./apis";
import { ParseError, entropy, entropyProfile } from "./bytes";
import { parseElf, type ElfAnalysis } from "./elf";
import { fileHashes, type FileHashes } from "./hash";
import { parseMacho, type MachoAnalysis } from "./macho";
import { identify, type FileType } from "./magic";
import { authenticodeDigest, parsePe, type PeAnalysis } from "./pe";
import { extractStrings, indicatorsFromStrings, type ExtractedString } from "./strings";

// Static file analysis. Runs in a browser worker (or Node for tests); the
// file never leaves the machine. Findings are evidence-backed observations
// with the structure or bytes that support them — not verdicts.

export const MAX_ANALYSIS_BYTES = 100 * 1024 * 1024;

export type FindingBasis = "structure" | "capability" | "heuristic" | "signature";

export interface FileFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: string[];
  attack?: string[];
  basis: FindingBasis;
}

export interface CapabilitySummary {
  id: string;
  title: string;
  attack: string[];
  severity: Severity;
  matched: string[];
  explanation: string;
}

export interface FileReport {
  name: string;
  size: number;
  type: FileType;
  hashes: FileHashes;
  entropy: number;
  profile: { offset: number; size: number; entropy: number }[];
  strings: ExtractedString[];
  stringsTruncated: boolean;
  indicators: { value: string; type: ObservableType; occurrences: number; offsets: number[] }[];
  pe?: PeAnalysis;
  elf?: ElfAnalysis;
  macho?: MachoAnalysis;
  parseError?: string;
  apiCategories: { category: ApiCategory; label: string; functions: string[] }[];
  capabilities: CapabilitySummary[];
  embedded: { offset: number; kind: string }[];
  findings: FileFinding[];
  durationMs: number;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const toSeverity = (s: "info" | "low" | "medium" | "high"): Severity => (s === "high" ? "HIGH" : s === "medium" ? "MEDIUM" : s === "low" ? "LOW" : "INFO");

const EXTENSION_FAMILIES: Record<string, string[]> = {
  pe: ["exe", "dll", "sys", "scr", "cpl", "ocx", "efi", "com", "drv", "mui", "ax", "node"],
  elf: ["", "so", "elf", "bin", "o", "ko", "out"],
  pdf: ["pdf"],
  zip: ["zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "ods", "xpi", "whl", "nupkg", "vsix", "ipa", "epub", "msix", "appx"],
  ole: ["doc", "xls", "ppt", "msi", "msg", "pub", "vsd"],
  png: ["png"],
  jpeg: ["jpg", "jpeg"],
  gif: ["gif"],
  rtf: ["rtf", "doc"],
};
const DOCUMENT_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip", "rar", "rtf", "csv"];
const EXECUTABLE_EXTENSIONS = ["exe", "scr", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "ps1", "hta", "lnk", "msi", "pif", "cpl", "wsf", "iso", "img", "dll"];

/** Signatures of embedded content worth pointing at, searched across the file. */
const EMBEDDED_MARKERS: { kind: string; needle: string }[] = [
  { kind: "Windows executable (DOS stub)", needle: "This program cannot be run in DOS mode" },
  { kind: "ELF executable", needle: "\x7fELF" },
  { kind: "PowerShell encoded command", needle: "-EncodedCommand" },
  { kind: "ZIP local file header", needle: "PK\x03\x04" },
];

function findAll(bytes: Uint8Array, needle: string, from = 0, limit = 32): number[] {
  const n = [...needle].map((c) => c.charCodeAt(0));
  const out: number[] = [];
  const first = n[0];
  for (let i = from; i <= bytes.length - n.length && out.length < limit; i++) {
    if (bytes[i] !== first) continue;
    let ok = true;
    for (let j = 1; j < n.length; j++)
      if (bytes[i + j] !== n[j]) {
        ok = false;
        break;
      }
    if (ok) out.push(i);
  }
  return out;
}

export async function analyzeFile(bytes: Uint8Array, name: string): Promise<FileReport> {
  const started = Date.now();
  if (bytes.length > MAX_ANALYSIS_BYTES) throw new ParseError(`File is larger than ${MAX_ANALYSIS_BYTES / 1024 / 1024} MB`);
  const type = identify(bytes);
  const hashes = await fileHashes(bytes);
  const strings = extractStrings(bytes, 5, 20_000);
  const report: FileReport = {
    name,
    size: bytes.length,
    type,
    hashes,
    entropy: entropy(bytes),
    profile: entropyProfile(bytes, 160),
    strings,
    stringsTruncated: strings.length >= 20_000,
    indicators: indicatorsFromStrings(strings).slice(0, 500),
    apiCategories: [],
    capabilities: [],
    embedded: [],
    findings: [],
    durationMs: 0,
  };

  try {
    if (type.analyzer === "pe") {
      report.pe = parsePe(bytes);
      if (report.pe.signature.present && report.pe.signature.signedDigest) {
        const digest = await authenticodeDigest(bytes, report.pe);
        if (digest) {
          report.pe.signature.imageDigest = digest;
          report.pe.signature.digestMatches = digest === report.pe.signature.signedDigest;
        }
      }
    } else if (type.analyzer === "elf") report.elf = parseElf(bytes);
    else if (type.analyzer === "macho") report.macho = parseMacho(bytes);
  } catch (err) {
    report.parseError = err instanceof Error ? err.message : String(err);
  }

  // Embedded content (beyond the file's own header).
  for (const m of EMBEDDED_MARKERS) {
    const skip = m.kind.startsWith("Windows") && type.analyzer === "pe" ? 0x200 : m.kind.startsWith("ELF") && type.analyzer === "elf" ? 4 : m.kind.startsWith("ZIP") && type.id === "zip" ? 4 : 0;
    const hits = findAll(bytes, m.needle, Math.max(1, skip), 16);
    for (const offset of hits) report.embedded.push({ offset, kind: m.kind });
  }

  const imported = new Set<string>();
  if (report.pe) for (const imp of report.pe.imports) for (const f of imp.functions) if (f.name) imported.add(f.name);
  if (report.elf) for (const s of report.elf.imports) imported.add(s.name);
  if (report.macho) for (const sl of report.macho.slices) for (const s of sl.imports) imported.add(s.replace(/^_/, ""));

  const byCategory = new Map<ApiCategory, string[]>();
  for (const fn of imported) {
    const info = apiInfo(fn);
    if (!info) continue;
    const list = byCategory.get(info.category) ?? [];
    list.push(fn);
    byCategory.set(info.category, list);
  }
  report.apiCategories = [...byCategory.entries()].map(([category, functions]) => ({ category, label: API_CATEGORY_LABEL[category], functions: functions.sort() }));
  if (report.pe) {
    report.capabilities = matchCapabilities(imported).map((h) => ({
      id: h.rule.id,
      title: h.rule.title,
      attack: h.rule.attack,
      // The MSVC C runtime imports IsDebuggerPresent in almost every program.
      severity: h.rule.id === "cap.debugger-detection" && h.matched.length === 1 && h.matched[0] === "IsDebuggerPresent" ? "INFO" : toSeverity(h.rule.severity),
      matched: h.matched,
      explanation: h.rule.explanation,
    }));
  }

  report.findings = [...generalFindings(report, name), ...(report.pe ? peFindings(report.pe, report, name) : []), ...(report.elf ? elfFindings(report.elf, report, imported) : []), ...(report.macho ? machoFindings(report.macho) : [])].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  report.durationMs = Date.now() - started;
  return report;
}

function generalFindings(report: FileReport, name: string): FileFinding[] {
  const out: FileFinding[] = [];
  const lower = name.toLowerCase();
  const parts = lower.split(".");
  const ext = parts.length > 1 ? parts[parts.length - 1] : "";

  if (/[‮‭⁦-⁩]/.test(name)) {
    out.push({ id: "file.rtlo", severity: "HIGH", title: "File name contains a bidirectional override character", detail: "Right-to-left override characters make a name display differently from its real extension (for example 'invoice‮xcod.exe').", evidence: [`Name code points: ${[...name].filter((c) => /[‪-‮⁦-⁩]/.test(c)).map((c) => `U+${c.charCodeAt(0).toString(16).toUpperCase()}`).join(", ")}`], attack: ["T1036.002"], basis: "heuristic" });
  }
  if (parts.length > 2 && DOCUMENT_EXTENSIONS.includes(parts[parts.length - 2]) && EXECUTABLE_EXTENSIONS.includes(ext)) {
    out.push({ id: "file.double-extension", severity: "MEDIUM", title: "Double file extension", detail: `The name ends in .${parts[parts.length - 2]}.${ext}: a document-looking name on an executable type. Windows hides known extensions by default.`, evidence: [name], attack: ["T1036.007"], basis: "heuristic" });
  }
  const detectedFamily = report.type.analyzer === "pe" ? "pe" : report.type.analyzer === "elf" ? "elf" : report.type.id in EXTENSION_FAMILIES ? report.type.id : null;
  if (detectedFamily && ext && !EXTENSION_FAMILIES[detectedFamily].includes(ext) && (report.type.family === "executable" || DOCUMENT_EXTENSIONS.includes(ext))) {
    const severity: Severity = report.type.family === "executable" && DOCUMENT_EXTENSIONS.includes(ext) ? "HIGH" : "LOW";
    out.push({ id: "file.extension-mismatch", severity, title: `Content is ${report.type.label}, name says .${ext}`, detail: "The file type was identified from its content (magic bytes), not its name. A mismatch can be innocent (renamed downloads) or an attempt to disguise an executable.", evidence: [`Detected: ${report.type.label} (${report.type.mime})`, `Extension: .${ext}`], attack: severity === "HIGH" ? ["T1036.008"] : undefined, basis: "structure" });
  }

  const compressedFamilies = ["archive", "image", "media"];
  if (report.size > 4096 && report.entropy > 7.5 && !compressedFamilies.includes(report.type.family) && report.type.analyzer !== "pe" && report.type.analyzer !== "elf" && report.type.analyzer !== "macho") {
    out.push({ id: "file.high-entropy", severity: report.type.id === "data" ? "LOW" : "INFO", title: "Content is compressed or encrypted", detail: `Overall entropy is ${report.entropy.toFixed(2)} bits/byte (8.00 is random). The format is not one that is normally compressed.`, evidence: [`Entropy ${report.entropy.toFixed(3)}`, `Type ${report.type.label}`], basis: "heuristic" });
  }

  // PE payloads already reported through the overlay or resources are not repeated here.
  const reported = [
    ...(report.pe?.overlay ? [[report.pe.overlay.offset, report.pe.overlay.offset + report.pe.overlay.size]] : []),
    ...(report.pe?.resources.filter((r) => r.detected?.family === "executable" && r.offset !== null).map((r) => [r.offset!, r.offset! + r.size]) ?? []),
  ];
  const pes = report.embedded.filter((e) => e.kind.startsWith("Windows") && !reported.some(([a, b]) => e.offset >= a && e.offset < b));
  if (pes.length) {
    out.push({ id: "file.embedded-pe", severity: report.type.analyzer === "pe" || report.type.family === "archive" ? "MEDIUM" : "HIGH", title: "Embedded Windows executable", detail: "The DOS stub text of a second PE file appears inside this file. Droppers and installers carry payloads this way.", evidence: pes.slice(0, 8).map((e) => `DOS stub at offset 0x${e.offset.toString(16)}`), attack: report.type.analyzer === "pe" ? ["T1027.009"] : undefined, basis: "structure" });
  }
  const enc = report.embedded.filter((e) => e.kind.startsWith("PowerShell"));
  const commands = report.strings.filter((s) => s.tags.includes("command"));
  if (enc.length || commands.length) {
    out.push({ id: "file.command-strings", severity: enc.length ? "MEDIUM" : "LOW", title: "Command-line strings", detail: "Shell or PowerShell command text is present. Text alone does not prove it executes; check where it is referenced.", evidence: [...enc.slice(0, 3).map((e) => `-EncodedCommand at 0x${e.offset.toString(16)}`), ...commands.slice(0, 6).map((s) => `0x${s.offset.toString(16)}: ${s.value.slice(0, 140)}`)], attack: ["T1059"], basis: "heuristic" });
  }
  const runKeys = report.strings.filter((s) => /\\CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)\b/i.test(s.value) || /\\Winlogon\\(Shell|Userinit)/i.test(s.value));
  if (runKeys.length) {
    out.push({ id: "file.autostart-strings", severity: "LOW", title: "Autostart registry locations referenced", detail: "Run keys and Winlogon values start programs at logon.", evidence: runKeys.slice(0, 6).map((s) => `0x${s.offset.toString(16)}: ${s.value.slice(0, 160)}`), attack: ["T1547.001"], basis: "heuristic" });
  }
  const shadow = report.strings.filter((s) => /vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+.*recoveryenabled\s+no|wbadmin\s+delete\s+catalog/i.test(s.value));
  if (shadow.length) {
    out.push({ id: "file.recovery-inhibition", severity: "HIGH", title: "Commands that delete backups or disable recovery", detail: "Shadow-copy deletion and boot-recovery changes are strongly associated with ransomware preparing for impact.", evidence: shadow.slice(0, 6).map((s) => `0x${s.offset.toString(16)}: ${s.value.slice(0, 160)}`), attack: ["T1490"], basis: "heuristic" });
  }
  const paymentVocabulary = report.strings.some((s) => /bitcoin|\bbtc\b|wallet|monero|\bxmr\b|ransom|decrypt|payment/i.test(s.value));
  const wallets = paymentVocabulary ? report.strings.filter((s) => /\b(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b/.test(s.value)) : [];
  if (wallets.length) {
    out.push({ id: "file.crypto-wallet", severity: "LOW", title: "Cryptocurrency wallet address pattern", detail: "Address-shaped strings near payment vocabulary. Validate the checksum before relying on it.", evidence: wallets.slice(0, 4).map((s) => `0x${s.offset.toString(16)}: ${s.value.slice(0, 120)}`), basis: "heuristic" });
  }
  if (report.indicators.length) {
    out.push({ id: "file.network-indicators", severity: "INFO", title: `${report.indicators.length} network indicator${report.indicators.length === 1 ? "" : "s"} in strings`, detail: "Domains, IPs, URLs and email addresses found in the file's strings. Many are benign (certificate authorities, schemas, documentation links).", evidence: report.indicators.slice(0, 8).map((i) => `${i.type} ${i.value}`), basis: "structure" });
  }
  if (report.parseError) {
    out.push({ id: "file.parse-error", severity: "LOW", title: `${report.type.label} structure could not be fully parsed`, detail: "Malformed headers can be corruption, truncation, or deliberate anti-analysis. The hashes, strings and entropy above are still valid.", evidence: [report.parseError], basis: "structure" });
  }
  return out;
}

function peFindings(pe: PeAnalysis, report: FileReport, name: string): FileFinding[] {
  const out: FileFinding[] = [];
  const hexa = (n: number) => `0x${n.toString(16)}`;

  const packers = [...new Set(pe.sections.filter((s) => s.packer).map((s) => s.packer!))];
  if (packers.length) out.push({ id: "pe.packer", severity: "MEDIUM", title: `Packer section names: ${packers.join(", ")}`, detail: "Section names match those written by known packers or protectors. Packing hides the real code from static analysis; unpack (or analyse dynamically in a sandbox) before judging capability.", evidence: pe.sections.filter((s) => s.packer).map((s) => `${s.name} → ${s.packer} (entropy ${s.entropy.toFixed(2)})`), attack: ["T1027.002"], basis: "structure" });

  const wx = pe.sections.filter((s) => s.writable && s.executable);
  if (wx.length) out.push({ id: "pe.wx-section", severity: "MEDIUM", title: "Writable and executable section", detail: "Code that can be modified at run time is typical of packers and self-modifying loaders; compilers do not normally emit it.", evidence: wx.map((s) => `${s.name}: ${s.flags.join(" | ")}`), basis: "structure" });

  const hot = pe.sections.filter((s) => s.executable && s.rawSize > 1024 && s.entropy > 7.0);
  if (hot.length) out.push({ id: "pe.high-entropy-code", severity: "MEDIUM", title: "High-entropy executable section", detail: "Compiled machine code usually measures 5.5–6.8 bits/byte. Above 7.0 the section is most likely compressed or encrypted.", evidence: hot.map((s) => `${s.name}: entropy ${s.entropy.toFixed(3)}, ${s.rawSize} bytes`), attack: ["T1027.002"], basis: "heuristic" });

  if (pe.entryPoint && !pe.isDll) {
    const entry = pe.sections.find((s) => s.name === pe.entrySection);
    if (!pe.entrySection) out.push({ id: "pe.entry-outside", severity: "HIGH", title: "Entry point is outside every section", detail: "The loader will start execution at an address no section maps. This is malformed or deliberately confusing to analysis tools.", evidence: [`AddressOfEntryPoint ${hexa(pe.entryPoint)}`], basis: "structure" });
    else if (entry && !entry.executable) out.push({ id: "pe.entry-non-exec", severity: "MEDIUM", title: `Entry point is in a non-executable section (${entry.name})`, detail: "Execution starts in a section not marked executable — a packer or hand-crafted file trait.", evidence: [`AddressOfEntryPoint ${hexa(pe.entryPoint)} in ${entry.name} (${entry.flags.join(" | ")})`], basis: "structure" });
    else if (entry && pe.sections.length > 2 && entry.index === pe.sections.length - 1 && !pe.isDotNet) out.push({ id: "pe.entry-last-section", severity: "LOW", title: "Entry point is in the last section", detail: "Packers and file infectors commonly append their stub as the final section and point the entry there.", evidence: [`AddressOfEntryPoint ${hexa(pe.entryPoint)} in ${entry.name} (section ${entry.index + 1} of ${pe.sections.length})`], basis: "heuristic" });
  }

  const dynamic = ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"];
  const names = pe.imports.flatMap((i) => i.functions.map((f) => f.name ?? ""));
  if (!pe.isDotNet && pe.importCount > 0 && pe.importCount <= 10 && names.some((n) => dynamic.includes(n))) {
    out.push({ id: "pe.tiny-imports", severity: "MEDIUM", title: `Only ${pe.importCount} imports, including run-time API resolution`, detail: "A program this small in imports that can load libraries and resolve functions itself is hiding its real API use — a hallmark of packed or shellcode-style loaders.", evidence: pe.imports.map((i) => `${i.dll}: ${i.functions.map((f) => f.name ?? `#${f.ordinal}`).join(", ")}`), attack: ["T1027.007"], basis: "heuristic" });
  } else if (!pe.isDotNet && pe.importCount === 0 && !pe.isDll && !pe.isDriver) {
    out.push({ id: "pe.no-imports", severity: "LOW", title: "No import table", detail: "An executable that imports nothing must find every API itself (walking the PEB) — typical of packed code and shellcode loaders.", evidence: ["Import directory empty or absent"], attack: ["T1027.007"], basis: "structure" });
  }

  for (const cap of report.capabilities) {
    out.push({ id: cap.id, severity: cap.severity, title: cap.title, detail: `${cap.explanation} Imports show capability, not behaviour.`, evidence: cap.matched.map((m) => `imports ${m}`), attack: cap.attack, basis: "capability" });
  }

  if (pe.tlsCallbacks.length) out.push({ id: "pe.tls-callbacks", severity: "LOW", title: `${pe.tlsCallbacks.length} TLS callback${pe.tlsCallbacks.length === 1 ? "" : "s"}`, detail: "TLS callbacks run before the entry point. Legitimate runtimes use them; malware uses them to run anti-debugging code before a debugger's first breakpoint.", evidence: pe.tlsCallbacks.map((c) => `${c.va} (${c.section ?? "outside sections"})`), basis: "structure" });

  if (pe.overlay) {
    const exe = pe.overlay.detected.family === "executable";
    out.push({
      id: "pe.overlay",
      severity: exe ? "HIGH" : pe.overlay.entropy > 7.5 && pe.overlay.size > 16_384 ? "LOW" : "INFO",
      title: exe ? `Executable appended after the image (${pe.overlay.detected.label})` : `${pe.overlay.size.toLocaleString()} bytes of overlay data`,
      detail: exe ? "Data after the last section is itself an executable: the file carries a second program the loader ignores." : "Data after the last section is not loaded by Windows. Installers (NSIS, Inno Setup), self-extracting archives and signed-then-appended data use it; so do droppers.",
      evidence: [`Offset ${hexa(pe.overlay.offset)}, ${pe.overlay.size} bytes`, `Entropy ${pe.overlay.entropy.toFixed(3)}`, `Content: ${pe.overlay.detected.label}`],
      attack: exe ? ["T1027.009"] : undefined,
      basis: "structure",
    });
  }

  const payloadResources = pe.resources.filter((r) => r.detected?.family === "executable");
  if (payloadResources.length) out.push({ id: "pe.resource-executable", severity: "MEDIUM", title: "Executable stored as a resource", detail: "A resource contains another executable — the classic dropper layout. Installers and some legitimate tools also embed helpers.", evidence: payloadResources.map((r) => `${r.type}/${r.name} lang ${r.language}: ${r.detected?.label}, ${r.size} bytes`), attack: ["T1027.009"], basis: "structure" });
  const encryptedResources = pe.resources.filter((r) => (r.typeId === 10 || r.typeId === undefined) && r.size > 16_384 && (r.entropy ?? 0) > 7.6 && !r.detected);
  if (encryptedResources.length) out.push({ id: "pe.resource-encrypted", severity: "LOW", title: "Large high-entropy resource", detail: "Opaque, near-random resource data is often an encrypted payload decrypted at run time. Compressed images and archives also look like this.", evidence: encryptedResources.slice(0, 6).map((r) => `${r.type}/${r.name}: ${r.size} bytes, entropy ${r.entropy?.toFixed(3)}`), basis: "heuristic" });

  const sig = pe.signature;
  if (!sig.present) out.push({ id: "pe.unsigned", severity: "INFO", title: "Not Authenticode-signed", detail: "No embedded signature. Much legitimate software is unsigned or catalogue-signed (Windows system files are signed through catalogues, not embedded signatures).", evidence: ["Security directory empty"], basis: "signature" });
  else if (sig.digestMatches === false) out.push({ id: "pe.signature-mismatch", severity: "HIGH", title: "File was modified after it was signed", detail: "The Authenticode digest computed over this file does not match the digest inside its signature. Windows will treat the signature as invalid.", evidence: [`Signed ${sig.digestAlgorithm} ${sig.signedDigest}`, `Computed ${sig.imageDigest}`], basis: "signature" });
  else if (sig.parsed) {
    const signer = sig.signer?.subject.cn ?? sig.signer?.subject.o ?? "unknown signer";
    out.push({ id: "pe.signed", severity: "INFO", title: `Signed: ${signer}`, detail: `The embedded signature parsed and ${sig.digestMatches ? "its digest matches this file" : "its digest could not be checked"}. The certificate chain and signature were not verified — trust decisions need a Windows trust store or signtool.`, evidence: [`Issuer: ${sig.signer?.issuer.text ?? "?"}`, `Digest ${sig.digestAlgorithm}${sig.digestMatches ? " matches" : ""}`, ...(sig.signingTime ? [`Timestamp ${sig.signingTime}`] : ["No countersignature timestamp"])], basis: "signature" });
    const exp = sig.signer?.notAfter;
    if (exp && Date.parse(exp) < Date.now() && !sig.signingTime) out.push({ id: "pe.signature-expired", severity: "LOW", title: "Signing certificate expired and no timestamp", detail: "Without a trusted timestamp, the signature stops validating once the certificate expires.", evidence: [`notAfter ${exp}`], basis: "signature" });
  } else out.push({ id: "pe.signature-malformed", severity: "LOW", title: "Signature present but malformed", detail: "A certificate table exists but could not be parsed as Authenticode.", evidence: [sig.error ?? "parse failed"], basis: "signature" });

  const company = pe.version.CompanyName ?? "";
  if (/microsoft/i.test(company) && (!sig.present || (sig.signer && !/microsoft/i.test(sig.signer.subject.text)))) {
    out.push({ id: "pe.version-masquerade", severity: "MEDIUM", title: "Claims to be Microsoft but is not Microsoft-signed", detail: "The version resource names Microsoft, but the embedded signature is absent or belongs to someone else. Malware copies version info from system binaries to blend in. (Some Microsoft files are catalogue-signed, so check the path the file came from.)", evidence: [`CompanyName: ${company}`, `Signature: ${sig.present ? sig.signer?.subject.text ?? "unparsed" : "none"}`], attack: ["T1036.005"], basis: "heuristic" });
  }
  const original = pe.version.OriginalFilename;
  if (original && name && original.toLowerCase() !== name.toLowerCase() && !original.toLowerCase().replace(/\.mui$/, "").startsWith(name.toLowerCase().replace(/\.[^.]+$/, ""))) {
    out.push({ id: "pe.renamed", severity: "INFO", title: "Renamed from its original file name", detail: "The version resource records a different original name. Renaming is normal for downloads; renamed system tools (e.g. a copy of rundll32) are a detection opportunity.", evidence: [`OriginalFilename: ${original}`, `Current name: ${name}`], attack: ["T1036.003"], basis: "structure" });
  }

  const now = Date.now() / 1000;
  if (!pe.reproducible && pe.timestamp) {
    if (pe.timestamp > now + 86_400) out.push({ id: "pe.timestamp-future", severity: "LOW", title: "Compile timestamp is in the future", detail: "The linker timestamp is after today. It was set by hand or by a tool (reproducible builds store a hash here, but those carry a REPRO debug entry, which this file does not).", evidence: [`TimeDateStamp ${pe.timestampIso}`], basis: "structure" });
    else if (pe.timestamp < 631_152_000) out.push({ id: "pe.timestamp-old", severity: "INFO", title: "Compile timestamp is before 1990", detail: "Delphi binaries famously carry 1992; other tools zero or forge it.", evidence: [`TimeDateStamp ${pe.timestampIso}`], basis: "structure" });
  }
  if (pe.rich && !pe.rich.checksumValid) out.push({ id: "pe.rich-tampered", severity: "LOW", title: "Rich header checksum does not match", detail: "The linker writes a checksum over the DOS header and the Rich entries. A mismatch means the header was edited after linking — seen in false-flag operations that transplant another group's toolchain fingerprint.", evidence: [`Key ${pe.rich.key}`, `${pe.rich.entries.length} entries`], basis: "structure" });
  if (pe.checksum.stored && pe.checksum.stored !== pe.checksum.computed) out.push({ id: "pe.checksum", severity: pe.isDriver ? "MEDIUM" : "INFO", title: "Optional-header checksum is wrong", detail: pe.isDriver ? "Drivers must carry a valid checksum; a wrong one means the file changed after linking." : "Only drivers and some system DLLs require a valid checksum; a mismatch shows the file changed after linking (patching, appended data or packing).", evidence: [`Stored ${hexa(pe.checksum.stored)}`, `Computed ${hexa(pe.checksum.computed)}`], basis: "structure" });

  const missing: string[] = [];
  if (!pe.dllCharacteristics.includes("DYNAMIC_BASE")) missing.push("ASLR (DYNAMIC_BASE)");
  if (!pe.dllCharacteristics.includes("NX_COMPAT")) missing.push("DEP (NX_COMPAT)");
  if (pe.is64 && !pe.dllCharacteristics.includes("HIGH_ENTROPY_VA")) missing.push("High-entropy ASLR");
  if (!pe.dllCharacteristics.includes("GUARD_CF")) missing.push("Control Flow Guard");
  if (missing.length && !pe.isDotNet) out.push({ id: "pe.hardening", severity: "INFO", title: "Exploit mitigations not enabled", detail: "Modern toolchains enable these by default; their absence points to an old compiler, a custom toolchain or a stripped/rebuilt header.", evidence: missing, basis: "structure" });
  if (pe.manifest?.executionLevel === "requireAdministrator") out.push({ id: "pe.requires-admin", severity: "INFO", title: "Requests administrator rights", detail: "The manifest asks for elevation (a UAC prompt) at launch.", evidence: [`requestedExecutionLevel: ${pe.manifest.executionLevel}`], basis: "structure" });
  if (pe.isDotNet) out.push({ id: "pe.dotnet", severity: "INFO", title: ".NET assembly", detail: "The code is .NET IL. Import-based capability analysis sees only mscoree; decompile with dnSpy/ILSpy for real behaviour.", evidence: ["CLR runtime header present"], basis: "structure" });
  for (const a of pe.anomalies) out.push({ id: "pe.anomaly", severity: "LOW", title: "Header anomaly", detail: "The structure deviates from what the Windows loader and linkers produce.", evidence: [a], basis: "structure" });
  return out;
}

const LINUX_RULES: { id: string; title: string; severity: Severity; attack: string[]; imports?: string[][]; strings?: RegExp; explanation: string }[] = [
  { id: "elf.reverse-shell", title: "Reverse shell pattern", severity: "MEDIUM", attack: ["T1059.004"], imports: [["socket"], ["connect"], ["dup2", "dup3"], ["execve", "execl", "execlp", "execv", "execvp", "system"]], explanation: "Connects a socket, duplicates it onto stdin/stdout and runs a program: the shape of a reverse shell. Network daemons that spawn helpers share some of it." },
  { id: "elf.ptrace", title: "Uses ptrace", severity: "LOW", attack: ["T1622", "T1055.008"], imports: [["ptrace"]], explanation: "ptrace is used to debug or inject into processes, and by malware to stop itself from being debugged (PTRACE_TRACEME)." },
  { id: "elf.process-vm", title: "Cross-process memory access", severity: "MEDIUM", attack: ["T1055"], imports: [["process_vm_writev", "process_vm_readv"]], explanation: "Reads or writes another process's memory directly." },
  { id: "elf.daemonize", title: "Detaches from the terminal", severity: "INFO", attack: [], imports: [["fork"], ["setsid"]], explanation: "fork + setsid is the standard way to become a daemon. Normal for services; bots do it too." },
  { id: "elf.preload", title: "References the dynamic-linker preload mechanism", severity: "MEDIUM", attack: ["T1574.006"], strings: /\/etc\/ld\.so\.preload|LD_PRELOAD=/, explanation: "Writing /etc/ld.so.preload or setting LD_PRELOAD injects a library into every process: a user-land rootkit technique." },
  { id: "elf.cron", title: "References cron persistence locations", severity: "LOW", attack: ["T1053.003"], strings: /\/etc\/cron(tab|\.d|\.hourly|\.daily)|\/var\/spool\/cron|crontab\s+-/, explanation: "Cron entries run commands on a schedule and survive reboot." },
  { id: "elf.systemd", title: "References service persistence locations", severity: "LOW", attack: ["T1543.002"], strings: /\/etc\/systemd\/system\/|systemctl\s+enable|\/etc\/rc\.local|\/etc\/init\.d\//, explanation: "systemd units, rc.local and init scripts start programs at boot." },
  { id: "elf.ssh-keys", title: "References SSH authorized_keys", severity: "MEDIUM", attack: ["T1098.004"], strings: /\.ssh\/authorized_keys/, explanation: "Adding a key to authorized_keys grants persistent SSH access." },
  { id: "elf.miner", title: "Cryptocurrency-mining strings", severity: "MEDIUM", attack: ["T1496"], strings: /stratum\+tcp:\/\/|xmrig|cryptonight|randomx|--donate-level/i, explanation: "Mining pool protocols and miner options indicate resource hijacking when unexpected." },
  { id: "elf.history-wipe", title: "Clears shell history or logs", severity: "LOW", attack: ["T1070.003"], strings: /history\s+-c|unset\s+HISTFILE|HISTFILE=\/dev\/null|>\s*\/var\/log\/(wtmp|btmp|lastlog|auth\.log)/, explanation: "Removing history and login records hides activity." },
];

function elfFindings(elf: ElfAnalysis, report: FileReport, imported: Set<string>): FileFinding[] {
  const out: FileFinding[] = [];
  if (elf.packer) out.push({ id: "elf.packer", severity: "MEDIUM", title: `Packed with ${elf.packer}`, detail: "The packer's marker is in the file header area. Unpack (upx -d on a copy) to see the real code; modified UPX headers that refuse to unpack are a common anti-analysis trick.", evidence: ["UPX! marker in the first 1 KB"], attack: ["T1027.002"], basis: "structure" });
  const rwx = elf.segments.filter((s) => s.type === "LOAD" && s.flags === "RWX");
  if (rwx.length) out.push({ id: "elf.rwx-segment", severity: "MEDIUM", title: "Loadable segment is writable and executable", detail: "An RWX LOAD segment lets code rewrite itself — packers and shellcode loaders do this; normal linkers split code and data.", evidence: rwx.map((s) => `LOAD @ ${s.vaddr} ${s.flags} (${s.memSize} bytes)`), basis: "structure" });
  if (!elf.checksec.nx && (elf.type.startsWith("EXEC") || elf.checksec.pie === "yes")) out.push({ id: "elf.exec-stack", severity: "LOW", title: "Executable stack", detail: "No non-executable GNU_STACK marker: the stack is executable, which makes memory-corruption bugs easier to exploit.", evidence: [elf.segments.find((s) => s.type === "GNU_STACK") ? "GNU_STACK is RWX" : "GNU_STACK segment absent"], basis: "structure" });
  const risky = [elf.rpath, elf.runpath].filter((p): p is string => !!p).flatMap((p) => p.split(":")).filter((p) => p === "" || p === "." || p.startsWith("/tmp") || p.startsWith("/dev/shm") || p.startsWith("/var/tmp") || (!p.startsWith("/") && !p.startsWith("$ORIGIN")));
  if (risky.length) out.push({ id: "elf.rpath", severity: "MEDIUM", title: "Library search path includes a writable or relative directory", detail: "Anyone who can write there can plant a library the program will load.", evidence: risky.map((p) => `RPATH/RUNPATH entry '${p}'`), attack: ["T1574.006"], basis: "structure" });
  if (elf.staticallyLinked && elf.stripped) out.push({ id: "elf.static-stripped", severity: "INFO", title: "Statically linked and stripped", detail: "No dynamic imports and no symbol table: static analysis has little to go on. Normal for Go and Rust release builds; also typical of IoT botnet binaries.", evidence: ["No PT_INTERP / DYNAMIC", "No .symtab"], basis: "structure" });
  for (const a of elf.anomalies) out.push({ id: "elf.anomaly", severity: "LOW", title: "Structure anomaly", detail: "The file deviates from what standard linkers produce.", evidence: [a], basis: "structure" });

  for (const rule of LINUX_RULES) {
    const evidence: string[] = [];
    if (rule.imports) {
      const groups = rule.imports.map((g) => g.filter((n) => imported.has(n)));
      if (groups.some((g) => !g.length)) continue;
      evidence.push(...groups.flat().map((n) => `imports ${n}`));
    }
    if (rule.strings) {
      const hits = report.strings.filter((s) => rule.strings!.test(s.value));
      if (!hits.length) continue;
      evidence.push(...hits.slice(0, 5).map((s) => `0x${s.offset.toString(16)}: ${s.value.slice(0, 140)}`));
    }
    out.push({ id: rule.id, severity: rule.severity, title: rule.title, detail: rule.explanation, evidence, attack: rule.attack.length ? rule.attack : undefined, basis: rule.imports ? "capability" : "heuristic" });
  }
  return out;
}

function machoFindings(macho: MachoAnalysis): FileFinding[] {
  const out: FileFinding[] = [];
  for (const slice of macho.slices) {
    const label = macho.fat ? ` (${slice.cpu})` : "";
    const sig = slice.signature;
    if (!sig && slice.fileType !== "Object") out.push({ id: "macho.unsigned", severity: slice.cpu === "ARM64" ? "LOW" : "INFO", title: `No code signature${label}`, detail: slice.cpu === "ARM64" ? "Apple Silicon refuses to run unsigned native code; this binary must be signed (even ad hoc) before it runs." : "Gatekeeper blocks unsigned downloaded apps unless the user overrides it.", evidence: ["No LC_CODE_SIGNATURE"], basis: "signature" });
    else if (sig && (sig.adhoc || !sig.hasCms)) out.push({ id: "macho.adhoc", severity: "INFO", title: `Ad-hoc signature${label}`, detail: "Signed without a Developer ID certificate, so it cannot be notarised. Normal for locally built and linker-signed binaries; downloaded software is normally Developer ID-signed.", evidence: [`Identifier ${sig.identifier ?? "?"}`, `Flags ${sig.flags.join(", ") || "none"}`], basis: "signature" });
    else if (sig) {
      const leaf = sig.certificates.find((c) => !c.isCA) ?? sig.certificates[0];
      out.push({ id: "macho.signed", severity: "INFO", title: `Signed: ${leaf?.subject.cn ?? sig.identifier ?? "?"}${label}`, detail: "Certificates were read from the signature. The signature, chain and notarisation were not verified here — use codesign --verify and spctl --assess.", evidence: [`Team ${sig.teamId ?? "?"}`, `Identifier ${sig.identifier ?? "?"}`, `Hardened runtime: ${sig.flags.includes("runtime") ? "yes" : "no"}`], basis: "signature" });
    }
    if (sig?.notableEntitlements.length) out.push({ id: "macho.entitlements", severity: "LOW", title: `Entitlements that weaken protections${label}`, detail: "These entitlements relax the hardened runtime or grant sensitive access.", evidence: sig.notableEntitlements.map((e) => `${e.key}: ${e.note}`), attack: sig.notableEntitlements.some((e) => e.key.includes("library-validation") || e.key.includes("dyld-environment")) ? ["T1574.004"] : undefined, basis: "structure" });
    const weak = slice.libraries.filter((l) => l.kind === "LOAD_WEAK_DYLIB" && l.name.startsWith("@rpath"));
    const relRpath = slice.rpaths.filter((p) => !p.startsWith("@") && !p.startsWith("/usr/lib") && !p.startsWith("/System"));
    if (weak.length || relRpath.length) out.push({ id: "macho.dylib-hijack", severity: "LOW", title: `Dylib search-path hijack surface${label}`, detail: "Weak @rpath libraries or non-system rpaths let a planted library load in place of a missing one when library validation is off.", evidence: [...weak.map((l) => `weak ${l.name}`), ...relRpath.map((p) => `rpath ${p}`)], attack: ["T1574.004"], basis: "structure" });
    if (slice.fileType === "Executable" && !slice.flags.includes("PIE")) out.push({ id: "macho.no-pie", severity: "INFO", title: `Not position-independent${label}`, detail: "Without PIE the executable loads at a fixed address (no ASLR for the main image).", evidence: [`Flags ${slice.flags.join(", ")}`], basis: "structure" });
    if (slice.flags.includes("ALLOW_STACK_EXECUTION")) out.push({ id: "macho.exec-stack", severity: "LOW", title: `Executable stack allowed${label}`, detail: "MH_ALLOW_STACK_EXECUTION disables the non-executable stack.", evidence: ["MH_ALLOW_STACK_EXECUTION"], basis: "structure" });
    if (slice.encrypted) out.push({ id: "macho.encrypted", severity: "INFO", title: `Encrypted segment (FairPlay)${label}`, detail: "App Store encryption: code bytes on disk are encrypted, so static analysis of this copy sees ciphertext.", evidence: ["LC_ENCRYPTION_INFO cryptid ≠ 0"], basis: "structure" });
    for (const a of slice.anomalies) out.push({ id: "macho.anomaly", severity: a.includes("writable and executable") ? "MEDIUM" : "LOW", title: `Structure anomaly${label}`, detail: "The Mach-O deviates from what Apple's linker produces.", evidence: [a], basis: "structure" });
  }
  return out;
}
