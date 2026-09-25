import {
  Activity,
  Binary,
  BookOpen,
  Briefcase,
  Bug,
  Code2,
  Cpu,
  Crosshair,
  FileSearch,
  FlaskConical,
  Globe,
  KeyRound,
  LayoutDashboard,
  Library,
  ListTree,
  Network,
  Radio,
  ScanSearch,
  Settings2,
  ShieldAlert,
  ShieldHalf,
  Sigma,
  SquareTerminal,
  Wrench,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** One-line purpose, shown in the palette and on collapsed-rail tooltips. */
  hint: string;
  shortcut?: string;
  match?: (path: string) => boolean;
}

export interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    id: "operate",
    label: "Operate",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard, hint: "What needs attention and what you worked on", shortcut: "G D", match: (p) => p === "/" },
      { href: "/investigations", label: "Investigations", icon: ListTree, hint: "History, comparison and the investigation workspace", shortcut: "G I", match: (p) => p.startsWith("/investigations") },
      { href: "/cases", label: "Cases", icon: Briefcase, hint: "Incident cases: notes, evidence, custody and timeline", shortcut: "G C" },
    ],
  },
  {
    id: "intelligence",
    label: "Intelligence",
    items: [
      { href: "/intel/feed", label: "Threat feed", icon: Radio, hint: "Current KEV additions, C2 servers, malware and IOCs from public feeds", shortcut: "G F" },
      { href: "/intel/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, hint: "KEV catalogue, recent CVEs and exploit prediction", shortcut: "G V" },
      { href: "/intel/exposure", label: "Exposure", icon: KeyRound, hint: "Breach exposure for domains and email addresses, password exposure (k-anonymity)" },
      { href: "/malware", label: "Malware", icon: Bug, hint: "Sample and hash intelligence with static analysis" },
      { href: "/ioc", label: "IOC library", icon: Library, hint: "Tracked indicators, extraction and STIX export", shortcut: "G L" },
    ],
  },
  {
    id: "analysis",
    label: "Analysis",
    items: [
      { href: "/analysis/file", label: "File & binary", icon: Binary, hint: "Static PE / ELF / Mach-O analysis in your browser", shortcut: "G B" },
      { href: "/analysis/pcap", label: "Packet capture", icon: Network, hint: "pcap / pcapng analysis: flows, DNS, TLS, HTTP, IOCs", shortcut: "G P" },
      { href: "/analysis/web", label: "Web security", icon: Globe, hint: "Headers, cookies, TLS, CORS, security.txt for authorised URLs", shortcut: "G W" },
      { href: "/analysis/code", label: "Code security", icon: Code2, hint: "Static checks, secrets, IaC and dependency advisories" },
    ],
  },
  {
    id: "detection",
    label: "Detection",
    items: [
      { href: "/attack", label: "ATT&CK", icon: Crosshair, hint: "Techniques, groups, software, mitigations, detections", shortcut: "G A" },
      { href: "/detection/yara", label: "YARA lab", icon: ScanSearch, hint: "Write, validate and run YARA rules against local files" },
      { href: "/detection/sigma", label: "Sigma lab", icon: Sigma, hint: "Validate, explain and test Sigma rules against your events" },
    ],
  },
  {
    id: "response",
    label: "Response & labs",
    items: [
      { href: "/dfir", label: "DFIR", icon: FileSearch, hint: "Process trees, hash comparison, timelines and forensic references" },
      { href: "/labs/decoder", label: "Decoder", icon: ShieldHalf, hint: "Chained encoding and decoding with auto-detection" },
      { href: "/labs/crypto", label: "Crypto lab", icon: FlaskConical, hint: "Hashing, HMAC, XOR, AES and RSA — input, transformation, output" },
      { href: "/labs/exercises", label: "Exercises", icon: Cpu, hint: "Local, isolated vulnerability exercises" },
      { href: "/toolbox", label: "Toolbox", icon: Wrench, hint: "Network, DNS, web and encoding utilities", shortcut: "G T" },
    ],
  },
  {
    id: "knowledge",
    label: "Knowledge",
    items: [
      { href: "/knowledge", label: "Encyclopedia", icon: BookOpen, hint: "Security concepts: what, why, how, detection, defence", shortcut: "G K", match: (p) => p === "/knowledge" || p.startsWith("/knowledge/topic") },
      { href: "/knowledge/re", label: "Reverse engineering", icon: Cpu, hint: "Instruction explainer, registers, calling conventions, syscalls" },
      { href: "/knowledge/commands", label: "Commands", icon: SquareTerminal, hint: "Defensive command and filter reference" },
      { href: "/knowledge/reference", label: "References", icon: Library, hint: "Event IDs, ports, protocols, HTTP status codes" },
    ],
  },
  {
    id: "platform",
    label: "Platform",
    items: [
      { href: "/observatory", label: "API Observatory", icon: Activity, hint: "Source health, authentication and connection tests", shortcut: "G O" },
      { href: "/settings", label: "Settings", icon: Settings2, hint: "Providers, security, database, appearance", shortcut: "G S" },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV.flatMap((g) => g.items);

export function isActive(item: NavItem, path: string): boolean {
  return item.match ? item.match(path) : path === item.href || path.startsWith(`${item.href}/`);
}

export function activeGroup(path: string): string | undefined {
  // Most specific match wins (e.g. /knowledge/re over /knowledge).
  let best: { group: string; len: number } | undefined;
  for (const g of NAV) for (const i of g.items) if (isActive(i, path) && (!best || i.href.length > best.len)) best = { group: g.id, len: i.href.length };
  return best?.group;
}
