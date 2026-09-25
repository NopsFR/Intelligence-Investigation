// Quick-reference tables not already covered by the Toolbox "References"
// tool (TCP flags, HTTP status, ports, protocols) or the DFIR workbench's
// Windows Event ID reference — hand-authored, not fetched.

export interface RegexPattern {
  name: string;
  pattern: string;
  note?: string;
}

export const REGEX_PATTERNS: RegexPattern[] = [
  { name: "IPv4 address", pattern: "^(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)$" },
  { name: "IPv6 address (simplified)", pattern: "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$", note: "Does not validate all compression edge cases — prefer a parser for strict validation." },
  { name: "Email address (practical)", pattern: "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$" },
  { name: "URL", pattern: "^https?://[^\\s/$.?#].[^\\s]*$" },
  { name: "MD5 hash", pattern: "^[a-fA-F0-9]{32}$" },
  { name: "SHA-1 hash", pattern: "^[a-fA-F0-9]{40}$" },
  { name: "SHA-256 hash", pattern: "^[a-fA-F0-9]{64}$" },
  { name: "CVE ID", pattern: "^CVE-\\d{4}-\\d{4,}$" },
  { name: "MAC address", pattern: "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$" },
  { name: "Base64 (loose)", pattern: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$" },
  { name: "JWT (structure only)", pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$" },
  { name: "Windows file path", pattern: "^[a-zA-Z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*$" },
  { name: "Private (RFC 1918) IPv4", pattern: "^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.)", note: "Matches the start of an address in the 10/8, 172.16/12, or 192.168/16 ranges." },
];

export interface MagicBytesEntry {
  format: string;
  hex: string;
  offset: string;
}

export const MAGIC_BYTES: MagicBytesEntry[] = [
  { format: "Windows PE (EXE/DLL)", hex: "4D 5A", offset: "0" },
  { format: "ELF (Linux executable)", hex: "7F 45 4C 46", offset: "0" },
  { format: "Mach-O 64-bit", hex: "CF FA ED FE", offset: "0" },
  { format: "ZIP / DOCX / XLSX / JAR / APK", hex: "50 4B 03 04", offset: "0" },
  { format: "PDF", hex: "25 50 44 46 2D", offset: "0 (%PDF-)" },
  { format: "RAR archive", hex: "52 61 72 21 1A 07", offset: "0" },
  { format: "7-Zip archive", hex: "37 7A BC AF 27 1C", offset: "0" },
  { format: "gzip", hex: "1F 8B", offset: "0" },
  { format: "PNG", hex: "89 50 4E 47 0D 0A 1A 0A", offset: "0" },
  { format: "JPEG", hex: "FF D8 FF", offset: "0" },
  { format: "GIF87a / GIF89a", hex: "47 49 46 38", offset: "0" },
  { format: "pcap (libpcap)", hex: "D4 C3 B2 A1 / A1 B2 C3 D4", offset: "0" },
  { format: "pcapng", hex: "0A 0D 0D 0A", offset: "0" },
  { format: "OLE compound (legacy Office / MSI)", hex: "D0 CF 11 E0 A1 B1 1A E1", offset: "0" },
  { format: "SQLite database", hex: "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00", offset: "0" },
  { format: "Windows Event Log (EVTX)", hex: "45 6C 66 46 69 6C 65 00", offset: "0 (ElfFile\\0)" },
  { format: "Windows shortcut (LNK)", hex: "4C 00 00 00 01 14 02 00", offset: "0" },
];
