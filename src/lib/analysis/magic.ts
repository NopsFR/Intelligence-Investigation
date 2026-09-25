import { bytesEqual, latin1 } from "./bytes";

// File-type identification from content (magic numbers), never from the name.

export type FormatFamily = "executable" | "archive" | "document" | "image" | "media" | "capture" | "script" | "text" | "crypto" | "data";

export interface FileType {
  id: string;
  label: string;
  mime: string;
  family: FormatFamily;
  /** The file contains another format we can analyse (PE, ELF, Mach-O, pcap). */
  analyzer?: "pe" | "elf" | "macho" | "pcap";
}

interface Signature extends FileType {
  test: (b: Uint8Array) => boolean;
}

const at = (sig: number[], offset = 0) => (b: Uint8Array) => bytesEqual(b, sig, offset);
const ascii = (s: string, offset = 0) => at([...s].map((c) => c.charCodeAt(0)), offset);

const SIGNATURES: Signature[] = [
  { id: "pe", label: "Windows PE (MZ)", mime: "application/vnd.microsoft.portable-executable", family: "executable", analyzer: "pe", test: ascii("MZ") },
  { id: "elf", label: "ELF", mime: "application/x-elf", family: "executable", analyzer: "elf", test: at([0x7f, 0x45, 0x4c, 0x46]) },
  { id: "macho64", label: "Mach-O 64-bit", mime: "application/x-mach-binary", family: "executable", analyzer: "macho", test: (b) => at([0xcf, 0xfa, 0xed, 0xfe])(b) || at([0xfe, 0xed, 0xfa, 0xcf])(b) },
  { id: "macho32", label: "Mach-O 32-bit", mime: "application/x-mach-binary", family: "executable", analyzer: "macho", test: (b) => at([0xce, 0xfa, 0xed, 0xfe])(b) || at([0xfe, 0xed, 0xfa, 0xce])(b) },
  // 0xCAFEBABE is shared by Java classes and fat Mach-O; the arch count disambiguates.
  { id: "macho-fat", label: "Mach-O universal (fat)", mime: "application/x-mach-binary", family: "executable", analyzer: "macho", test: (b) => at([0xca, 0xfe, 0xba, 0xbe])(b) && b.length > 8 && b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] > 0 && b[7] < 20 },
  { id: "java-class", label: "Java class file", mime: "application/java-vm", family: "executable", test: at([0xca, 0xfe, 0xba, 0xbe]) },
  { id: "dex", label: "Android DEX", mime: "application/vnd.android.dex", family: "executable", test: ascii("dex\n") },
  { id: "wasm", label: "WebAssembly module", mime: "application/wasm", family: "executable", test: at([0x00, 0x61, 0x73, 0x6d]) },
  { id: "pcap", label: "pcap capture", mime: "application/vnd.tcpdump.pcap", family: "capture", analyzer: "pcap", test: (b) => at([0xd4, 0xc3, 0xb2, 0xa1])(b) || at([0xa1, 0xb2, 0xc3, 0xd4])(b) || at([0x4d, 0x3c, 0xb2, 0xa1])(b) || at([0xa1, 0xb2, 0x3c, 0x4d])(b) },
  { id: "pcapng", label: "pcapng capture", mime: "application/x-pcapng", family: "capture", analyzer: "pcap", test: at([0x0a, 0x0d, 0x0d, 0x0a]) },
  { id: "evtx", label: "Windows event log (EVTX)", mime: "application/x-ms-evtx", family: "data", test: ascii("ElfFile\0") },
  { id: "lnk", label: "Windows shortcut (LNK)", mime: "application/x-ms-shortcut", family: "executable", test: at([0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) },
  { id: "ole", label: "OLE compound document (legacy Office / MSI)", mime: "application/x-ole-storage", family: "document", test: at([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) },
  { id: "pdf", label: "PDF document", mime: "application/pdf", family: "document", test: (b) => latin1(b.subarray(0, 1024)).includes("%PDF-") },
  { id: "rtf", label: "Rich Text Format", mime: "application/rtf", family: "document", test: ascii("{\\rtf") },
  { id: "zip", label: "ZIP archive (also DOCX/XLSX/JAR/APK)", mime: "application/zip", family: "archive", test: (b) => at([0x50, 0x4b, 0x03, 0x04])(b) || at([0x50, 0x4b, 0x05, 0x06])(b) },
  { id: "rar", label: "RAR archive", mime: "application/vnd.rar", family: "archive", test: ascii("Rar!\x1a\x07") },
  { id: "7z", label: "7-Zip archive", mime: "application/x-7z-compressed", family: "archive", test: at([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { id: "gzip", label: "gzip", mime: "application/gzip", family: "archive", test: at([0x1f, 0x8b]) },
  { id: "bzip2", label: "bzip2", mime: "application/x-bzip2", family: "archive", test: ascii("BZh") },
  { id: "xz", label: "xz", mime: "application/x-xz", family: "archive", test: at([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) },
  { id: "zstd", label: "Zstandard", mime: "application/zstd", family: "archive", test: at([0x28, 0xb5, 0x2f, 0xfd]) },
  { id: "cab", label: "Microsoft Cabinet", mime: "application/vnd.ms-cab-compressed", family: "archive", test: ascii("MSCF") },
  { id: "tar", label: "tar archive", mime: "application/x-tar", family: "archive", test: ascii("ustar", 257) },
  { id: "iso", label: "ISO 9660 image", mime: "application/x-iso9660-image", family: "archive", test: (b) => ascii("CD001", 0x8001)(b) || ascii("CD001", 0x8801)(b) },
  { id: "vhdx", label: "VHDX disk image", mime: "application/x-vhdx", family: "archive", test: ascii("vhdxfile") },
  { id: "png", label: "PNG image", mime: "image/png", family: "image", test: at([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { id: "jpeg", label: "JPEG image", mime: "image/jpeg", family: "image", test: at([0xff, 0xd8, 0xff]) },
  { id: "gif", label: "GIF image", mime: "image/gif", family: "image", test: (b) => ascii("GIF87a")(b) || ascii("GIF89a")(b) },
  { id: "bmp", label: "BMP image", mime: "image/bmp", family: "image", test: ascii("BM") },
  { id: "webp", label: "WebP image", mime: "image/webp", family: "image", test: (b) => ascii("RIFF")(b) && ascii("WEBP", 8)(b) },
  { id: "ico", label: "Windows icon", mime: "image/vnd.microsoft.icon", family: "image", test: at([0x00, 0x00, 0x01, 0x00]) },
  { id: "mp4", label: "MP4 / QuickTime", mime: "video/mp4", family: "media", test: ascii("ftyp", 4) },
  { id: "mp3", label: "MP3 audio", mime: "audio/mpeg", family: "media", test: (b) => ascii("ID3")(b) || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0) },
  { id: "sqlite", label: "SQLite database", mime: "application/vnd.sqlite3", family: "data", test: ascii("SQLite format 3\0") },
  { id: "pem-cert", label: "PEM certificate", mime: "application/x-pem-file", family: "crypto", test: (b) => latin1(b.subarray(0, 200)).includes("-----BEGIN CERTIFICATE-----") },
  { id: "pem-key", label: "PEM private key", mime: "application/x-pem-file", family: "crypto", test: (b) => /-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(latin1(b.subarray(0, 200))) },
  { id: "der", label: "DER / ASN.1 (certificate or key)", mime: "application/pkix-cert", family: "crypto", test: (b) => b[0] === 0x30 && b[1] === 0x82 && b.length > 256 && b[4] === 0x30 },
];

function looksText(b: Uint8Array): boolean {
  const n = Math.min(b.length, 4096);
  if (!n) return false;
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i];
    if (c === 0) return false;
    if (c < 0x09 || (c > 0x0d && c < 0x20)) bad++;
  }
  return bad / n < 0.02;
}

const SCRIPT_HINTS: [RegExp, FileType][] = [
  [/^#!.*\b(ba|z|k)?sh\b/, { id: "shell", label: "Shell script", mime: "text/x-shellscript", family: "script" }],
  [/^#!.*\bpython/, { id: "python", label: "Python script", mime: "text/x-python", family: "script" }],
  [/^#!.*\b(perl|ruby|node)\b/, { id: "script", label: "Interpreted script", mime: "text/plain", family: "script" }],
  [/^\s*<\?php/, { id: "php", label: "PHP script", mime: "application/x-httpd-php", family: "script" }],
  [/^\s*(<!doctype html|<html)/i, { id: "html", label: "HTML document", mime: "text/html", family: "text" }],
  [/^\s*<\?xml/, { id: "xml", label: "XML document", mime: "application/xml", family: "text" }],
  [/^\s*[[{]/, { id: "json", label: "JSON (probable)", mime: "application/json", family: "text" }],
  [/\b(powershell|Invoke-Expression|IEX\s*\(|FromBase64String|New-Object\s+Net\.WebClient)\b/i, { id: "powershell", label: "PowerShell (probable)", mime: "text/plain", family: "script" }],
  [/\b(CreateObject\s*\(|WScript\.Shell|Dim\s+\w+)\b/i, { id: "vbscript", label: "VBScript (probable)", mime: "text/vbscript", family: "script" }],
  [/^@echo off|\bcmd(\.exe)?\s+\/c\b/im, { id: "batch", label: "Windows batch (probable)", mime: "text/plain", family: "script" }],
];

export function identify(bytes: Uint8Array): FileType {
  for (const s of SIGNATURES) {
    if (s.test(bytes)) {
      const { test, ...type } = s;
      void test;
      return type;
    }
  }
  if (looksText(bytes)) {
    const head = latin1(bytes.subarray(0, 4096));
    for (const [re, type] of SCRIPT_HINTS) if (re.test(head)) return type;
    return { id: "text", label: "Text", mime: "text/plain", family: "text" };
  }
  return { id: "data", label: "Unrecognised binary data", mime: "application/octet-stream", family: "data" };
}
