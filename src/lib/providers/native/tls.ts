import "server-only";
import tls, { type DetailedPeerCertificate, type TLSSocket } from "node:tls";
import { X509Certificate } from "node:crypto";
import type { NormalizedFinding, NormalizedRelationship } from "@/lib/core/types";
import { resolvePublicAddress } from "@/lib/net/policy";
import { TargetRequestError } from "@/lib/net/target";
import { classifyIp } from "@/lib/observables/ip";
import { event, events, fact, facts } from "../helpers";
import { ProviderSkip } from "../runtime";
import type { ProviderDefinition } from "../types";

export interface ChainCertificate {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint256: string;
  keyType?: string;
  keySize?: number;
  curve?: string;
  selfSigned: boolean;
  isCA?: boolean;
}

export interface TlsInspection {
  hostname: string;
  address: string;
  port: number;
  protocol: string | null;
  cipher?: string;
  authorized: boolean;
  authorizationError?: string;
  hostnameMatches: boolean;
  hostnameError?: string;
  subjectAltNames: string[];
  chain: ChainCertificate[];
  daysRemaining: number;
  alpn?: string | false;
  tls13?: boolean;
  legacy?: { tls10: boolean; tls11: boolean };
}

const flat = (v: string | string[] | undefined) => (Array.isArray(v) ? v.join(", ") : v ?? "");
const dn = (o: Record<string, string | string[]> | undefined) =>
  o ? ["CN", "O", "OU", "C"].filter((k) => o[k]).map((k) => `${k}=${flat(o[k])}`).join(", ") : "";

function describe(cert: DetailedPeerCertificate): ChainCertificate {
  let keyType: string | undefined;
  let keySize: number | undefined;
  let curve: string | undefined;
  let isCA: boolean | undefined;
  try {
    const x = new X509Certificate(cert.raw);
    keyType = x.publicKey.asymmetricKeyType;
    keySize = x.publicKey.asymmetricKeyDetails?.modulusLength;
    curve = x.publicKey.asymmetricKeyDetails?.namedCurve;
    isCA = x.ca;
  } catch {
    keySize = cert.bits;
  }
  return {
    subject: dn(cert.subject as unknown as Record<string, string>),
    issuer: dn(cert.issuer as unknown as Record<string, string>),
    validFrom: new Date(cert.valid_from).toISOString(),
    validTo: new Date(cert.valid_to).toISOString(),
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256,
    keyType,
    keySize,
    curve,
    selfSigned: dn(cert.subject as unknown as Record<string, string>) === dn(cert.issuer as unknown as Record<string, string>),
    isCA,
  };
}

function connect(address: string, hostname: string, port: number, timeoutMs: number, options: tls.ConnectionOptions = {}): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: address,
      servername: hostname,
      port,
      rejectUnauthorized: false,
      timeout: timeoutMs,
      ALPNProtocols: ["h2", "http/1.1"],
      ...options,
    });
    const onError = (err: Error) => {
      socket.destroy();
      reject(err);
    };
    socket.once("secureConnect", () => resolve(socket));
    socket.once("error", onError);
    socket.setTimeout(timeoutMs, () => onError(Object.assign(new Error("TLS handshake timed out"), { name: "TimeoutError" })));
  });
}

async function probe(address: string, hostname: string, port: number, options: tls.ConnectionOptions): Promise<boolean> {
  try {
    const s = await connect(address, hostname, port, 4000, options);
    s.destroy();
    return true;
  } catch {
    return false;
  }
}

export async function inspectTls(hostname: string, options: { port?: number; deep?: boolean; timeoutMs?: number } = {}): Promise<TlsInspection> {
  const port = options.port ?? 443;
  const { address } = await resolvePublicAddress(hostname);
  const socket = await connect(address, hostname, port, options.timeoutMs ?? 7000);
  try {
    const leaf = socket.getPeerCertificate(true);
    if (!leaf || !leaf.raw) throw new TargetRequestError("The server completed the handshake without presenting a certificate", "tls");
    const chain: ChainCertificate[] = [];
    const seen = new Set<string>();
    let current: DetailedPeerCertificate | undefined = leaf;
    while (current && current.raw && !seen.has(current.fingerprint256) && chain.length < 6) {
      seen.add(current.fingerprint256);
      chain.push(describe(current));
      current = current.issuerCertificate;
    }
    const identityError = tls.checkServerIdentity(hostname, leaf);
    const inspection: TlsInspection = {
      hostname,
      address,
      port,
      protocol: socket.getProtocol(),
      cipher: socket.getCipher()?.standardName ?? socket.getCipher()?.name,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
      hostnameMatches: !identityError,
      hostnameError: identityError?.message,
      subjectAltNames: (leaf.subjectaltname ?? "")
        .split(",")
        .map((s) => s.trim().replace(/^(DNS|IP Address):/, ""))
        .filter(Boolean),
      chain,
      daysRemaining: Math.floor((new Date(leaf.valid_to).getTime() - Date.now()) / 86_400_000),
      alpn: socket.alpnProtocol ?? undefined,
    };
    socket.destroy();
    if (options.deep) {
      const [tls13, tls11, tls10] = await Promise.all([
        inspection.protocol === "TLSv1.3" ? Promise.resolve(true) : probe(address, hostname, port, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" }),
        probe(address, hostname, port, { minVersion: "TLSv1.1", maxVersion: "TLSv1.1", ciphers: "DEFAULT@SECLEVEL=0" }),
        probe(address, hostname, port, { minVersion: "TLSv1", maxVersion: "TLSv1", ciphers: "DEFAULT@SECLEVEL=0" }),
      ]);
      inspection.tls13 = tls13;
      inspection.legacy = { tls10, tls11 };
    }
    return inspection;
  } finally {
    socket.destroy();
  }
}

export function tlsFindings(i: TlsInspection): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const leaf = i.chain[0];
  if (i.daysRemaining < 0) {
    findings.push({
      rule: "tls.expired",
      severity: "HIGH",
      category: "tls",
      title: `Certificate expired ${Math.abs(i.daysRemaining)} day(s) ago`,
      description: `The certificate for ${i.hostname} was valid until ${leaf.validTo.slice(0, 10)}.`,
      rationale: "Browsers and clients reject expired certificates; users who click through are trained to ignore real interception warnings.",
      evidence: `notAfter ${leaf.validTo}`,
      remediation: "Renew the certificate and automate renewal.",
    });
  } else if (i.daysRemaining < 7) {
    findings.push({
      rule: "tls.expiring",
      severity: "MEDIUM",
      category: "tls",
      title: `Certificate expires in ${i.daysRemaining} day(s)`,
      description: `The certificate for ${i.hostname} expires on ${leaf.validTo.slice(0, 10)}.`,
      rationale: "Short-lived certificates renew automatically well before expiry; this close to the deadline, renewal may be failing.",
      evidence: `notAfter ${leaf.validTo}`,
    });
  }
  if (!i.hostnameMatches) {
    findings.push({
      rule: "tls.hostname-mismatch",
      severity: "HIGH",
      category: "tls",
      title: "Certificate does not cover this hostname",
      description: i.hostnameError ?? `${i.hostname} is not listed in the certificate's names.`,
      rationale: "A name mismatch means clients cannot verify they reached the intended server.",
      evidence: `SANs: ${i.subjectAltNames.slice(0, 8).join(", ") || "none"}`,
    });
  }
  if (!i.authorized && i.authorizationError && !/CERT_HAS_EXPIRED/.test(i.authorizationError)) {
    const selfSigned = /SELF_SIGNED/.test(i.authorizationError);
    findings.push({
      rule: selfSigned ? "tls.self-signed" : "tls.untrusted",
      severity: "HIGH",
      category: "tls",
      title: selfSigned ? "Self-signed certificate" : "Certificate chain is not trusted",
      description: `Validation against the public trust store failed: ${i.authorizationError}.`,
      rationale: "Untrusted certificates provide no protection against interception because clients cannot authenticate the server.",
      evidence: `Issuer: ${leaf.issuer}`,
    });
  }
  if (leaf?.keyType === "rsa" && (leaf.keySize ?? 4096) < 2048) {
    findings.push({
      rule: "tls.weak-key",
      severity: "MEDIUM",
      category: "tls",
      title: `Weak ${leaf.keySize}-bit RSA key`,
      description: "The certificate key is below the 2048-bit minimum required by the CA/Browser Forum.",
      evidence: `Key: RSA ${leaf.keySize}`,
    });
  }
  if (i.protocol === "TLSv1" || i.protocol === "TLSv1.1") {
    findings.push({
      rule: "tls.legacy-negotiated",
      severity: "HIGH",
      category: "tls",
      title: `Server negotiated deprecated ${i.protocol}`,
      description: "The server's best protocol was a TLS version deprecated by RFC 8996.",
      evidence: `Negotiated: ${i.protocol}`,
    });
  } else if (i.legacy && (i.legacy.tls10 || i.legacy.tls11)) {
    const versions = [i.legacy.tls10 && "TLS 1.0", i.legacy.tls11 && "TLS 1.1"].filter(Boolean).join(" and ");
    findings.push({
      rule: "tls.legacy-accepted",
      severity: "MEDIUM",
      category: "tls",
      title: `Server still accepts ${versions}`,
      description: `A handshake restricted to ${versions} succeeded.`,
      rationale: "TLS 1.0/1.1 were deprecated in 2021 (RFC 8996); keeping them enabled exposes downgrade-susceptible clients and fails PCI DSS.",
      evidence: `Probe results: TLS1.0 ${i.legacy.tls10 ? "accepted" : "refused"}, TLS1.1 ${i.legacy.tls11 ? "accepted" : "refused"}`,
      remediation: "Disable TLS 1.0 and 1.1 on the server.",
    });
  }
  if (i.tls13 === false) {
    findings.push({
      rule: "tls.no-tls13",
      severity: "INFO",
      category: "tls",
      title: "TLS 1.3 not supported",
      description: `The server's highest protocol is ${i.protocol}.`,
      rationale: "TLS 1.3 removes legacy cipher suites and shortens the handshake; supporting it is current best practice.",
      evidence: `TLS 1.3-only handshake refused.`,
    });
  }
  return findings;
}

function targetHost(observable: string, type: string): string {
  if (type === "URL") {
    const url = new URL(observable);
    if (url.protocol !== "https:") throw new ProviderSkip("URL is not HTTPS; no certificate to inspect");
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (classifyIp(host)) throw new ProviderSkip("URL uses an IP address; certificate hostname checks do not apply");
    return host;
  }
  return observable;
}

export const tlsInspection: ProviderDefinition = {
  id: "tls",
  code: "TLS",
  name: "TLS & certificate",
  vendor: "Native · direct TLS handshake",
  category: "certificates",
  kind: "native",
  active: true,
  description: "Direct TLS handshake: certificate chain, validity, hostname match, key strength, negotiated protocol and legacy-protocol probing.",
  homepage: "https://datatracker.ietf.org/doc/html/rfc8446",
  auth: { type: "none" },
  endpoint: "TLS · port 443 (SSRF-guarded, address pinned)",
  supports: ["DOMAIN", "URL"],
  quick: "none",
  cacheTtlSeconds: 30 * 60,
  timeoutMs: 15_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    const host = targetHost(ctx.observable, ctx.type);
    const port = ctx.type === "URL" && new URL(ctx.observable).port ? Number(new URL(ctx.observable).port) : 443;
    if (![443, 8443].includes(port)) throw new ProviderSkip(`TLS inspection is limited to ports 443 and 8443 (URL uses ${port})`);
    const i = await inspectTls(host, { port, deep: ctx.mode === "DEEP" });
    const leaf = i.chain[0];
    const relationships: NormalizedRelationship[] = [
      { source: { type: "domain", value: host }, target: { type: "certificate", value: leaf.fingerprint256.replace(/:/g, "").toLowerCase(), label: leaf.subject.split(",")[0] }, type: "presents-certificate", evidence: `Presented during TLS handshake to ${i.address}:${i.port}.` },
      ...i.subjectAltNames
        .filter((n) => n.toLowerCase() !== host)
        .slice(0, 20)
        .map((n) => ({
          source: { type: "certificate" as const, value: leaf.fingerprint256.replace(/:/g, "").toLowerCase() },
          target: { type: "domain" as const, value: n.replace(/^\*\./, "").toLowerCase() },
          type: "covers",
          evidence: "Subject alternative name on the served certificate.",
        })),
    ];
    return {
      summary: `${i.protocol ?? "TLS"} · ${leaf.issuer.match(/O=([^,]+)/)?.[1] ?? "issuer unknown"} · ${i.daysRemaining >= 0 ? `${i.daysRemaining} days left` : "expired"}`,
      listed: true,
      facts: facts(
        fact("protocol", "Negotiated protocol", i.protocol, "mono", true),
        fact("cipher", "Cipher suite", i.cipher, "mono"),
        fact("issuer", "Issuer", leaf.issuer, "text", true),
        fact("subject", "Subject", leaf.subject, "text"),
        fact("validTo", "Expires", leaf.validTo, "datetime", true),
        fact("daysRemaining", "Days remaining", i.daysRemaining, "number"),
        fact("trusted", "Trusted chain", i.authorized, "bool", true),
        fact("hostnameMatch", "Hostname matches", i.hostnameMatches, "bool"),
        fact("key", "Key", leaf.keyType ? `${leaf.keyType.toUpperCase()}${leaf.keySize ? ` ${leaf.keySize}` : ""}${leaf.curve ? ` ${leaf.curve}` : ""}` : undefined, "mono"),
        fact("sans", "Subject alternative names", i.subjectAltNames.slice(0, 30), "list"),
        fact("alpn", "ALPN", i.alpn || undefined, "mono"),
        fact("tls13", "TLS 1.3 supported", i.tls13, "bool"),
        fact("legacy", "Legacy TLS 1.0 / 1.1 accepted", i.legacy ? i.legacy.tls10 || i.legacy.tls11 : undefined, "bool"),
        fact("fingerprint", "SHA-256 fingerprint", leaf.fingerprint256, "mono"),
        fact("address", "Connected to", `${i.address}:${i.port}`, "mono")
      ),
      data: { kind: "tls", ...i },
      findings: tlsFindings(i),
      relationships,
      timeline: events(event(leaf.validFrom, "Certificate validity begins", leaf.issuer.match(/O=([^,]+)/)?.[1]), event(leaf.validTo, "Certificate expires")),
      raw: { ...i, chain: i.chain.map((c) => ({ ...c })) },
    };
  },
};

