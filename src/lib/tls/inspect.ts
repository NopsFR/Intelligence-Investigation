import tls from "node:tls";
import { isBlockedIp } from "@/lib/security/ssrf";
import dns from "node:dns/promises";
import type { NormalizedFinding } from "@/types/provider";

export interface CertificateInfo {
  subject: string;
  issuer: string;
  subjectAltNames: string[];
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  serialNumber: string;
  fingerprint256: string;
  publicKeyAlgorithm?: string;
  bits?: number;
  protocol: string | null;
  cipher: string | undefined;
}

export class TlsInspectionError extends Error {}

/**
 * Opens a direct TLS connection to inspect the certificate presented by a
 * host. Resolves the hostname first and refuses to connect to private,
 * loopback, or link-local addresses (SSRF protection).
 */
export async function inspectTls(hostname: string, port = 443, timeoutMs = 6000): Promise<CertificateInfo> {
  const records = await dns.lookup(hostname, { all: true });
  if (records.length === 0) throw new TlsInspectionError("Could not resolve hostname");
  if (records.every((r) => isBlockedIp(r.address))) {
    throw new TlsInspectionError("Destination blocked by network safety controls");
  }

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        timeout: timeoutMs,
        rejectUnauthorized: false, // we want to inspect the cert even if invalid, and report that as a finding
      },
      () => {
        const cert = socket.getPeerCertificate(false);
        if (!cert || Object.keys(cert).length === 0) {
          socket.destroy();
          reject(new TlsInspectionError("No certificate presented"));
          return;
        }

        const validTo = new Date(cert.valid_to);
        const daysUntilExpiry = Math.round((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

        const asString = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v.join(", ") : v);

        const info: CertificateInfo = {
          subject: asString(cert.subject?.CN) ?? Object.values(cert.subject ?? {}).join(", "),
          issuer: asString(cert.issuer?.O) ?? asString(cert.issuer?.CN) ?? Object.values(cert.issuer ?? {}).join(", "),
          subjectAltNames: (cert.subjectaltname ?? "")
            .split(", ")
            .map((s) => s.replace(/^DNS:/, ""))
            .filter(Boolean),
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysUntilExpiry,
          serialNumber: cert.serialNumber,
          fingerprint256: cert.fingerprint256,
          publicKeyAlgorithm: cert.pubkey ? `${cert.bits ?? "?"}-bit` : undefined,
          bits: cert.bits,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name,
        };

        socket.end();
        resolve(info);
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new TlsInspectionError("TLS connection timed out"));
    });

    socket.on("error", (err) => reject(new TlsInspectionError(err.message)));
  });
}

export function findingsForCertificate(hostname: string, cert: CertificateInfo): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  if (cert.daysUntilExpiry < 0) {
    findings.push({
      severity: "CRITICAL",
      category: "tls",
      title: "Certificate has expired",
      description: `The TLS certificate for ${hostname} expired ${Math.abs(cert.daysUntilExpiry)} day(s) ago.`,
      evidence: `Certificate valid_to: ${cert.validTo}.`,
    });
  } else if (cert.daysUntilExpiry < 14) {
    findings.push({
      severity: "HIGH",
      category: "tls",
      title: "Certificate expires soon",
      description: `The TLS certificate for ${hostname} expires in ${cert.daysUntilExpiry} day(s).`,
      evidence: `Certificate valid_to: ${cert.validTo}.`,
    });
  } else if (cert.daysUntilExpiry < 30) {
    findings.push({
      severity: "MEDIUM",
      category: "tls",
      title: "Certificate expiring within 30 days",
      description: `The TLS certificate for ${hostname} expires in ${cert.daysUntilExpiry} day(s).`,
      evidence: `Certificate valid_to: ${cert.validTo}.`,
    });
  }

  const names = [cert.subject, ...cert.subjectAltNames].map((n) => n.toLowerCase());
  const matches = names.some((n) => n === hostname.toLowerCase() || (n.startsWith("*.") && hostname.toLowerCase().endsWith(n.slice(1))));
  if (!matches) {
    findings.push({
      severity: "HIGH",
      category: "tls",
      title: "Certificate hostname mismatch",
      description: `Neither the certificate subject nor its SANs cover ${hostname}.`,
      evidence: `Subject: ${cert.subject}. SANs: ${cert.subjectAltNames.join(", ") || "none"}.`,
    });
  }

  if (cert.protocol === "TLSv1" || cert.protocol === "TLSv1.1") {
    findings.push({
      severity: "MEDIUM",
      category: "tls",
      title: `Outdated TLS protocol negotiated (${cert.protocol})`,
      description: "The server negotiated a deprecated TLS protocol version.",
      evidence: `Negotiated protocol: ${cert.protocol}.`,
    });
  }

  return findings;
}
