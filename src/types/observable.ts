export const OBSERVABLE_TYPES = [
  "IPV4",
  "IPV6",
  "DOMAIN",
  "URL",
  "MD5",
  "SHA1",
  "SHA256",
  "CVE",
  "ASN",
] as const;

export type ObservableType = (typeof OBSERVABLE_TYPES)[number];

export interface DetectedObservable {
  raw: string;
  normalized: string;
  type: ObservableType;
}

export const OBSERVABLE_LABELS: Record<ObservableType, string> = {
  IPV4: "IPv4 address",
  IPV6: "IPv6 address",
  DOMAIN: "Domain",
  URL: "URL",
  MD5: "MD5 hash",
  SHA1: "SHA1 hash",
  SHA256: "SHA256 hash",
  CVE: "CVE identifier",
  ASN: "Autonomous System Number",
};
