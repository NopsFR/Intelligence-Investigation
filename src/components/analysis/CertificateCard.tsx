"use client";

import { useEffect, useState } from "react";
import { hex } from "@/lib/analysis/bytes";
import type { Certificate } from "@/lib/analysis/der";
import { CopyButton } from "@/components/ui/primitives";
import { Chip, KV, Mono } from "./common";

function useFingerprint(der: Uint8Array | undefined, alg: "SHA-1" | "SHA-256") {
  const [fp, setFp] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    if (!der?.length) return;
    void crypto.subtle.digest(alg, der as unknown as BufferSource).then((b) => live && setFp(hex(new Uint8Array(b), ":").toUpperCase()));
    return () => {
      live = false;
    };
  }, [der, alg]);
  return fp;
}

/** One X.509 certificate: identity, validity, key, usage and fingerprints. Nothing here is a trust decision. */
export function CertificateCard({ cert, role, now: nowProp }: { cert: Certificate; role?: string; now?: number }) {
  const [mountedAt] = useState(() => Date.now());
  const now = nowProp ?? mountedAt;
  const sha256 = useFingerprint(cert.der, "SHA-256");
  const sha1 = useFingerprint(cert.der, "SHA-1");
  const expired = cert.notAfter ? Date.parse(cert.notAfter) < now : false;
  const notYet = cert.notBefore ? Date.parse(cert.notBefore) > now : false;
  return (
    <div className="rounded-[2px] border border-line-1 bg-ink-1">
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-3 py-2">
        {role && <span className="label">{role}</span>}
        <span className="min-w-0 truncate text-sm font-medium text-fg-1">{cert.subject.cn ?? cert.subject.o ?? cert.subject.text}</span>
        <span className="ml-auto flex gap-1.5">
          {cert.selfIssued && <Chip>self-issued</Chip>}
          {cert.isCA && <Chip tone="ice">CA</Chip>}
          {expired && <Chip tone="err">expired</Chip>}
          {notYet && <Chip tone="warn">not yet valid</Chip>}
        </span>
      </div>
      <div className="px-3 py-1">
        <KV
          rows={[
            ["Subject", <Mono key="s">{cert.subject.text}</Mono>],
            ["Issuer", <Mono key="i">{cert.issuer.text}</Mono>],
            ["Valid", <Mono key="v">{`${cert.notBefore?.slice(0, 10) ?? "?"} → ${cert.notAfter?.slice(0, 10) ?? "?"}`}</Mono>],
            ["Serial", <Mono key="n">{cert.serial}</Mono>],
            ["Key", `${cert.publicKey.algorithm}${cert.publicKey.bits ? ` ${cert.publicKey.bits}-bit` : ""}${cert.publicKey.curve ? ` ${cert.publicKey.curve}` : ""}`],
            ["Signature", cert.signatureAlgorithm],
            ["Extended key usage", cert.extendedKeyUsage.length ? cert.extendedKeyUsage.join(", ") : undefined],
            ["Subject alt names", cert.subjectAltNames.length ? <Mono key="san">{cert.subjectAltNames.slice(0, 30).join(", ")}{cert.subjectAltNames.length > 30 ? ` … +${cert.subjectAltNames.length - 30}` : ""}</Mono> : undefined],
            [
              "SHA-256",
              sha256 && (
                <span key="f" className="flex items-start gap-1">
                  <Mono className="break-all text-fg-2">{sha256}</Mono>
                  <CopyButton value={sha256.replace(/:/g, "").toLowerCase()} label="Copy SHA-256 fingerprint" />
                </span>
              ),
            ],
            ["SHA-1", sha1 && <Mono key="f1" className="break-all text-fg-3">{sha1}</Mono>],
          ]}
        />
      </div>
    </div>
  );
}
