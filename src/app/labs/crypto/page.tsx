import { Page } from "@/components/shell/Page";
import { CryptoLab } from "@/components/labs/CryptoLab";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Crypto lab" };

export default function CryptoLabPage() {
  return (
    <Page>
      <PageHeader eyebrow="Response & labs" title="Crypto lab" description="Hashing, HMAC, XOR (with single-byte brute force), AES (GCM/CBC/CTR) and RSA (OAEP/PSS) — all computed locally via WebCrypto. No key or plaintext ever leaves your browser." />
      <CryptoLab />
    </Page>
  );
}
