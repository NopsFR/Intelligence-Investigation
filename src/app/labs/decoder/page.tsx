import { Page } from "@/components/shell/Page";
import { DecoderLab } from "@/components/labs/DecoderLab";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Decoder lab" };

export default function DecoderLabPage() {
  return (
    <Page>
      <PageHeader eyebrow="Response & labs" title="Decoder lab" description="Chain encodings and decodings with auto-detection: base64, hex, binary, URL, HTML entities, unicode escapes, quoted-printable, ROT13, and JWT payloads. Every step runs in your browser." />
      <DecoderLab />
    </Page>
  );
}
