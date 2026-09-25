import { Page } from "@/components/shell/Page";
import { Exposure } from "@/components/intel/Exposure";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Exposure" };

export default function ExposurePage() {
  return (
    <Page>
      <PageHeader eyebrow="Intelligence" title="Exposure" description="Breach exposure for a domain, and password exposure checked with k-anonymity so the password never leaves your browser. No leaked credentials, tokens or private documents are collected or displayed." />
      <Exposure />
    </Page>
  );
}
