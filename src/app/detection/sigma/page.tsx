import { Page } from "@/components/shell/Page";
import { SigmaLab } from "@/components/detection/SigmaLab";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Sigma lab" };

export default function SigmaLabPage() {
  return (
    <Page>
      <PageHeader eyebrow="Detection" title="Sigma lab" description="Write or load a Sigma rule, evaluate it against real or sample events, and convert it to Splunk, KQL or Lucene. A match is only reported when the rule ran against the events you provided." />
      <SigmaLab />
    </Page>
  );
}
