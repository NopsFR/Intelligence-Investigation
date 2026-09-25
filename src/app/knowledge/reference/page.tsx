import { Page } from "@/components/shell/Page";
import { ReferenceHub } from "@/components/knowledge/ReferenceHub";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "References" };

export default function ReferencePage() {
  return (
    <Page>
      <PageHeader eyebrow="Knowledge" title="References" description="File signatures and security regex patterns, plus quick links to the TCP/HTTP/port reference in the Toolbox and the Windows Event ID reference in the DFIR workbench." />
      <ReferenceHub />
    </Page>
  );
}
