import { Page } from "@/components/shell/Page";
import { DfirWorkbench } from "@/components/dfir/DfirWorkbench";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "DFIR" };

export default function DfirPage() {
  return (
    <Page>
      <PageHeader eyebrow="Response & labs" title="DFIR workbench" description="Local, offline forensics utilities: merge and sort logs into a timeline, compare hash lists across sources, reconstruct a process tree from a listing, and look up Windows / Sysmon / PowerShell event IDs. Nothing here touches a live system." />
      <DfirWorkbench />
    </Page>
  );
}
