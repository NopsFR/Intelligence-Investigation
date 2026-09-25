import { Page } from "@/components/shell/Page";
import { ReReference } from "@/components/knowledge/ReReference";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Reverse engineering reference" };

export default function ReReferencePage() {
  return (
    <Page>
      <PageHeader eyebrow="Knowledge" title="Reverse engineering reference" description="Registers, common instructions, calling conventions, and syscalls for x86-64 and ARM64, plus the Windows API catalogue used by the binary analyzer's import annotations." />
      <ReReference />
    </Page>
  );
}
