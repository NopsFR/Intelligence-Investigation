import { Page } from "@/components/shell/Page";
import { CommandReference } from "@/components/knowledge/CommandReference";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Command reference" };

export default function CommandsPage() {
  return (
    <Page>
      <PageHeader eyebrow="Knowledge" title="Command reference" description="Defensive investigation commands and filters — Linux, PowerShell, Wireshark display filters, tcpdump capture filters, Git, and OpenSSL." />
      <CommandReference />
    </Page>
  );
}
