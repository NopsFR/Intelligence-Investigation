import { Page } from "@/components/shell/Page";
import { PasswordLab } from "@/components/labs/PasswordLab";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Password security" };

export default function PasswordLabPage() {
  return (
    <Page>
      <PageHeader eyebrow="Response & labs" title="Password security" description="Strength analysis, breach checking, and generation — entirely local except a 5-character SHA-1 prefix sent for the k-anonymity breach check. Nothing you type is stored or logged." />
      <PasswordLab />
    </Page>
  );
}
