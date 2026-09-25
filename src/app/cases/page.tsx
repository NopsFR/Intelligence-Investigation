import { Page } from "@/components/shell/Page";
import { CasesList } from "@/components/cases/CasesList";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Cases" };

export default function CasesPage() {
  return (
    <Page>
      <PageHeader eyebrow="Operate" title="Cases" description="Incident cases: notes, evidence with hashes, chain-of-custody log and a timeline, alongside the investigations and indicators involved." />
      <CasesList />
    </Page>
  );
}
