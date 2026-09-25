import { Page } from "@/components/shell/Page";
import { Encyclopedia } from "@/components/knowledge/Encyclopedia";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Security encyclopedia" };

export default function KnowledgePage() {
  return (
    <Page>
      <PageHeader eyebrow="Knowledge" title="Security encyclopedia" description="Reference articles on attack and defence concepts, each structured as what it is, why it matters, how it works, how it's detected, and how it's defended against." />
      <Encyclopedia />
    </Page>
  );
}
