import { Suspense } from "react";
import { Page } from "@/components/shell/Page";
import { Toolbox } from "@/components/toolbox/Toolbox";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Toolbox" };

export default function ToolboxPage() {
  return (
    <Page>
      <PageHeader eyebrow="Platform" title="Toolbox" description="Small, exact utilities for day-to-day analysis. Only the DNS lookup and extractor touch the server; everything else runs in your browser." />
      <Suspense>
        <Toolbox />
      </Suspense>
    </Page>
  );
}
