import { Page } from "@/components/shell/Page";
import { YaraLab } from "@/components/detection/YaraLab";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "YARA lab" };

export default function YaraLabPage() {
  return (
    <Page>
      <PageHeader eyebrow="Detection" title="YARA lab" description="Write or load a YARA rule, scan a file against it in your browser, and see exactly which strings matched at which offsets. A rule only ever reports a match it actually evaluated." />
      <YaraLab />
    </Page>
  );
}
