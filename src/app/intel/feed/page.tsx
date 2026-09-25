import { Page } from "@/components/shell/Page";
import { ThreatFeed } from "@/components/intel/ThreatFeed";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Threat feed" };

export default function ThreatFeedPage() {
  return (
    <Page>
      <PageHeader eyebrow="Intelligence" title="Threat feed" description="Recent indicators from abuse.ch: ThreatFox IOCs, URLhaus malicious URLs, MalwareBazaar samples and Feodo Tracker C2 servers — each row sourced and timestamped, nothing fabricated." />
      <ThreatFeed />
    </Page>
  );
}
