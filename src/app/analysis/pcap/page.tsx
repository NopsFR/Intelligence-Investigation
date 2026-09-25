import { Page } from "@/components/shell/Page";
import { PcapAnalysis } from "@/components/analysis/pcap/PcapAnalysis";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Packet capture analysis" };

export default function PcapPage() {
  return (
    <Page>
      <PageHeader
        eyebrow="Analysis"
        title="Packet capture lab"
        description="Open a pcap or pcapng locally: conversations with TCP reassembly, DNS, HTTP objects, TLS handshakes with certificates and JA3 / JA4 fingerprints, display filters, stream following, indicators and traffic findings mapped to ATT&CK."
      />
      <PcapAnalysis />
    </Page>
  );
}
