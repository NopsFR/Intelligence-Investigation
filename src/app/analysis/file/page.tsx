import { Page } from "@/components/shell/Page";
import { FileAnalysis } from "@/components/analysis/file/FileAnalysis";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "File & binary analysis" };

export default function FileAnalysisPage() {
  return (
    <Page>
      <PageHeader
        eyebrow="Analysis"
        title="File & binary analysis"
        description="Static analysis in your browser: file type from content, hashes, entropy, strings and indicators, then PE, ELF and Mach-O structure — headers, sections, imports, exports, resources, signatures and capability indicators mapped to ATT&CK. Nothing is uploaded or executed."
      />
      <FileAnalysis />
    </Page>
  );
}
