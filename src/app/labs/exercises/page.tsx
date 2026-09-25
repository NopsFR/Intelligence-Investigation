import { Page } from "@/components/shell/Page";
import { ExercisesLab } from "@/components/labs/ExercisesLab";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Exercises" };

export default function ExercisesLabPage() {
  return (
    <Page>
      <PageHeader eyebrow="Response & labs" title="Exercises" description="Six local, isolated vulnerability exercises — SQL injection, XSS, path traversal, IDOR, insecure deserialization, and command injection — each with a vulnerable version and its fix, side by side." />
      <ExercisesLab />
    </Page>
  );
}
