import { ObservableSearch } from "@/components/ObservableSearch";

export default function InvestigatePage() {
  return (
    <div className="mx-auto max-w-3xl px-4 md:px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-3">New investigation</p>
      <h1 className="text-2xl font-medium mb-6 text-[var(--nops-text)]">
        What are you investigating?
      </h1>
      <ObservableSearch autoFocus />

      <div className="mt-10 grid sm:grid-cols-2 gap-4 font-mono text-xs">
        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] p-4">
          <p className="text-[var(--nops-text)] uppercase tracking-wider mb-1">Quick Scan</p>
          <p className="text-[var(--nops-text-dim)] leading-relaxed">
            A fast pass using a sensible subset of high-signal sources per observable type. Good for triage.
          </p>
        </div>
        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] p-4">
          <p className="text-[var(--nops-text)] uppercase tracking-wider mb-1">Deep Investigation</p>
          <p className="text-[var(--nops-text-dim)] leading-relaxed">
            Executes the full appropriate provider set plus native DNS, TLS, and header analysis where relevant.
          </p>
        </div>
      </div>
    </div>
  );
}
