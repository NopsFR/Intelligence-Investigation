import { Skeleton } from "@/components/ui/primitives";

export default function Loading() {
  return (
    <div className="mx-auto w-full max-w-[1480px] px-4 pt-6 sm:px-6 lg:px-8" aria-busy="true" aria-label="Loading investigation">
      <Skeleton className="mb-3 h-3 w-40" />
      <Skeleton className="mb-3 h-7 w-[420px] max-w-full" />
      <Skeleton className="mb-6 h-3 w-[300px]" />
      <Skeleton className="mb-6 h-[6px] w-full" />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <Skeleton className="h-[320px]" />
        <Skeleton className="h-[320px]" />
      </div>
    </div>
  );
}
