import { cn } from "@/lib/utils"

/** A static placeholder block. No pulse: the layout should not repaint while it waits. */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("bg-muted", className)} />
}

const skeletonRows = ["a", "b", "c", "d", "e", "f"]

export function RowsSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading" className="divide-y">
      {skeletonRows.slice(0, rows).map((key) => (
        <div key={key} className="flex items-center gap-3 px-4 py-3">
          <Skeleton className="h-6 w-8" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-3 w-2/5" />
            <Skeleton className="h-2.5 w-3/5" />
          </div>
          <Skeleton className="h-3 w-10" />
        </div>
      ))}
    </div>
  )
}
