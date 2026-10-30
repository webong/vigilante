import type { ReactNode } from "react"
import { cn } from "@/lib/utils"

export function PageHeader({
  title,
  description,
  actions,
  meta,
  className,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  meta?: ReactNode
  className?: string
}) {
  return (
    <div className={cn("flex flex-wrap items-end justify-between gap-x-6 gap-y-3", className)}>
      <div className="min-w-0">
        <h1 className="font-heading text-lg font-semibold tracking-tight">{title}</h1>
        {description && (
          <p className="mt-0.5 max-w-2xl text-xs/relaxed text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="flex items-center gap-3">
        {meta}
        {actions}
      </div>
    </div>
  )
}

export function SectionHeader({
  title,
  hint,
  action,
  className,
}: {
  title: ReactNode
  hint?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div className={cn("flex items-start justify-between gap-3", className)}>
      <div className="min-w-0">
        <h2 className="font-heading text-xs font-semibold tracking-wide">{title}</h2>
        {hint && <p className="mt-0.5 text-[11px]/relaxed text-muted-foreground">{hint}</p>}
      </div>
      {action}
    </div>
  )
}
