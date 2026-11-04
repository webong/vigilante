import { cn } from "@/lib/utils"

/** A broken radar ring with a sweep and an echo: lookout watching. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={cn("size-5", className)} fill="none" aria-hidden>
      <path d="M12 3.2a8.8 8.8 0 1 0 8.8 8.8" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      <path d="M12 12 18.2 5.8" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      <circle cx="12" cy="12" r="2.1" fill="currentColor" />
      <circle cx="18.9" cy="16" r="1.15" fill="currentColor" />
    </svg>
  )
}

export function Logo({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 font-heading text-sm font-semibold tracking-tight",
        className,
      )}
    >
      <LogoMark className="text-primary" />
      lookout
    </span>
  )
}
