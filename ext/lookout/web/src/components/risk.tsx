import { SealCheckIcon } from "@phosphor-icons/react"
import type { ActorClass, RiskBand } from "@/api"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { bandLabel, bandRange, bands, classLabel, classMeaning, riskBand } from "@/lib/format"
import { cn } from "@/lib/utils"

export const bandBar: Record<RiskBand, string> = {
  hostile: "bg-risk-hostile",
  suspicious: "bg-risk-suspicious",
  watch: "bg-risk-watch",
  benign: "bg-risk-benign",
}

export const bandText: Record<RiskBand, string> = {
  hostile: "text-risk-hostile",
  suspicious: "text-risk-suspicious",
  watch: "text-risk-watch",
  benign: "text-risk-benign",
}

export function RiskMeter({ risk, className }: { risk: number; className?: string }) {
  return (
    <span className={cn("block h-1 overflow-hidden bg-muted", className)} aria-hidden>
      <span
        className={cn("block h-full", bandBar[riskBand(risk)])}
        style={{ width: `${Math.max(4, Math.min(100, risk))}%` }}
      />
    </span>
  )
}

/** The score carries its band in text as well as color. */
export function RiskBadge({ risk, className }: { risk: number; className?: string }) {
  const band = riskBand(risk)
  return (
    <span
      className={cn("inline-flex items-center gap-1.5 text-xs whitespace-nowrap", className)}
      title={`Risk ${risk} of 100 · ${bandLabel[band]}`}
    >
      <span className={cn("size-1.5 rounded-full", bandBar[band])} aria-hidden />
      <span className={cn("font-mono font-semibold tnum", bandText[band])}>{risk}</span>
      <span className="text-muted-foreground">{bandLabel[band]}</span>
    </span>
  )
}

export function RiskScore({ risk, size = "sm" }: { risk: number; size?: "sm" | "lg" }) {
  const band = riskBand(risk)
  if (size === "lg") {
    return (
      <div className="w-32 shrink-0" title={`Risk ${risk} of 100`}>
        <div className="flex items-baseline gap-2">
          <span
            className={cn(
              "font-mono text-4xl leading-none font-semibold tracking-tight tnum",
              bandText[band],
            )}
          >
            {risk}
          </span>
          <span className="text-xs text-muted-foreground">{bandLabel[band]}</span>
        </div>
        <RiskMeter risk={risk} className="mt-2 h-1" />
        <p className="mt-1.5 font-mono text-[10px] text-muted-foreground tnum">risk {bandRange[band]}</p>
      </div>
    )
  }
  return (
    <div className="w-10 shrink-0 text-right" title={`Risk ${risk} of 100`}>
      <div className={cn("font-mono text-lg leading-none font-semibold tnum", bandText[band])}>{risk}</div>
      <RiskMeter risk={risk} className="mt-1.5 h-0.5" />
    </div>
  )
}

export function ClassBadge({ value, className }: { value: ActorClass; className?: string }) {
  return (
    <Badge variant="outline" className={cn("font-normal", className)} title={classMeaning[value]}>
      {classLabel[value]}
    </Badge>
  )
}

export function VerifiedBadge({ label }: { label: string }) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Badge
            variant="outline"
            className="border-risk-benign/40 font-normal text-risk-benign"
            aria-label={`Verified: ${label}`}
          />
        }
      >
        <SealCheckIcon weight="fill" />
        Verified
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

/** Visitors split by risk band: one stacked bar and a legend that carries the numbers. */
export function RiskMix({ counts }: { counts: Record<RiskBand, number> }) {
  const total = bands.reduce((n, band) => n + counts[band], 0)
  return (
    <div className="flex flex-col gap-2">
      <div className="flex h-1.5 gap-px overflow-hidden bg-muted" role="img" aria-label="Visitors by risk">
        {total === 0 ? (
          <span className="flex-1" />
        ) : (
          bands
            .filter((band) => counts[band] > 0)
            .map((band) => (
              <span
                key={band}
                className={bandBar[band]}
                style={{ flexGrow: counts[band], flexBasis: 0, minWidth: 3 }}
                title={`${counts[band]} ${bandLabel[band].toLowerCase()} · ${Math.round((counts[band] / total) * 100)}%`}
              />
            ))
        )}
      </div>
      <ul className="grid grid-cols-2 gap-x-3 gap-y-1">
        {bands.map((band) => (
          <li key={band} className="flex items-center gap-1.5 text-[11px] whitespace-nowrap">
            <span className={cn("size-1.5 shrink-0 rounded-full", bandBar[band])} aria-hidden />
            <span className="font-mono font-semibold tnum">{counts[band]}</span>
            <span className="text-muted-foreground">{bandLabel[band]}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
