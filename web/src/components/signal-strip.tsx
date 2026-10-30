import { ArrowRightIcon } from "@phosphor-icons/react"
import { Link } from "@tanstack/react-router"
import type { Overview } from "@/api"
import { RiskMix } from "@/components/risk"
import { compact, plural } from "@/lib/format"
import { cn } from "@/lib/utils"

export function SignalStrip({ overview }: { overview: Overview }) {
  const stats = overview.stats
  return (
    <section
      className="grid grid-cols-2 gap-px bg-border ring-1 ring-border sm:grid-cols-4 xl:grid-cols-[1fr_1fr_1fr_1fr_1.35fr]"
      aria-label="Last 24 hours at a glance"
    >
      <Stat
        label="Visitors · 24h"
        value={compact(stats.actors_24h)}
        sub={`${compact(stats.requests_24h)} requests`}
      />
      <Stat label="AI agents" value={compact(stats.agents_24h)} sub="detected in the last 24h" />
      <div className="bg-card p-3.5 sm:p-4">
        <p className="label-caps">Waiting for you</p>
        <div className="mt-1 flex items-baseline gap-2">
          <span
            className={cn(
              "font-mono text-2xl leading-none font-semibold tnum",
              stats.pending_decisions > 0 && "text-risk-suspicious",
            )}
          >
            {compact(stats.pending_decisions)}
          </span>
          {stats.pending_decisions > 0 && (
            <Link
              to="/review"
              className="inline-flex items-center gap-0.5 text-[10px] text-muted-foreground underline decoration-border underline-offset-2 hover:text-foreground"
            >
              review <ArrowRightIcon className="size-2.5" />
            </Link>
          )}
        </div>
        <p className="mt-1 text-[11px] text-muted-foreground">
          {stats.pending_decisions > 0 ? "suggestions, not enforced yet" : "queue clear"}
        </p>
      </div>
      <Stat label="In force" value={compact(stats.active_decisions)} sub="actions enforced now" />
      <div className="col-span-2 bg-card p-3.5 sm:col-span-4 sm:p-4 xl:col-span-1">
        <div className="flex items-baseline justify-between gap-3">
          <p className="label-caps">Risk mix</p>
          <span className="text-[10px] text-muted-foreground">{plural(stats.actors_24h, "visitor")}</span>
        </div>
        <div className="mt-2.5">
          <RiskMix counts={stats.bands} />
        </div>
      </div>
    </section>
  )
}

function Stat({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="bg-card p-3.5 sm:p-4">
      <p className="label-caps">{label}</p>
      <p className="mt-1 font-mono text-2xl leading-none font-semibold tnum">{value}</p>
      <p className="mt-1 text-[11px] text-muted-foreground">{sub}</p>
    </div>
  )
}
