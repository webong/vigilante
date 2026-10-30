import { MagnifyingGlassIcon, RobotIcon, SealCheckIcon, UsersIcon } from "@phosphor-icons/react"
import { Link } from "@tanstack/react-router"
import type { Actor, ActorFilter } from "@/api"
import { bandBar, ClassBadge, RiskScore } from "@/components/risk"
import { RowsSkeleton } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { ago, claimedName, plural, riskBand } from "@/lib/format"
import { cn } from "@/lib/utils"

export const filterLabels: Record<ActorFilter, string> = {
  suspicious: "Attention",
  agents: "Agents",
  all: "All",
  verified: "Verified",
  dismissed: "Dismissed",
}

const emptyCopy: Record<ActorFilter, string> = {
  suspicious: "Nothing needs attention in the last 24 hours.",
  agents: "No AI agents in the last 24 hours.",
  all: "No traffic yet. Add a sensor and point it at your app.",
  verified: "No verified bots or agents in the last 24 hours.",
  dismissed: "You have not dismissed anyone.",
}

export function VisitorList({
  actors,
  filter,
  search,
  counts,
  selected,
  loading,
  error,
  onFilter,
  onSearch,
  onRetry,
  onClearSearch,
}: {
  actors: Actor[]
  filter: ActorFilter
  search: string
  counts: Partial<Record<ActorFilter, number>>
  selected: boolean
  loading: boolean
  error: unknown
  onFilter: (filter: ActorFilter) => void
  onSearch: (value: string) => void
  onRetry: () => void
  onClearSearch: () => void
}) {
  const needle = search.trim().toLowerCase()
  const visible = needle
    ? actors.filter((actor) =>
        `${claimedName(actor.ua)} ${actor.ip} ${actor.ua} ${actor.class}`.toLowerCase().includes(needle),
      )
    : actors

  return (
    <section
      className={cn("panel overflow-hidden lg:sticky lg:top-16", selected && "max-lg:hidden")}
      aria-label="Visitors"
    >
      <div className="flex flex-col gap-2.5 border-b p-3">
        <div className="flex items-baseline justify-between gap-2 px-0.5">
          <div className="flex items-baseline gap-2">
            <h2 className="font-heading text-xs font-semibold tracking-wide">Visitors</h2>
            <span className="font-mono text-[10px] text-muted-foreground tnum">
              {needle ? `${visible.length}/${actors.length}` : actors.length}
            </span>
          </div>
          <span className="text-[10px] text-muted-foreground">riskiest first</span>
        </div>
        <div className="relative">
          <MagnifyingGlassIcon className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="Search name, IP or class"
            aria-label="Search visitors"
            className="h-8 pl-8 text-xs"
          />
        </div>
        <ToggleGroup
          aria-label="Filter visitors"
          value={[filter]}
          onValueChange={(value) => {
            const next = value[0] as ActorFilter | undefined
            if (next) onFilter(next)
          }}
          variant="outline"
          size="sm"
          spacing={0}
          className="w-full"
        >
          {(Object.keys(filterLabels) as ActorFilter[]).map((value) => (
            <ToggleGroupItem
              key={value}
              value={value}
              className="flex-1 justify-center gap-1 px-1.5 aria-pressed:bg-muted aria-pressed:text-foreground"
            >
              <span className="whitespace-nowrap">{filterLabels[value]}</span>
              {(counts[value] ?? 0) > 0 && (
                <span className="font-mono text-[10px] text-muted-foreground tnum">{counts[value]}</span>
              )}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
      </div>

      {loading && actors.length === 0 ? (
        <RowsSkeleton />
      ) : error ? (
        <div className="flex flex-col items-start gap-2 p-4">
          <p className="text-xs font-medium">Could not load visitors</p>
          <p className="text-[11px] text-muted-foreground">Check the connection and try again.</p>
          <Button size="sm" variant="outline" onClick={onRetry}>
            Retry
          </Button>
        </div>
      ) : visible.length === 0 ? (
        <Empty className="border-0 py-10">
          <EmptyHeader>
            <EmptyMedia variant="icon">{filter === "agents" ? <RobotIcon /> : <UsersIcon />}</EmptyMedia>
            <EmptyTitle>{needle ? "No visitor matches" : emptyCopy[filter]}</EmptyTitle>
            <EmptyDescription>
              {needle
                ? `Nothing in this list matches “${search.trim()}”.`
                : filter === "all"
                  ? "Traffic appears here as soon as a sensor sees a request."
                  : "The list updates every five seconds."}
            </EmptyDescription>
          </EmptyHeader>
          {needle && (
            <EmptyContent>
              <Button size="sm" variant="outline" onClick={onClearSearch}>
                Clear search
              </Button>
            </EmptyContent>
          )}
        </Empty>
      ) : (
        <ul className="max-h-[calc(100dvh-22rem)] divide-y overflow-y-auto">
          {visible.map((actor) => (
            <li key={actor.id}>
              <VisitorRow actor={actor} />
            </li>
          ))}
        </ul>
      )}

      <div className="flex items-center justify-between border-t px-3 py-2 text-[10px] text-muted-foreground">
        <span>{plural(actors.length, "visitor")} in 24h</span>
        <span className="inline-flex items-center gap-1.5">
          <span className="size-1 rounded-full bg-risk-benign" aria-hidden />
          live
        </span>
      </div>
    </section>
  )
}

function VisitorRow({ actor }: { actor: Actor }) {
  const why = actor.triage?.summary ?? actor.signals.find((signal) => signal.weight > 0)?.detail
  return (
    <Link
      to="/visitors/$actorId"
      params={{ actorId: String(actor.id) }}
      search={(previous) => previous}
      className="group relative flex items-start gap-3 px-3 py-3 transition-colors hover:bg-muted/40 data-[status=active]:bg-muted/60"
    >
      <span className={cn("absolute inset-y-0 left-0 w-0.5", bandBar[riskBand(actor.risk)])} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="truncate font-heading text-xs font-semibold">{claimedName(actor.ua)}</span>
          <ClassBadge value={actor.class} className="shrink-0" />
          {actor.verified && (
            <SealCheckIcon className="size-3 shrink-0 text-risk-benign" weight="fill" aria-label="Verified" />
          )}
        </div>
        <p className="mt-0.5 line-clamp-1 text-[11px]/relaxed text-muted-foreground">
          {why ?? "No rule fired."}
        </p>
        <div className="mt-1.5 flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
          <span className="truncate">{actor.ip}</span>
          <span aria-hidden>·</span>
          <span className="whitespace-nowrap">{plural(actor.requests, "req")}</span>
          {actor.triage && (
            <>
              <span aria-hidden>·</span>
              <span className="inline-flex items-center gap-0.5">
                <RobotIcon className="size-2.5" /> AI
              </span>
            </>
          )}
        </div>
      </div>
      <div className="flex shrink-0 flex-col items-end gap-1">
        <RiskScore risk={actor.risk} />
        <span className="text-[9px] whitespace-nowrap text-muted-foreground">{ago(actor.last_seen)}</span>
      </div>
    </Link>
  )
}
