import { RobotIcon } from "@phosphor-icons/react"
import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Outlet, useMatchRoute } from "@tanstack/react-router"
import type { ActorFilter } from "@/api"
import { LogoMark } from "@/components/logo"
import { PageHeader } from "@/components/page-header"
import { SignalStrip } from "@/components/signal-strip"
import { Skeleton } from "@/components/skeletons"
import { VisitorList } from "@/components/visitor-list"
import { ago, modelName } from "@/lib/format"
import { actorsQuery, overviewQuery } from "@/lib/queries"
import { cn } from "@/lib/utils"

const filters: ActorFilter[] = ["suspicious", "all", "agents", "verified", "dismissed"]

export type VisitorsSearch = { filter?: ActorFilter; q?: string }

export const Route = createFileRoute("/_app/visitors")({
  validateSearch: (search: Record<string, unknown>): VisitorsSearch => {
    const filter = filters.includes(search.filter as ActorFilter) ? (search.filter as ActorFilter) : undefined
    const q = typeof search.q === "string" && search.q !== "" ? search.q : undefined
    return { filter, q }
  },
  component: VisitorsLayout,
})

function VisitorsLayout() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const matchRoute = useMatchRoute()
  const filter = search.filter ?? "suspicious"
  const q = search.q ?? ""
  const selected = Boolean(matchRoute({ to: "/visitors/$actorId" }))

  const overview = useQuery(overviewQuery)
  const actors = useQuery(actorsQuery(filter))

  const setFilter = (next: ActorFilter) =>
    navigate({
      search: (previous) => ({ ...previous, filter: next === "suspicious" ? undefined : next }),
      replace: true,
    })
  const setSearch = (value: string) =>
    navigate({
      search: (previous) => ({ ...previous, q: value === "" ? undefined : value }),
      replace: true,
    })

  const stats = overview.data?.stats
  const counts: Partial<Record<ActorFilter, number>> = stats
    ? { suspicious: stats.bands.hostile + stats.bands.suspicious, agents: stats.agents_24h }
    : {}

  return (
    <div className="flex flex-col gap-4">
      <title>Visitors · lookout</title>
      <div className={cn("flex flex-col gap-4", selected && "max-lg:hidden")}>
        <PageHeader
          title="Visitors"
          description="Everyone who reached your apps in the last 24 hours, grouped by IP and TLS fingerprint."
          meta={
            <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
              <span className="inline-flex items-center gap-1.5" role="status">
                <span
                  className={cn(
                    "size-1.5 rounded-full",
                    overview.isError
                      ? "bg-destructive"
                      : overview.isFetching
                        ? "bg-risk-watch"
                        : "bg-risk-benign",
                  )}
                  aria-hidden
                />
                {overview.isError
                  ? "updates interrupted"
                  : overview.isFetching
                    ? "updating"
                    : overview.dataUpdatedAt
                      ? `live · ${ago(new Date(overview.dataUpdatedAt).toISOString())}`
                      : "connecting"}
              </span>
              <span className="hidden h-3 w-px bg-border sm:block" aria-hidden />
              <span className="hidden items-center gap-1 sm:inline-flex">
                <RobotIcon className="size-3" />
                {overview.data?.llm ? modelName(overview.data.llm) : "AI triage off"}
              </span>
            </div>
          }
        />

        {overview.data ? <SignalStrip overview={overview.data} /> : <SignalStripSkeleton />}

        {overview.isError && (
          <div className="flex flex-wrap items-center justify-between gap-2 border border-dashed px-3 py-2 text-[11px]">
            <span className="text-muted-foreground">The 24-hour summary could not be updated.</span>
            <button
              type="button"
              onClick={() => overview.refetch()}
              className="underline decoration-border underline-offset-2 hover:text-foreground"
            >
              Retry
            </button>
          </div>
        )}
      </div>

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,420px)_minmax(0,1fr)] xl:grid-cols-[minmax(0,460px)_minmax(0,1fr)]">
        <VisitorList
          actors={actors.data ?? []}
          filter={filter}
          search={q}
          counts={counts}
          selected={selected}
          loading={actors.isPending}
          error={actors.isError ? actors.error : null}
          onFilter={setFilter}
          onSearch={setSearch}
          onRetry={() => actors.refetch()}
          onClearSearch={() => setSearch("")}
        />
        <div className={cn("min-w-0", !selected && "hidden lg:block")}>
          <Outlet />
        </div>
      </div>
    </div>
  )
}

const skeletonCells = ["visitors", "agents", "waiting", "enforce", "mix"]

function SignalStripSkeleton() {
  return (
    <section className="grid grid-cols-2 gap-px bg-border ring-1 ring-border sm:grid-cols-4 xl:grid-cols-5">
      {skeletonCells.map((key) => (
        <div key={key} className="bg-card p-3.5 sm:p-4">
          <Skeleton className="h-2 w-16" />
          <Skeleton className="mt-2 h-6 w-10" />
          <Skeleton className="mt-2 h-2 w-20" />
        </div>
      ))}
    </section>
  )
}

export function VisitorPlaceholder() {
  return (
    <div className="panel flex min-h-[420px] flex-col items-center justify-center gap-3 p-8 text-center">
      <LogoMark className="size-8 text-muted-foreground/40" />
      <p className="font-heading text-sm font-medium">Select a visitor</p>
      <p className="max-w-xs text-[11px]/relaxed text-muted-foreground">
        Pick a row to see what vigilante thinks it is, the evidence behind that, and what you can do about it.
      </p>
    </div>
  )
}
