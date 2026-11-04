import { CaretDownIcon, SealCheckIcon } from "@phosphor-icons/react"
import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { DecisionRow } from "@/components/decision-row"
import { PageHeader, SectionHeader } from "@/components/page-header"
import { RowsSkeleton } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { ago, plural } from "@/lib/format"
import { decisionsQuery, overviewQuery } from "@/lib/queries"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/review")({
  component: ReviewPage,
})

function ReviewPage() {
  const decisions = useQuery(decisionsQuery)
  const overview = useQuery(overviewQuery)
  const all = decisions.data ?? []
  const pending = all.filter((decision) => decision.status === "pending")
  const active = all.filter((decision) => decision.status === "active")
  const past = all.filter((decision) => decision.status !== "pending" && decision.status !== "active")

  return (
    <div className="flex flex-col gap-4">
      <title>Review · lookout</title>
      <PageHeader
        title="Review"
        description="The AI and the rules suggest. You decide. Nothing is enforced until you approve it."
        meta={
          <span className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground" role="status">
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
        }
      />

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <section className="panel overflow-hidden" aria-label="Suggestions waiting for approval">
          <div className="flex items-baseline justify-between gap-3 border-b p-4">
            <SectionHeader
              title="Waiting for you"
              hint="Approve to enforce, reject to let it go. A rejected suggestion stays away for a day."
            />
            <span className="font-mono text-sm font-semibold tnum">{pending.length}</span>
          </div>
          {decisions.isPending ? (
            <RowsSkeleton rows={4} />
          ) : decisions.isError ? (
            <div className="flex flex-col items-start gap-2 p-4">
              <p className="text-xs font-medium">Could not load the queue</p>
              <p className="text-[11px] text-muted-foreground">Check the connection and try again.</p>
              <Button size="sm" variant="outline" onClick={() => decisions.refetch()}>
                Retry
              </Button>
            </div>
          ) : pending.length === 0 ? (
            <Empty className="border-0 py-14">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <SealCheckIcon />
                </EmptyMedia>
                <EmptyTitle>The queue is clear</EmptyTitle>
                <EmptyDescription>
                  When a visitor should be blocked, challenged or slowed down, the suggestion lands here.
                </EmptyDescription>
              </EmptyHeader>
              <EmptyContent>
                <Button size="sm" variant="outline" nativeButton={false} render={<Link to="/visitors" />}>
                  Look at visitors
                </Button>
              </EmptyContent>
            </Empty>
          ) : (
            <div className="divide-y">
              {pending.map((decision) => (
                <DecisionRow key={decision.id} decision={decision} />
              ))}
            </div>
          )}
        </section>

        <section className="panel overflow-hidden lg:sticky lg:top-16" aria-label="Decisions in force">
          <div className="flex items-baseline justify-between gap-3 border-b p-4">
            <SectionHeader title="In force" hint="Sensors apply these within seconds." />
            <span className="font-mono text-sm font-semibold tnum">{active.length}</span>
          </div>
          {active.length === 0 ? (
            <p className="p-4 text-[11px] text-muted-foreground">Nothing is being enforced right now.</p>
          ) : (
            <div className="divide-y">
              {active.map((decision) => (
                <DecisionRow key={decision.id} decision={decision} compact />
              ))}
            </div>
          )}
        </section>
      </div>

      {past.length > 0 && (
        <Collapsible defaultOpen={false}>
          <section className="panel overflow-hidden">
            <CollapsibleTrigger
              render={<button type="button" className="flex w-full items-center gap-3 p-4 text-left" />}
            >
              <SectionHeader title="History" hint={`${plural(past.length, "closed decision")}`} />
              <CaretDownIcon className="ml-auto size-4 text-muted-foreground" />
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="divide-y border-t">
                {past.map((decision) => (
                  <DecisionRow key={decision.id} decision={decision} />
                ))}
              </div>
            </CollapsibleContent>
          </section>
        </Collapsible>
      )}
    </div>
  )
}
