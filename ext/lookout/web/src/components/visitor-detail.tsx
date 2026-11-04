import {
  ArrowLeftIcon,
  ArrowSquareOutIcon,
  CaretDownIcon,
  EyeIcon,
  EyeSlashIcon,
  SparkleIcon,
} from "@phosphor-icons/react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { toast } from "sonner"
import { type Actor, api, type EnforcementKind } from "@/api"
import { ActionForm, type Plan } from "@/components/action-form"
import { DecisionRow } from "@/components/decision-row"
import { IdentityAndSignals } from "@/components/identity-signals"
import { SectionHeader } from "@/components/page-header"
import { RequestsTable } from "@/components/requests-table"
import { ClassBadge, RiskBadge, RiskScore, VerifiedBadge } from "@/components/risk"
import { Skeleton } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  ago,
  claimedName,
  classMeaning,
  duration,
  kindEffect,
  kindLabel,
  modelName,
  plural,
  shortJA4,
} from "@/lib/format"
import { actorQuery, overviewQuery } from "@/lib/queries"

export function VisitorDetail({ id }: { id: number }) {
  return <VisitorDetailInner key={id} id={id} />
}

function VisitorDetailInner({ id }: { id: number }) {
  const detail = useQuery(actorQuery(id))
  const overview = useQuery(overviewQuery)

  if (detail.isError) {
    return (
      <div className="panel flex flex-col items-start gap-3 p-5">
        <p className="font-heading text-sm font-medium">This visitor is out of reach.</p>
        <p className="text-[11px] text-muted-foreground">
          {detail.error instanceof Error ? detail.error.message : "The request failed."} It may have fallen
          outside the 24-hour window.
        </p>
        <div className="flex gap-2">
          <Button size="sm" onClick={() => detail.refetch()}>
            Try again
          </Button>
          <Button size="sm" variant="outline" nativeButton={false} render={<Link to="/visitors" />}>
            Back to visitors
          </Button>
        </div>
      </div>
    )
  }

  if (!detail.data) {
    return (
      <div className="panel">
        <div className="flex items-start justify-between gap-4 p-5">
          <div className="flex-1 space-y-2">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-3 w-64" />
            <Skeleton className="h-3 w-48" />
          </div>
          <Skeleton className="h-10 w-24" />
        </div>
        <div className="space-y-3 border-t p-5">
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-3 w-2/3" />
        </div>
      </div>
    )
  }

  const { actor, requests, decisions } = detail.data
  const open = decisions.filter((decision) => decision.status === "pending" || decision.status === "active")
  const past = decisions.filter((decision) => decision.status !== "pending" && decision.status !== "active")
  const llm = overview.data?.llm ?? ""
  const recommended = recommendedPlan(actor)

  return (
    <div className="panel detail-enter">
      <VisitorHeader actor={actor} llm={llm} />
      <Assessment actor={actor} llm={llm} />
      <section className="border-t p-4 sm:p-5">
        <SectionHeader
          title="Enforce"
          hint={
            open.some((decision) => decision.status === "pending")
              ? "A suggestion is waiting. Nothing is enforced until you approve it."
              : "Decisions reach every sensor within a few seconds."
          }
        />
        <div className="mt-3 flex flex-col gap-3">
          {open.length > 0 && (
            <div className="divide-y border">
              {open.map((decision) => (
                <DecisionRow key={decision.id} decision={decision} inActor />
              ))}
            </div>
          )}
          {open.length > 0 ? (
            <Collapsible>
              <CollapsibleTrigger
                render={
                  <Button variant="ghost" size="sm" className="justify-between px-0 hover:bg-transparent" />
                }
              >
                Add another action
                <CaretDownIcon data-icon="inline-end" />
              </CollapsibleTrigger>
              <CollapsibleContent className="pt-3">
                <ActionForm
                  key={actor.triaged_at ?? "rules"}
                  actor={actor}
                  initial={
                    recommended ?? { kind: "challenge", scope: actor.ja4 ? "fingerprint" : "ip", ttl: 1440 }
                  }
                  fromAI={false}
                />
              </CollapsibleContent>
            </Collapsible>
          ) : (
            <ActionForm
              key={actor.triaged_at ?? "rules"}
              actor={actor}
              initial={
                recommended ?? { kind: "challenge", scope: actor.ja4 ? "fingerprint" : "ip", ttl: 1440 }
              }
              fromAI={recommended !== null}
            />
          )}
          {past.length > 0 && (
            <Collapsible>
              <CollapsibleTrigger
                render={
                  <Button variant="ghost" size="sm" className="justify-between px-0 hover:bg-transparent" />
                }
              >
                {plural(past.length, "past decision")}
                <CaretDownIcon data-icon="inline-end" />
              </CollapsibleTrigger>
              <CollapsibleContent className="divide-y border-t">
                {past.map((decision) => (
                  <DecisionRow key={decision.id} decision={decision} inActor />
                ))}
              </CollapsibleContent>
            </Collapsible>
          )}
        </div>
      </section>

      <section className="border-t p-4 sm:p-5">
        <SectionHeader
          title="Identity & signals"
          hint="What it claims, what lookout proved, and every rule that fired."
        />
        <div className="mt-3">
          <IdentityAndSignals actor={actor} />
        </div>
      </section>

      <section className="border-t p-4 sm:p-5">
        <SectionHeader
          title={`Recent requests · ${requests.length}`}
          hint="Newest first. Sensitive query values are redacted at the sensor."
        />
        <div className="mt-3">
          <RequestsTable requests={requests} />
        </div>
      </section>
    </div>
  )
}

function recommendedPlan(actor: Actor): Plan | null {
  const verdict = actor.triage
  if (!verdict || verdict.recommended_action === "none" || verdict.recommended_action === "watch") return null
  return {
    kind: verdict.recommended_action as EnforcementKind,
    scope: actor.ja4 ? verdict.scope : "ip",
    ttl: verdict.ttl_minutes,
  }
}

function VisitorHeader({ actor, llm }: { actor: Actor; llm: string }) {
  const qc = useQueryClient()
  const triage = useMutation({
    mutationFn: () => api.triage(actor.id),
    onSuccess: () => {
      toast.success("A new verdict is ready")
      qc.invalidateQueries()
    },
  })
  const dismiss = useMutation({
    mutationFn: () => api.dismiss(actor.id, actor.dismissed_at === null),
    onSuccess: () => {
      toast.success(actor.dismissed_at ? "Visitor restored" : "Visitor dismissed")
      qc.invalidateQueries()
    },
  })

  return (
    <div className="p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <Link
            to="/visitors"
            search={(previous) => previous}
            className="mb-3 inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground lg:hidden"
          >
            <ArrowLeftIcon className="size-3" /> Back to visitors
          </Link>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="font-heading text-xl leading-tight font-semibold tracking-tight">
              {claimedName(actor.ua)}
            </h2>
            <ClassBadge value={actor.class} />
            {actor.verified && <VerifiedBadge label={actor.verified} />}
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground">{classMeaning[actor.class]}</p>
          <dl className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-muted-foreground">
            <span>{actor.ip}</span>
            <span className="hidden sm:inline" aria-hidden>
              ·
            </span>
            <span title={actor.ja4 || "No TLS fingerprint"}>JA4 {shortJA4(actor.ja4)}</span>
            <span className="hidden sm:inline" aria-hidden>
              ·
            </span>
            <span>{plural(actor.requests, "request")}</span>
            <span className="hidden sm:inline" aria-hidden>
              ·
            </span>
            <span>first seen {ago(actor.first_seen)}</span>
          </dl>
        </div>
        <RiskScore risk={actor.risk} size="lg" />
      </div>

      {actor.dismissed_at && (
        <p className="mt-3 border border-dashed px-3 py-2 text-[11px] text-muted-foreground">
          Dismissed {ago(actor.dismissed_at)}. Hidden from the default lists; still monitored.
        </p>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2 border-t pt-3">
        {llm ? (
          <Button
            size="sm"
            variant={actor.triage ? "outline" : "default"}
            disabled={triage.isPending}
            onClick={() => triage.mutate()}
          >
            <SparkleIcon data-icon="inline-start" />
            {triage.isPending ? "Reading…" : actor.triage ? "Ask AI again" : "Ask AI"}
          </Button>
        ) : actor.triage ? null : (
          <span className="text-[11px] text-muted-foreground">AI triage is off · rules only</span>
        )}
        <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => dismiss.mutate()}>
          {actor.dismissed_at ? (
            <EyeIcon data-icon="inline-start" />
          ) : (
            <EyeSlashIcon data-icon="inline-start" />
          )}
          {actor.dismissed_at ? "Restore" : "Dismiss"}
        </Button>
        <Link
          to="/review"
          className="ml-auto inline-flex items-center gap-1 text-[11px] text-muted-foreground underline decoration-border underline-offset-2 hover:text-foreground"
        >
          Review queue <ArrowSquareOutIcon className="size-3" />
        </Link>
      </div>
      {triage.error && (
        <p role="alert" className="mt-2 text-[11px] text-destructive">
          {triage.error instanceof Error ? triage.error.message : "The model call failed."}
        </p>
      )}
      {dismiss.error && (
        <p role="alert" className="mt-2 text-[11px] text-destructive">
          {dismiss.error instanceof Error ? dismiss.error.message : "Could not change the dismissal."}
        </p>
      )}
    </div>
  )
}

function Assessment({ actor, llm }: { actor: Actor; llm: string }) {
  const verdict = actor.triage
  const topSignals = actor.signals.filter((signal) => signal.weight > 0).slice(0, 3)
  return (
    <section className="border-t p-4 sm:p-5">
      <SectionHeader
        title="Assessment"
        hint={
          verdict
            ? `AI verdict · ${modelName(verdict.model)} · ${actor.triaged_at ? ago(actor.triaged_at) : ""}`
            : "From the rules. No AI verdict yet."
        }
        action={verdict ? <RiskBadge risk={verdict.risk} /> : undefined}
      />
      <div className="mt-3 flex flex-col gap-3">
        {verdict ? (
          <>
            <p className="max-w-2xl text-[13px]/relaxed">{verdict.summary}</p>
            {verdict.evidence.length > 0 && (
              <ul className="flex flex-col gap-1.5">
                {verdict.evidence.map((item) => (
                  <li key={item} className="flex gap-2 text-[11px]/relaxed text-muted-foreground">
                    <span className="mt-2 size-1 shrink-0 bg-muted-foreground/60" aria-hidden />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            )}
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border bg-muted/30 px-3 py-2 text-[11px]">
              <span>
                <span className="text-muted-foreground">Recommends </span>
                <span className="font-medium">
                  {verdict.recommended_action === "none"
                    ? "no action"
                    : verdict.recommended_action === "watch"
                      ? "keep watching"
                      : kindLabel[verdict.recommended_action]}
                </span>
                {verdict.recommended_action !== "none" && verdict.recommended_action !== "watch" && (
                  <span className="text-muted-foreground">
                    {" "}
                    · {verdict.scope === "fingerprint" ? "this fingerprint" : "the whole IP"} ·{" "}
                    {duration(verdict.ttl_minutes)}
                  </span>
                )}
              </span>
              <span className="ml-auto font-mono text-[10px] text-muted-foreground tnum">
                {Math.round(verdict.confidence * 100)}% confident
              </span>
            </div>
            {verdict.risk !== actor.rule_score && (
              <p className="text-[10px] text-muted-foreground">
                Rules scored {actor.rule_score}; the AI's score of {verdict.risk} is the one shown.{" "}
                {kindEffect[verdict.recommended_action as EnforcementKind] ?? ""}
              </p>
            )}
          </>
        ) : (
          <>
            {topSignals.length > 0 ? (
              <ul className="flex flex-col gap-1.5">
                {topSignals.map((signal) => (
                  <li key={signal.code} className="flex gap-2 text-[11px]/relaxed">
                    <span className="mt-2 size-1 shrink-0 bg-muted-foreground/60" aria-hidden />
                    <span>{signal.detail}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[11px] text-muted-foreground">
                No rule found anything unusual about this visitor.
              </p>
            )}
            <p className="text-[10px]/relaxed text-muted-foreground">
              {!llm
                ? "AI triage is off. Set OPENROUTER_API_KEY or ANTHROPIC_API_KEY on the server for a second opinion."
                : actor.rule_score >= 25
                  ? "Queued for the AI: it reads every visitor the rules score 25 or more. Ask now to skip the queue."
                  : "The rules do not send this visitor to the AI. Ask if you want a second opinion."}
            </p>
          </>
        )}
      </div>
    </section>
  )
}
