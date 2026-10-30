import { ArrowSquareOutIcon, HandIcon, RobotIcon, SparkleIcon } from "@phosphor-icons/react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { toast } from "sonner"
import { api, type Decision, type EnforcementKind } from "@/api"
import { Button } from "@/components/ui/button"
import { ago, claimedName, duration, kindLabel, until } from "@/lib/format"
import { cn } from "@/lib/utils"
import { RiskBadge } from "./risk"

export const kindBar: Record<EnforcementKind, string> = {
  block: "bg-risk-hostile",
  challenge: "bg-primary",
  rate_limit: "bg-risk-suspicious",
}

const sourceMeta = {
  llm: { icon: RobotIcon, text: "Suggested by AI" },
  rules: { icon: SparkleIcon, text: "Suggested by rules" },
  manual: { icon: HandIcon, text: "Added by you" },
} as const

function statusLine(decision: Decision) {
  switch (decision.status) {
    case "pending":
      return `Waiting · lasts ${duration(decision.ttl_minutes)} once approved`
    case "active":
      return decision.expires_at ? `In force · ends ${until(decision.expires_at)}` : "In force"
    case "expired":
      return decision.expires_at ? `Expired ${ago(decision.expires_at)}` : "Expired"
    case "rejected":
      return `Rejected${decision.decided_at ? ` ${ago(decision.decided_at)}` : ""}`
    case "revoked":
      return `Revoked${decision.decided_at ? ` ${ago(decision.decided_at)}` : ""}`
  }
}

const target = (decision: Decision) =>
  decision.ja4 ? `${decision.ip} · this TLS fingerprint only` : `everything from ${decision.ip}`

export function DecisionRow({
  decision,
  inActor = false,
  compact = false,
  className,
}: {
  decision: Decision
  inActor?: boolean
  compact?: boolean
  className?: string
}) {
  const qc = useQueryClient()
  const act = useMutation({
    mutationFn: (verb: "approve" | "reject" | "revoke") => api.transition(decision.id, verb),
    onSuccess: (_data, verb) => {
      toast.success(
        verb === "approve"
          ? `${kindLabel[decision.kind]} approved`
          : verb === "reject"
            ? "Suggestion rejected"
            : "Decision revoked",
      )
      qc.invalidateQueries()
    },
  })
  const Source = sourceMeta[decision.source]
  const live = decision.status === "pending" || decision.status === "active"
  const actor = inActor ? undefined : decision.actor

  return (
    <div className={cn("relative flex flex-col gap-3 py-3.5 pr-4 pl-5", !live && "opacity-65", className)}>
      <span className={cn("absolute inset-y-0 left-0 w-0.5", kindBar[decision.kind])} aria-hidden />
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:gap-x-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-heading text-xs font-semibold tracking-wide uppercase">
              {decision.kind === "rate_limit" ? `Rate limit ${decision.rpm}/min` : kindLabel[decision.kind]}
            </span>
            {actor && <span className="text-xs text-muted-foreground">on {claimedName(actor.ua)}</span>}
            {actor && <RiskBadge risk={actor.risk} />}
          </div>
          <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{target(decision)}</p>
          {decision.reason && !(inActor && decision.source === "llm") && (
            <p className={cn("mt-2 max-w-2xl text-xs/relaxed", compact && "line-clamp-2")}>
              {decision.reason}
            </p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
            <span className="inline-flex items-center gap-1">
              <Source.icon className="size-3" />
              {Source.text}
            </span>
            <span aria-hidden>·</span>
            <span>{statusLine(decision)}</span>
            {!inActor && decision.actor_id !== null && (
              <>
                <span aria-hidden>·</span>
                <Link
                  to="/visitors/$actorId"
                  params={{ actorId: String(decision.actor_id) }}
                  className="inline-flex items-center gap-0.5 underline decoration-border underline-offset-2 hover:text-foreground"
                >
                  Open visitor <ArrowSquareOutIcon className="size-3" />
                </Link>
              </>
            )}
          </div>
        </div>
        {live && (
          <div className="flex shrink-0 gap-1.5 max-sm:w-full">
            {decision.status === "pending" ? (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  className="max-sm:flex-1"
                  disabled={act.isPending}
                  onClick={() => act.mutate("reject")}
                >
                  Reject
                </Button>
                <Button
                  variant={decision.kind === "block" ? "destructive" : "default"}
                  size="sm"
                  className="max-sm:flex-1"
                  disabled={act.isPending}
                  onClick={() => act.mutate("approve")}
                >
                  Approve {kindLabel[decision.kind].toLowerCase()}
                </Button>
              </>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="max-sm:flex-1"
                disabled={act.isPending}
                onClick={() => act.mutate("revoke")}
              >
                Revoke
              </Button>
            )}
          </div>
        )}
      </div>
      {act.error && (
        <p role="alert" className="text-[11px] text-destructive">
          {act.error instanceof Error ? act.error.message : "That did not work. Try again."}
        </p>
      )}
    </div>
  )
}
