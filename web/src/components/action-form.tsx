import { RobotIcon } from "@phosphor-icons/react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { toast } from "sonner"
import { type Actor, api, type EnforcementKind } from "@/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { duration, kindEffect, kindLabel } from "@/lib/format"
import { cn } from "@/lib/utils"

export type Plan = { kind: EnforcementKind; scope: "ip" | "fingerprint"; ttl: number }

const baseDurations = [60, 360, 1440, 10080]

export function ActionForm({ actor, initial, fromAI }: { actor: Actor; initial: Plan; fromAI: boolean }) {
  const qc = useQueryClient()
  const [plan, setPlan] = useState<Plan>(initial)
  const [rpm, setRpm] = useState(60)
  const durations = baseDurations.includes(plan.ttl)
    ? baseDurations
    : [...baseDurations, plan.ttl].sort((a, b) => a - b)

  const create = useMutation({
    mutationFn: () =>
      api.createDecision({
        actor_id: actor.id,
        ip: actor.ip,
        ja4: plan.scope === "fingerprint" ? actor.ja4 : undefined,
        kind: plan.kind,
        rpm: plan.kind === "rate_limit" ? rpm : undefined,
        ttl_minutes: plan.ttl,
        reason:
          fromAI && plan.kind === initial.kind && plan.scope === initial.scope && plan.ttl === initial.ttl
            ? (actor.triage?.summary ?? "")
            : `Manual ${kindLabel[plan.kind].toLowerCase()} from the dashboard`,
      }),
    onSuccess: () => {
      toast.success(`${kindLabel[plan.kind]} sent to every sensor`)
      qc.invalidateQueries()
    },
  })

  const target = plan.scope === "fingerprint" ? "this fingerprint" : `all of ${actor.ip}`

  return (
    <div className="flex flex-col gap-3">
      {fromAI && (
        <p className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <RobotIcon className="size-3.5 text-primary" />
          Prefilled from the AI recommendation. You can change anything.
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <ToggleGroup
          aria-label="Action"
          value={[plan.kind]}
          onValueChange={(value) => {
            const kind = value[0] as EnforcementKind | undefined
            if (kind) setPlan({ ...plan, kind })
          }}
          variant="outline"
          size="sm"
          spacing={0}
        >
          <ToggleGroupItem value="challenge" className="aria-pressed:bg-muted">
            Challenge
          </ToggleGroupItem>
          <ToggleGroupItem value="rate_limit" className="aria-pressed:bg-muted">
            Rate limit
          </ToggleGroupItem>
          <ToggleGroupItem value="block" className="aria-pressed:bg-muted">
            Block
          </ToggleGroupItem>
        </ToggleGroup>
        {plan.kind === "rate_limit" && (
          <div className="flex items-center gap-1.5">
            <Input
              type="number"
              min={1}
              max={100000}
              value={rpm}
              onChange={(event) => setRpm(Math.max(1, Math.min(100000, Number(event.target.value) || 1)))}
              aria-label="Requests per minute"
              className="h-7 w-16 font-mono text-xs"
            />
            <span className="text-[11px] text-muted-foreground">req/min</span>
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {actor.ja4 && (
          <Select
            value={plan.scope}
            onValueChange={(value) => setPlan({ ...plan, scope: value as Plan["scope"] })}
            items={[
              { value: "fingerprint", label: "This fingerprint" },
              { value: "ip", label: "Whole IP" },
            ]}
          >
            <SelectTrigger size="sm" className="min-w-36" aria-label="Scope">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="fingerprint">This fingerprint</SelectItem>
                <SelectItem value="ip">Whole IP</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        )}
        <Select
          value={String(plan.ttl)}
          onValueChange={(value) => setPlan({ ...plan, ttl: Number(value) })}
          items={durations.map((minutes) => ({ value: String(minutes), label: duration(minutes) }))}
        >
          <SelectTrigger size="sm" className="min-w-28" aria-label="Duration">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {durations.map((minutes) => (
                <SelectItem key={minutes} value={String(minutes)}>
                  {duration(minutes)}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>

      <p className="text-[11px]/relaxed text-muted-foreground">
        {kindEffect[plan.kind]}
        {plan.scope === "ip" && " A whole IP can be shared by an office, a NAT or a mobile carrier."}
      </p>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          size="sm"
          variant={plan.kind === "block" ? "destructive" : "default"}
          disabled={create.isPending}
          onClick={() => create.mutate()}
        >
          {create.isPending ? "Sending…" : `${kindLabel[plan.kind]} ${target} for ${duration(plan.ttl)}`}
        </Button>
        {create.isSuccess && (
          <span className={cn("text-[11px] text-muted-foreground")}>
            Sensors will apply it within seconds.
          </span>
        )}
      </div>
      {create.error && (
        <p role="alert" className="text-[11px] text-destructive">
          {create.error instanceof Error ? create.error.message : "Could not create the decision."}
        </p>
      )}
    </div>
  )
}
