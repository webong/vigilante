import { ShieldCheckIcon, ShieldWarningIcon } from "@phosphor-icons/react"
import type { Actor } from "@/api"
import { cn } from "@/lib/utils"

/** Who it says it is, what lookout could prove, and every rule that fired. */
export function IdentityAndSignals({ actor }: { actor: Actor }) {
  const failed = actor.signals.find((signal) => signal.code === "identity_failed")
  const max = Math.max(1, ...actor.signals.map((signal) => Math.abs(signal.weight)))

  return (
    <div className="flex flex-col gap-5">
      <dl className="grid gap-x-4 gap-y-2.5 text-[11px] sm:grid-cols-[7.5rem_1fr]">
        <dt className="text-muted-foreground">Proof</dt>
        <dd>
          {actor.verified ? (
            <span className="inline-flex items-start gap-1.5 text-risk-benign">
              <ShieldCheckIcon className="mt-0.5 size-3.5 shrink-0" weight="fill" />
              {actor.verified}
            </span>
          ) : failed ? (
            <span className="inline-flex items-start gap-1.5 text-destructive">
              <ShieldWarningIcon className="mt-0.5 size-3.5 shrink-0" weight="fill" />
              {failed.detail}
            </span>
          ) : (
            <span className="text-muted-foreground">
              None. It did not sign its requests, and lookout could not verify a bot claim.
            </span>
          )}
        </dd>
        <dt className="text-muted-foreground">Says it is</dt>
        <dd className="font-mono leading-5 break-all">{actor.ua || "no user agent"}</dd>
        <dt className="text-muted-foreground">IP address</dt>
        <dd className="font-mono leading-5">{actor.ip}</dd>
        <dt className="text-muted-foreground">TLS fingerprint</dt>
        <dd>
          <span className="font-mono leading-5 break-all">{actor.ja4 || "none (plain HTTP)"}</span>
          <span className="mt-0.5 block text-[10px]/relaxed text-muted-foreground">
            JA4 is how its TLS library says hello. Browsers and scripts look different here, whatever they
            claim.
          </span>
        </dd>
      </dl>

      <div>
        <div className="flex items-baseline justify-between gap-3">
          <h3 className="label-caps">Rule signals</h3>
          <span className="font-mono text-[10px] text-muted-foreground tnum">score {actor.rule_score}</span>
        </div>
        {actor.signals.length === 0 ? (
          <p className="mt-2 text-[11px] text-muted-foreground">No rule fired for this visitor.</p>
        ) : (
          <ul className="mt-2 divide-y border-t">
            {actor.signals.map((signal) => (
              <li key={signal.code} className="flex items-start gap-3 py-2">
                <span className="w-12 shrink-0 pt-0.5">
                  <span
                    className={cn(
                      "block font-mono text-[10px] tnum",
                      signal.weight > 0 ? "text-foreground" : "text-risk-benign",
                    )}
                  >
                    {signal.weight > 0 ? `+${signal.weight}` : signal.weight}
                  </span>
                  <span className="mt-1 block h-0.5 bg-muted">
                    <span
                      className={cn(
                        "block h-full",
                        signal.weight > 0 ? "bg-risk-suspicious" : "bg-risk-benign",
                      )}
                      style={{ width: `${(Math.abs(signal.weight) / max) * 100}%` }}
                    />
                  </span>
                </span>
                <span className="text-[11px]/relaxed">{signal.detail}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-2 text-[10px]/relaxed text-muted-foreground">
          Each rule adds or removes points. The total is capped at 0–100.
        </p>
      </div>
    </div>
  )
}
