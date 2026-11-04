import type { RequestEvent } from "@/api"
import { Badge } from "@/components/ui/badge"
import { clock } from "@/lib/format"
import { cn } from "@/lib/utils"

const actionLabel: Record<RequestEvent["action"], string | null> = {
  allow: null,
  block: "blocked",
  challenge: "challenged",
  challenge_passed: "passed check",
  rate_limit: "rate limited",
}

/** Newest first. Sensitive query values are already redacted at the sensor. */
export function RequestsTable({ requests }: { requests: RequestEvent[] }) {
  const rows = [...requests].reverse()
  if (rows.length === 0) {
    return <p className="text-[11px] text-muted-foreground">No requests in the analysis window.</p>
  }
  return (
    <div className="max-h-80 overflow-auto border">
      <table className="w-full text-left text-[11px]">
        <thead className="sticky top-0 z-10 bg-card text-muted-foreground">
          <tr className="border-b">
            <th className="px-3 py-2 font-medium">Time</th>
            <th className="py-2 font-medium">Request</th>
            <th className="px-2 py-2 text-right font-medium">Status</th>
            <th className="px-3 py-2 text-right font-medium max-sm:hidden">ms</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.map((request, index) => {
            const action = actionLabel[request.action]
            return (
              // Requests carry no id and two can share a timestamp; the list only re-renders whole.
              // biome-ignore lint/suspicious/noArrayIndexKey: see above
              <tr key={`${request.ts}-${index}`} className="hover:bg-muted/40">
                <td className="px-3 py-1.5 font-mono whitespace-nowrap text-muted-foreground tnum">
                  {clock(request.ts)}
                </td>
                <td className="max-w-0 py-1.5 font-mono">
                  <div
                    className="truncate"
                    title={`${request.method} ${request.path}${request.query ? `?${request.query}` : ""}`}
                  >
                    <span className="text-muted-foreground">{request.method} </span>
                    {request.path}
                    {request.query && <span className="text-muted-foreground">?{request.query}</span>}
                  </div>
                </td>
                <td className="px-2 py-1.5 text-right whitespace-nowrap">
                  {action && (
                    <Badge variant="outline" className="mr-1 font-normal">
                      {action}
                    </Badge>
                  )}
                  <span
                    className={cn(
                      "font-mono tnum",
                      request.status >= 400 && "font-semibold text-destructive",
                    )}
                  >
                    {request.status}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-right font-mono text-muted-foreground tnum max-sm:hidden">
                  {request.duration_ms.toFixed(0)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
