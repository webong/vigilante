import {
  ArrowUpRightIcon,
  CopyIcon,
  InfoIcon,
  MagnifyingGlassIcon,
  SealCheckIcon,
  WarningIcon,
  XIcon,
} from "@phosphor-icons/react"
import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { useState } from "react"
import { toast } from "sonner"
import type { EgressDest } from "@/api"
import { PageHeader } from "@/components/page-header"
import { RowsSkeleton } from "@/components/skeletons"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { ago, compact, plural } from "@/lib/format"
import { egressQuery, sensorsQuery } from "@/lib/queries"
import { cn } from "@/lib/utils"

type OutboundSearch = {
  connection?: string
  q?: string
  sensor?: string
  flagged?: boolean
  sort?: "recent" | "flagged"
}

export const Route = createFileRoute("/_app/outbound")({
  validateSearch: (search: Record<string, unknown>): OutboundSearch => ({
    connection:
      typeof search.connection === "string" && search.connection !== "" ? search.connection : undefined,
    q: typeof search.q === "string" && search.q !== "" ? search.q : undefined,
    sensor: typeof search.sensor === "string" && search.sensor !== "" ? search.sensor : undefined,
    flagged:
      search.flagged === true || search.flagged === "1" || search.flagged === "true" ? true : undefined,
    sort: search.sort === "flagged" ? "flagged" : undefined,
  }),
  component: OutboundPage,
})

const flagText = {
  new_destination: "New destination",
  uncommon_port: "Uncommon port",
} as const

function destinationAddress(row: EgressDest) {
  return `${row.dst_ip.includes(":") ? `[${row.dst_ip}]` : row.dst_ip}:${row.dst_port}`
}

function OutboundPage() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const egress = useQuery(egressQuery)
  const sensors = useQuery(sensorsQuery)
  const q = search.q ?? ""
  const sensor = search.sensor ?? "all"
  const flagged = search.flagged ?? false
  const sort = search.sort ?? "recent"

  const rows = egress.data ?? []
  const sensorName = (id: number) => sensors.data?.find((item) => item.id === id)?.name ?? `Sensor ${id}`
  const needle = q.trim().toLowerCase()
  const filtered = rows
    .filter(
      (row) =>
        (sensor === "all" || String(row.sensor_id) === sensor) &&
        (!flagged || row.flags.length > 0) &&
        `${row.comm} ${destinationAddress(row)} ${row.uid} ${row.last_pid} ${sensorName(row.sensor_id)}`
          .toLowerCase()
          .includes(needle),
    )
    .sort(
      (a, b) =>
        (sort === "flagged" ? b.flags.length - a.flags.length : 0) ||
        Date.parse(b.last_seen) - Date.parse(a.last_seen) ||
        a.id - b.id,
    )

  const observing =
    sensors.data?.filter(
      (item) => item.egress_since && item.last_seen_at && Date.now() - Date.parse(item.last_seen_at) < 30_000,
    ) ?? []
  const selected = rows.find((row) => String(row.id) === search.connection)
  const filtersActive = Boolean(q || search.sensor || flagged)

  const update = (next: Partial<OutboundSearch>) =>
    navigate({ search: (previous) => ({ ...previous, ...next }), replace: true })

  return (
    <div className="flex flex-col gap-4">
      <title>Outbound · lookout</title>
      <PageHeader
        title="Outbound"
        description="TCP connections leaving your servers, grouped by process, user and destination. Metadata only."
        meta={
          <span className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground" role="status">
            <span
              className={cn(
                "size-1.5 rounded-full",
                sensors.isError
                  ? "bg-destructive"
                  : observing.length > 0
                    ? "bg-risk-benign"
                    : "bg-muted-foreground/40",
              )}
              aria-hidden
            />
            {sensors.isError
              ? "capture status unavailable"
              : observing.length > 0
                ? `capturing on ${observing.map((item) => item.name).join(", ")}`
                : "no egress capture"}
          </span>
        }
      />

      {!sensors.isPending && observing.length === 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 border border-dashed px-3 py-2 text-[11px]">
          <span className="text-muted-foreground">
            No connected sensor is capturing outbound traffic. Start one with{" "}
            <code className="font-mono">-egress</code> (needs root).
          </span>
          <Button size="xs" variant="outline" nativeButton={false} render={<Link to="/sensors" />}>
            Sensors
          </Button>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-48 flex-1 max-sm:w-full">
          <MagnifyingGlassIcon className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            value={q}
            onChange={(event) => update({ q: event.target.value || undefined })}
            placeholder="Search process, destination, user or PID"
            aria-label="Search outbound connections"
            className="h-8 pl-8 text-xs"
          />
        </div>
        <Select
          value={sensor}
          onValueChange={(value) => update({ sensor: value === "all" ? undefined : (value as string) })}
          items={[
            { value: "all", label: "All sensors" },
            ...(sensors.data ?? []).map((item) => ({ value: String(item.id), label: item.name })),
          ]}
        >
          <SelectTrigger size="sm" className="min-w-32" aria-label="Filter by sensor">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All sensors</SelectItem>
              {(sensors.data ?? []).map((item) => (
                <SelectItem key={item.id} value={String(item.id)}>
                  {item.name}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        <ToggleGroup
          aria-label="Filter connections"
          value={[flagged ? "flagged" : "all"]}
          onValueChange={(value) => {
            const next = value[0]
            if (next) update({ flagged: next === "flagged" ? true : undefined })
          }}
          variant="outline"
          size="sm"
          spacing={0}
        >
          <ToggleGroupItem value="all" className="aria-pressed:bg-muted">
            All
          </ToggleGroupItem>
          <ToggleGroupItem value="flagged" className="aria-pressed:bg-muted">
            Flagged
          </ToggleGroupItem>
        </ToggleGroup>
        <Select
          value={sort}
          onValueChange={(value) => update({ sort: value === "flagged" ? "flagged" : undefined })}
          items={[
            { value: "recent", label: "Most recent" },
            { value: "flagged", label: "Flagged first" },
          ]}
        >
          <SelectTrigger size="sm" className="min-w-32" aria-label="Sort connections">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="recent">Most recent</SelectItem>
              <SelectItem value="flagged">Flagged first</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
        {filtersActive && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => navigate({ search: {}, replace: true })}
            aria-label="Clear filters"
          >
            <XIcon data-icon="inline-start" />
            Clear
          </Button>
        )}
      </div>

      <section className="panel overflow-hidden" aria-label="Outbound connections">
        {egress.isPending ? (
          <RowsSkeleton />
        ) : egress.isError ? (
          <div className="flex flex-col items-start gap-2 p-4">
            <p className="text-xs font-medium">Could not load outbound connections</p>
            <p className="text-[11px] text-muted-foreground">Check the connection and try again.</p>
            <Button size="sm" variant="outline" onClick={() => egress.refetch()}>
              Retry
            </Button>
          </div>
        ) : filtered.length === 0 ? (
          <Empty className="border-0 py-14">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <ArrowUpRightIcon />
              </EmptyMedia>
              <EmptyTitle>
                {rows.length ? "No connections match" : "No outbound connections recorded"}
              </EmptyTitle>
              <EmptyDescription>
                {rows.length
                  ? "Try a different search, sensor or filter."
                  : "Outbound TCP appears here when a sensor with egress capture observes traffic."}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="border-b text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Process / destination</th>
                  <th className="px-3 py-2.5 font-medium max-md:hidden">Sensor</th>
                  <th className="px-3 py-2.5 text-right font-medium">Connections</th>
                  <th className="px-4 py-2.5 text-right font-medium whitespace-nowrap">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {filtered.map((row) => (
                  <tr
                    key={row.id}
                    className={cn(
                      "cursor-pointer transition-colors hover:bg-muted/40",
                      row.id === selected?.id && "bg-muted/60",
                    )}
                    onClick={() => update({ connection: String(row.id) })}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-heading text-xs font-semibold">
                          {row.comm || "Unknown process"}
                        </span>
                        {row.flags.length > 0 && (
                          <Badge
                            variant="outline"
                            className="border-risk-suspicious/40 font-normal text-risk-suspicious"
                          >
                            <WarningIcon />
                            {row.flags.length}
                          </Badge>
                        )}
                      </div>
                      <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                        {destinationAddress(row)}
                      </div>
                      {row.flags.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-x-2 gap-y-0.5 text-[10px] text-muted-foreground">
                          {row.flags.map((flag) => (
                            <span key={flag}>{flagText[flag]}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-3 text-muted-foreground max-md:hidden">
                      {sensorName(row.sensor_id)}
                    </td>
                    <td className="px-3 py-3 text-right font-mono tnum">{compact(row.connections)}</td>
                    <td
                      className="px-4 py-3 text-right whitespace-nowrap text-muted-foreground"
                      title={new Date(row.last_seen).toLocaleString()}
                    >
                      {ago(row.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <footer className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-[10px] text-muted-foreground">
          <span>
            {filtered.length} of {rows.length} loaded groups · {plural(rows.length, "group")} max 500
          </span>
          <span>refreshes every 10s</span>
        </footer>
      </section>

      <Sheet
        open={Boolean(search.connection)}
        onOpenChange={(open) => {
          if (!open) update({ connection: undefined })
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md">
          {selected ? (
            <ConnectionSheet
              key={selected.id}
              row={selected}
              sensor={sensorName(selected.sensor_id)}
              onClose={() => update({ connection: undefined })}
            />
          ) : (
            <div className="p-5">
              <SheetHeader className="p-0">
                <SheetTitle>Connection unavailable</SheetTitle>
                <SheetDescription>
                  This connection may be outside the last 24 hours or the 500 loaded groups.
                </SheetDescription>
              </SheetHeader>
              <Button size="sm" className="mt-4" onClick={() => update({ connection: undefined })}>
                Close
              </Button>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  )
}

function ConnectionSheet({ row, sensor, onClose }: { row: EgressDest; sensor: string; onClose: () => void }) {
  const fields: [string, string][] = [
    ["Sensor", sensor],
    ["Protocol", "TCP"],
    ["Destination", destinationAddress(row)],
    ["Destination IP", row.dst_ip],
    ["Port", String(row.dst_port)],
    ["Process", row.comm || "Unknown"],
    ["User ID", String(row.uid)],
    ["Last PID", String(row.last_pid)],
    ["First seen", new Date(row.first_seen).toLocaleString()],
    ["Last seen", new Date(row.last_seen).toLocaleString()],
    ["Connections", row.connections.toLocaleString()],
  ]
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(row, null, 2))
      setCopied(true)
      toast.success("Connection record copied")
    } catch {
      toast.error("Could not copy. Open Raw record to select it.")
    }
  }

  return (
    <div className="flex flex-col gap-5 p-5">
      <SheetHeader className="gap-1 p-0 pr-8">
        <p className="label-caps">Connection details</p>
        <SheetTitle className="text-lg">{row.comm || "Unknown process"}</SheetTitle>
        <SheetDescription className="font-mono text-[11px]">{destinationAddress(row)}</SheetDescription>
      </SheetHeader>

      <Tabs defaultValue="details">
        <TabsList className="w-full">
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="raw">Raw record</TabsTrigger>
        </TabsList>
        <TabsContent value="details" className="pt-4">
          <div className="flex flex-col gap-4">
            {row.flags.length > 0 ? (
              <div className="flex flex-col gap-3 border bg-muted/30 p-3">
                {row.flags.map((flag) => (
                  <div key={flag} className="flex gap-2 text-[11px]">
                    <WarningIcon className="mt-0.5 size-3.5 shrink-0 text-risk-suspicious" />
                    <div>
                      <p className="font-medium">{flagText[flag]}</p>
                      <p className="mt-0.5 text-muted-foreground">
                        {flag === "new_destination"
                          ? "This process and user contacted this destination after the sensor's initial one-hour baseline."
                          : "This port is outside the common-port list. That alone does not mean malicious activity."}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="flex items-start gap-2 text-[11px] text-muted-foreground">
                <SealCheckIcon className="mt-0.5 size-3.5 shrink-0 text-risk-benign" />
                No connection rule flagged this record. This is not an AI safety verdict.
              </p>
            )}
            <dl className="divide-y border-t text-[11px]">
              {fields.map(([label, value]) => (
                <div key={label} className="grid grid-cols-[7rem_1fr] gap-3 py-2">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="font-mono break-all">{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </TabsContent>
        <TabsContent value="raw" className="pt-4">
          <pre className="max-h-[55vh] overflow-auto border bg-muted/30 p-3 font-mono text-[10px] leading-relaxed">
            {JSON.stringify(row, null, 2)}
          </pre>
        </TabsContent>
      </Tabs>

      <p className="flex items-start gap-2 text-[10px]/relaxed text-muted-foreground">
        <InfoIcon className="mt-0.5 size-3.5 shrink-0" />
        Aggregated metadata only. URLs, payloads, connection duration and individual connection history are
        not captured. The PID is the most recently observed process ID.
      </p>

      <div className="flex gap-2 border-t pt-4">
        <Button size="sm" variant="outline" onClick={copy}>
          <CopyIcon data-icon="inline-start" />
          {copied ? "Copied" : "Copy record"}
        </Button>
        <Button size="sm" variant="ghost" onClick={onClose}>
          Close
        </Button>
      </div>
    </div>
  )
}
