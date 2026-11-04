import {
  CheckIcon,
  CopyIcon,
  DotsThreeIcon,
  HardDrivesIcon,
  PlusIcon,
  TrashIcon,
  WarningIcon,
} from "@phosphor-icons/react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { type FormEvent, useState } from "react"
import { toast } from "sonner"
import { api, type Sensor } from "@/api"
import { PageHeader } from "@/components/page-header"
import { RowsSkeleton } from "@/components/skeletons"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { ago, plural } from "@/lib/format"
import { sensorsQuery } from "@/lib/queries"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/sensors")({
  component: SensorsPage,
})

const online = (sensor: Sensor) =>
  sensor.last_seen_at !== null && Date.now() - new Date(sensor.last_seen_at).getTime() < 30_000

function SensorsPage() {
  const sensors = useQuery(sensorsQuery)
  const [addOpen, setAddOpen] = useState(false)
  const list = sensors.data ?? []
  const live = list.filter(online).length
  const egress = list.filter((sensor) => sensor.egress_since !== null).length

  return (
    <div className="flex flex-col gap-4">
      <title>Sensors · lookout</title>
      <PageHeader
        title="Sensors"
        description="A sensor is a small proxy in front of your app. It records traffic and enforces your decisions."
        meta={
          <span className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground" role="status">
            <span
              className={cn("size-1.5 rounded-full", live > 0 ? "bg-risk-benign" : "bg-muted-foreground/40")}
              aria-hidden
            />
            {sensors.isError ? "status unavailable" : `${live} of ${list.length} live`}
          </span>
        }
        actions={
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <PlusIcon data-icon="inline-start" />
            Add sensor
          </Button>
        }
      />

      <section className="grid grid-cols-3 gap-px bg-border ring-1 ring-border" aria-label="Sensor summary">
        <Stat label="Sensors" value={String(list.length)} sub="registered" />
        <Stat label="Live" value={String(live)} sub="checked in under 30s" />
        <Stat label="Egress" value={String(egress)} sub="capturing TCP" />
      </section>

      {sensors.isPending ? (
        <div className="panel">
          <RowsSkeleton rows={3} />
        </div>
      ) : sensors.isError ? (
        <div className="panel flex flex-col items-start gap-2 p-5">
          <p className="text-xs font-medium">Could not load sensors</p>
          <p className="text-[11px] text-muted-foreground">Check the connection and try again.</p>
          <Button size="sm" variant="outline" onClick={() => sensors.refetch()}>
            Retry
          </Button>
        </div>
      ) : list.length === 0 ? (
        <div className="panel">
          <Empty className="border-0 py-16">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <HardDrivesIcon />
              </EmptyMedia>
              <EmptyTitle>No sensors yet</EmptyTitle>
              <EmptyDescription>
                Create a key, run vigilante in front of your app, and traffic appears within seconds.
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Button size="sm" onClick={() => setAddOpen(true)}>
                <PlusIcon data-icon="inline-start" />
                Add your first sensor
              </Button>
            </EmptyContent>
          </Empty>
        </div>
      ) : (
        <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {list.map((sensor) => (
            <li key={sensor.id}>
              <SensorCard sensor={sensor} />
            </li>
          ))}
        </ul>
      )}

      <AddSensorDialog open={addOpen} onOpenChange={setAddOpen} />
    </div>
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

function SensorCard({ sensor }: { sensor: Sensor }) {
  const qc = useQueryClient()
  const [deleteOpen, setDeleteOpen] = useState(false)
  const isOnline = online(sensor)
  const remove = useMutation({
    mutationFn: () => api.deleteSensor(sensor.id),
    onSuccess: () => {
      toast.success(`${sensor.name} removed`)
      qc.invalidateQueries({ queryKey: sensorsQuery.queryKey })
      setDeleteOpen(false)
    },
    onError: () => toast.error("Could not delete this sensor"),
  })

  return (
    <article className="panel flex h-full flex-col">
      <div className="flex items-start gap-2.5 border-b p-4">
        <span
          className={cn(
            "mt-1.5 size-2 shrink-0 rounded-full",
            isOnline ? "bg-risk-benign" : "bg-muted-foreground/30",
          )}
          aria-hidden
        />
        <div className="min-w-0 flex-1">
          <h2 className="truncate font-heading text-xs font-semibold">{sensor.name}</h2>
          <p className="mt-0.5 text-[10px] text-muted-foreground">
            {isOnline
              ? "online"
              : sensor.last_seen_at
                ? `last seen ${ago(sensor.last_seen_at)}`
                : "never connected"}
          </p>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger
            render={<Button variant="ghost" size="icon-xs" aria-label={`Actions for ${sensor.name}`} />}
          >
            <DotsThreeIcon />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-40">
            <DropdownMenuItem variant="destructive" onClick={() => setDeleteOpen(true)}>
              <TrashIcon />
              Delete sensor
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <dl className="flex flex-1 flex-col gap-2 p-4 text-[11px]">
        <div className="flex items-center justify-between gap-3">
          <dt className="text-muted-foreground">Egress capture</dt>
          <dd>
            {sensor.egress_since ? (
              <Badge variant="outline" className="border-risk-benign/40 font-normal text-risk-benign">
                on
              </Badge>
            ) : (
              <span className="text-muted-foreground">off</span>
            )}
          </dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="text-muted-foreground">Dropped events</dt>
          <dd className={cn("font-mono tnum", sensor.dropped > 0 && "text-risk-suspicious")}>
            {sensor.dropped.toLocaleString()}
          </dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="text-muted-foreground">Registered</dt>
          <dd className="font-mono text-[10px]">{new Date(sensor.created_at).toLocaleDateString()}</dd>
        </div>
        {sensor.dropped > 0 && (
          <p className="mt-1 flex items-start gap-1.5 text-[10px]/relaxed text-risk-suspicious">
            <WarningIcon className="mt-0.5 size-3 shrink-0" />
            The sensor buffer filled under load. Some events were discarded.
          </p>
        )}
      </dl>

      <div className="border-t px-4 py-2.5 text-[10px] text-muted-foreground">
        {sensor.egress_since
          ? `Egress on since ${ago(sensor.egress_since)} · ${plural(sensor.dropped, "event")} dropped`
          : "Inbound HTTP and TLS only"}
      </div>

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {sensor.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              Its key stops working immediately and its requests, actors and outbound records are removed.
              This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel variant="outline" size="sm">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              size="sm"
              variant="destructive"
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {remove.isPending ? "Deleting…" : "Delete sensor"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </article>
  )
}

function AddSensorDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState("")
  const create = useMutation({
    mutationFn: () => api.createSensor(name.trim()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: sensorsQuery.queryKey })
    },
  })
  const reset = () => {
    setName("")
    create.reset()
  }
  const close = (next: boolean) => {
    if (!next) reset()
    onOpenChange(next)
  }
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (name.trim() && !create.isPending) create.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        {create.data ? (
          <>
            <DialogHeader>
              <p className="label-caps">Sensor created</p>
              <DialogTitle>{create.data.sensor.name} is ready to connect</DialogTitle>
              <DialogDescription>
                This key is shown once. Copy the command now; only a hash is stored on the server.
              </DialogDescription>
            </DialogHeader>
            <InstallCommand name={create.data.sensor.name} sensorKey={create.data.key} />
            <DialogFooter>
              <Button size="sm" onClick={() => close(false)}>
                Done
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={submit}>
            <DialogHeader>
              <p className="label-caps">New sensor</p>
              <DialogTitle>Add a sensor</DialogTitle>
              <DialogDescription>
                Name it after the machine or service it protects. You will get a key and a ready-to-run
                command.
              </DialogDescription>
            </DialogHeader>
            <FieldGroup className="py-4">
              <Field>
                <FieldLabel htmlFor="sensor-name">Sensor name</FieldLabel>
                <Input
                  id="sensor-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="e.g. web-1"
                  maxLength={80}
                  autoFocus
                  className="h-8"
                />
                <FieldDescription>Only letters, numbers and dashes read best in the list.</FieldDescription>
              </Field>
            </FieldGroup>
            {create.error && (
              <p role="alert" className="mb-3 text-[11px] text-destructive">
                {create.error instanceof Error ? create.error.message : "Could not create the sensor."}
              </p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" size="sm" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" disabled={!name.trim() || create.isPending}>
                {create.isPending ? "Creating…" : "Create key"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

function InstallCommand({ name, sensorKey }: { name: string; sensorKey: string }) {
  const [copied, setCopied] = useState(false)
  const command = [
    `VIGILANTE_OBS_TOKEN=${sensorKey} \\`,
    "vigilante \\",
    `  -server ${location.origin} \\`,
    "  -upstream http://127.0.0.1:3000 \\",
    "  -listen :443 -domain your-site.example \\",
    "  -egress",
  ].join("\n")

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      toast.success("Install command copied")
    } catch {
      toast.error("Could not copy. Select the command and copy it manually.")
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="border bg-muted/30">
        <div className="flex items-center justify-between border-b px-3 py-2">
          <span className="font-mono text-[10px] text-muted-foreground">{name} · install</span>
          <Button size="xs" variant="ghost" onClick={copy}>
            {copied ? <CheckIcon data-icon="inline-start" /> : <CopyIcon data-icon="inline-start" />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
        <pre className="overflow-x-auto p-3 font-mono text-[10px]/relaxed">{command}</pre>
      </div>
      <p className="text-[10px]/relaxed text-muted-foreground">
        Set <code className="font-mono">-upstream</code> to your app and{" "}
        <code className="font-mono">-domain</code> for a Let's Encrypt certificate (or pass{" "}
        <code className="font-mono">-tls-cert</code>/<code className="font-mono">-tls-key</code>). Behind a
        CDN, add <code className="font-mono">-trust-proxy</code> with its ranges.{" "}
        <code className="font-mono">-egress</code> needs root or CAP_BPF.
      </p>
    </div>
  )
}
