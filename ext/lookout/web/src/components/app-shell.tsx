import { SignOutIcon } from "@phosphor-icons/react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link, Outlet, useNavigate, useRouter } from "@tanstack/react-router"
import { type ReactNode, useState } from "react"
import { api } from "@/api"
import { Logo } from "@/components/logo"
import { ThemeSwitch } from "@/components/theme-switch"
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
import { Button } from "@/components/ui/button"
import { overviewQuery, sensorsQuery, sessionQuery } from "@/lib/queries"
import { cn } from "@/lib/utils"

const nav = [
  { to: "/visitors", label: "Visitors" },
  { to: "/outbound", label: "Outbound" },
  { to: "/review", label: "Review" },
  { to: "/sensors", label: "Sensors" },
] as const

export function AppShell({ children }: { children?: ReactNode }) {
  const overview = useQuery(overviewQuery)
  const sensors = useQuery(sensorsQuery)
  const qc = useQueryClient()
  const router = useRouter()
  const navigate = useNavigate()
  const [signOutOpen, setSignOutOpen] = useState(false)

  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: async () => {
      await qc.cancelQueries()
      qc.clear()
      qc.setQueryData(sessionQuery.queryKey, { authenticated: false })
      await router.invalidate()
      navigate({ to: "/login", replace: true })
    },
  })

  const pending = overview.data?.stats.pending_decisions ?? 0
  const flagged = overview.data?.stats.flagged_egress ?? 0
  const online =
    sensors.data?.filter(
      (sensor) => sensor.last_seen_at && Date.now() - new Date(sensor.last_seen_at).getTime() < 30_000,
    ).length ?? 0
  const counts: Record<string, number> = { "/review": pending, "/outbound": flagged }

  return (
    <div className="min-h-svh">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:bg-background focus:px-3 focus:py-2 focus:text-xs focus:ring-1 focus:ring-border"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-30 border-b bg-background/90 backdrop-blur-sm">
        <div className="mx-auto flex h-12 max-w-[1440px] items-center gap-5 px-4 sm:px-6">
          <Link to="/visitors" aria-label="lookout home" className="shrink-0">
            <Logo />
          </Link>
          <NavLinks counts={counts} className="hidden h-full sm:flex" />
          <div className="ml-auto flex shrink-0 items-center gap-2">
            <span
              className="hidden items-center gap-1.5 text-[11px] text-muted-foreground sm:inline-flex"
              title="Sensors that checked in in the last 30 seconds"
            >
              <span
                className={cn(
                  "size-1.5 rounded-full",
                  online > 0
                    ? "bg-risk-benign"
                    : sensors.isError
                      ? "bg-destructive"
                      : "bg-muted-foreground/40",
                )}
                aria-hidden
              />
              {sensors.isError ? "status unknown" : `${online} sensor${online === 1 ? "" : "s"} live`}
            </span>
            <span className="hidden h-4 w-px bg-border sm:block" aria-hidden />
            <ThemeSwitch />
            <Button variant="ghost" size="icon-sm" aria-label="Sign out" onClick={() => setSignOutOpen(true)}>
              <SignOutIcon />
            </Button>
          </div>
        </div>
        <NavLinks counts={counts} className="h-10 border-t px-3 sm:hidden" />
      </header>
      <main id="main" className="mx-auto max-w-[1440px] px-4 py-5 sm:px-6 sm:py-6">
        {children ?? <Outlet />}
      </main>

      <AlertDialog open={signOutOpen} onOpenChange={setSignOutOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Sign out of vigilante?</AlertDialogTitle>
            <AlertDialogDescription>
              You will need the admin token to sign back in. Sensors keep running and enforcing decisions.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel variant="outline" size="sm">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction size="sm" disabled={logout.isPending} onClick={() => logout.mutate()}>
              {logout.isPending ? "Signing out…" : "Sign out"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function NavLinks({ counts, className }: { counts: Record<string, number>; className?: string }) {
  return (
    <nav aria-label="Sections" className={cn("items-stretch gap-0.5 overflow-x-auto", className)}>
      {nav.map((item) => {
        const count = counts[item.to] ?? 0
        return (
          <Link
            key={item.to}
            to={item.to}
            className={cn(
              "relative inline-flex items-center gap-1.5 px-2.5 text-xs whitespace-nowrap text-muted-foreground transition-colors hover:text-foreground",
              "after:absolute after:inset-x-2.5 after:bottom-0 after:h-px after:bg-transparent",
              "data-[status=active]:text-foreground data-[status=active]:after:bg-primary",
            )}
          >
            {item.label}
            {count > 0 && (
              <span className="min-w-4 bg-muted px-1 text-center font-mono text-[10px] leading-4 font-medium text-foreground tnum">
                {count > 99 ? "99+" : count}
              </span>
            )}
          </Link>
        )
      })}
    </nav>
  )
}
