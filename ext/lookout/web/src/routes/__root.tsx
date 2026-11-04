import type { QueryClient } from "@tanstack/react-query"
import { createRootRouteWithContext, Outlet } from "@tanstack/react-router"
import { TooltipProvider } from "@/components/ui/tooltip"

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: Root,
  notFoundComponent: () => (
    <div className="grid min-h-svh place-items-center p-6 text-center">
      <div>
        <p className="font-mono text-xs tracking-widest text-muted-foreground uppercase">404</p>
        <h1 className="mt-2 font-heading text-lg font-semibold">This page is outside the perimeter.</h1>
        <a href="/visitors" className="mt-4 inline-block text-xs text-primary underline underline-offset-4">
          Back to visitors
        </a>
      </div>
    </div>
  ),
})

function Root() {
  return (
    <TooltipProvider>
      <Outlet />
    </TooltipProvider>
  )
}
