import { createFileRoute, redirect } from "@tanstack/react-router"
import { AppShell } from "@/components/app-shell"
import { sessionQuery } from "@/lib/queries"

export const Route = createFileRoute("/_app")({
  beforeLoad: async ({ context }) => {
    const session = await context.queryClient.ensureQueryData(sessionQuery)
    if (!session.authenticated) throw redirect({ to: "/login" })
  },
  component: () => <AppShell />,
})
