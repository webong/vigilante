import { useMutation, useQueryClient } from "@tanstack/react-query"
import { createFileRoute, redirect, useNavigate, useRouter } from "@tanstack/react-router"
import { type FormEvent, useState } from "react"
import { ApiError, api } from "@/api"
import { Logo } from "@/components/logo"
import { ThemeSwitch } from "@/components/theme-switch"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { sessionQuery } from "@/lib/queries"

export const Route = createFileRoute("/login")({
  beforeLoad: async ({ context }) => {
    const session = await context.queryClient.ensureQueryData(sessionQuery)
    if (session.authenticated) throw redirect({ to: "/visitors" })
  },
  component: LoginPage,
})

function LoginPage() {
  const qc = useQueryClient()
  const router = useRouter()
  const navigate = useNavigate()
  const [token, setToken] = useState("")
  const login = useMutation({
    mutationFn: () => api.login(token),
    onSuccess: async () => {
      qc.setQueryData(sessionQuery.queryKey, { authenticated: true })
      await router.invalidate()
      navigate({ to: "/visitors", replace: true })
    },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (token && !login.isPending) login.mutate()
  }

  return (
    <div className="relative grid min-h-svh place-items-center px-4 py-10">
      <title>Sign in · vigilante</title>
      <div className="absolute top-4 right-4">
        <ThemeSwitch />
      </div>

      <div className="w-full max-w-[340px]">
        <div className="flex justify-center">
          <Logo />
        </div>

        <div className="mt-9">
          <h1 className="font-heading text-xl font-semibold tracking-tight">Sign in</h1>
          <p className="mt-1 text-xs/relaxed text-muted-foreground">
            Use the admin token printed by the server.
          </p>
        </div>

        <form onSubmit={submit} className="mt-6">
          <FieldGroup>
            <Field data-invalid={login.isError}>
              <FieldLabel htmlFor="token">Admin token</FieldLabel>
              <Input
                id="token"
                type="password"
                autoComplete="current-password"
                autoFocus
                spellCheck={false}
                value={token}
                onChange={(event) => setToken(event.target.value)}
                aria-invalid={login.isError}
                placeholder="VIGILANTE_OBS_TOKEN"
                className="h-9 font-mono"
              />
              {login.error ? (
                <FieldDescription className="text-destructive">
                  {login.error instanceof ApiError ? login.error.message : "Could not sign in. Try again."}
                </FieldDescription>
              ) : (
                <FieldDescription>16 characters or more.</FieldDescription>
              )}
            </Field>
          </FieldGroup>
          <Button type="submit" size="lg" className="mt-4 w-full" disabled={!token || login.isPending}>
            {login.isPending ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </div>
    </div>
  )
}
