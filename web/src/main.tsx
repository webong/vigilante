import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createRouter, RouterProvider } from "@tanstack/react-router"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { ApiError } from "@/api"
import { ThemeProvider } from "@/components/theme-provider"
import { Toaster } from "@/components/ui/sonner"
import { parseSearch, stringifySearch } from "@/lib/search"
import { routeTree } from "./routeTree.gen"
import "./index.css"

// Paint the saved appearance before React mounts, so a dark-mode reload does not flash light.
try {
  const saved = localStorage.getItem("lookout-theme")
  const dark = saved === "dark" || (saved !== "light" && matchMedia("(prefers-color-scheme: dark)").matches)
  document.documentElement.classList.add(dark ? "dark" : "light")
} catch {
  // Use the stylesheet's light default when storage is unavailable.
}

const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error) => {
      // A protected query answered 401: the session ended. Start clean at sign-in.
      if (error instanceof ApiError && error.status === 401) {
        queryClient.clear()
        window.location.assign("/login")
      }
    },
  }),
  mutationCache: new MutationCache(),
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
})

const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
  defaultPreloadStaleTime: 0,
  defaultPendingMs: 0,
  defaultPendingMinMs: 0,
  scrollRestoration: true,
  parseSearch,
  stringifySearch,
})

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}

const root = document.getElementById("root")
if (!root) throw new Error("Missing #root element")

createRoot(root).render(
  <StrictMode>
    <ThemeProvider defaultTheme="system" storageKey="lookout-theme">
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
        <Toaster position="bottom-right" />
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
)
