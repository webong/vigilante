import * as React from "react"

type Theme = "dark" | "light" | "system"
type ResolvedTheme = "dark" | "light"

type ThemeProviderProps = {
  children: React.ReactNode
  defaultTheme?: Theme
  storageKey?: string
}

type ThemeProviderState = {
  theme: Theme
  setTheme: (theme: Theme) => void
}

const COLOR_SCHEME_QUERY = "(prefers-color-scheme: dark)"
const THEME_VALUES: Theme[] = ["dark", "light", "system"]

const ThemeProviderContext = React.createContext<ThemeProviderState | undefined>(undefined)

function isTheme(value: string | null): value is Theme {
  return value !== null && THEME_VALUES.includes(value as Theme)
}

function getSystemTheme(): ResolvedTheme {
  return window.matchMedia(COLOR_SCHEME_QUERY).matches ? "dark" : "light"
}

/** Theme changes should not animate every surface in the app. */
function disableTransitionsTemporarily() {
  const style = document.createElement("style")
  style.appendChild(
    document.createTextNode("*,*::before,*::after{transition:none!important;animation:none!important}"),
  )
  document.head.appendChild(style)
  return () => {
    window.getComputedStyle(document.body)
    requestAnimationFrame(() => {
      requestAnimationFrame(() => style.remove())
    })
  }
}

export function ThemeProvider({
  children,
  defaultTheme = "system",
  storageKey = "theme",
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<Theme>(() => {
    try {
      const stored = localStorage.getItem(storageKey)
      return isTheme(stored) ? stored : defaultTheme
    } catch {
      return defaultTheme
    }
  })

  const setTheme = React.useCallback(
    (next: Theme) => {
      try {
        localStorage.setItem(storageKey, next)
      } catch {
        // Appearance still works when storage is unavailable.
      }
      setThemeState(next)
    },
    [storageKey],
  )

  const applyTheme = React.useCallback((next: Theme) => {
    const root = document.documentElement
    const restore = disableTransitionsTemporarily()
    root.classList.remove("light", "dark")
    root.classList.add(next === "system" ? getSystemTheme() : next)
    restore()
  }, [])

  React.useEffect(() => {
    applyTheme(theme)
    if (theme !== "system") return
    const media = window.matchMedia(COLOR_SCHEME_QUERY)
    const onChange = () => applyTheme("system")
    media.addEventListener("change", onChange)
    return () => media.removeEventListener("change", onChange)
  }, [theme, applyTheme])

  return <ThemeProviderContext.Provider value={{ theme, setTheme }}>{children}</ThemeProviderContext.Provider>
}

export function useTheme() {
  const context = React.useContext(ThemeProviderContext)
  if (!context) throw new Error("useTheme must be used inside ThemeProvider")
  return context
}
