import { DesktopIcon, MoonIcon, SunIcon } from "@phosphor-icons/react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useTheme } from "./theme-provider"

const options = [
  { value: "light", label: "Light", icon: SunIcon },
  { value: "dark", label: "Dark", icon: MoonIcon },
  { value: "system", label: "System", icon: DesktopIcon },
] as const

export function ThemeSwitch() {
  const { theme, setTheme } = useTheme()
  const Active = options.find((option) => option.value === theme)?.icon ?? DesktopIcon
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={<Button variant="ghost" size="icon-sm" aria-label={`Appearance: ${theme}`} />}
      >
        <Active />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-36">
        <DropdownMenuGroup>
          <DropdownMenuLabel>Appearance</DropdownMenuLabel>
          {options.map((option) => (
            <DropdownMenuItem key={option.value} onClick={() => setTheme(option.value)}>
              <option.icon />
              <span>{option.label}</span>
              {theme === option.value && <span className="ml-auto text-primary">•</span>}
            </DropdownMenuItem>
          ))}
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
