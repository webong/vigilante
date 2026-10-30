import type { ActorClass, EnforcementKind, RiskBand } from "@/api"

const compactFmt = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 })

export const compact = (n: number) => compactFmt.format(n)

function span(ms: number): string {
  const s = Math.round(Math.abs(ms) / 1000)
  if (s < 60) return `${s}s`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.round(m / 60)
  if (h < 48) return `${h}h`
  return `${Math.round(h / 24)}d`
}

export const ago = (iso: string) => {
  const ms = Date.now() - new Date(iso).getTime()
  return ms < 5000 ? "just now" : `${span(ms)} ago`
}

export const until = (iso: string) => `in ${span(new Date(iso).getTime() - Date.now())}`

export const clock = (iso: string) =>
  new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })

/** Short form: "90m", "6h", "1d". */
export const minutes = (m: number) =>
  m % 1440 === 0 ? `${m / 1440}d` : m % 60 === 0 ? `${m / 60}h` : `${m}m`

/** Long form for sentences: "6 hours", "1 day". */
export const duration = (m: number) => {
  const [n, unit] = m % 1440 === 0 ? [m / 1440, "day"] : m % 60 === 0 ? [m / 60, "hour"] : [m, "minute"]
  return `${n} ${unit}${n === 1 ? "" : "s"}`
}

export const plural = (n: number, word: string) => `${compact(n)} ${word}${n === 1 ? "" : "s"}`

export const classLabel: Record<ActorClass, string> = {
  impersonator: "Impersonator",
  scanner: "Scanner",
  verified_bot: "Verified bot",
  ai_agent: "AI agent",
  automation: "Automation",
  crawler: "Crawler",
  browser: "Browser",
  unknown: "Unknown",
}

/** One plain sentence per class, for people who don't live in this vocabulary. */
export const classMeaning: Record<ActorClass, string> = {
  impersonator: "Claims to be a known bot, but the claim failed verification.",
  scanner: "Probes for vulnerabilities or known weak spots.",
  verified_bot: "A bot whose identity was proven by reverse DNS or a signature.",
  ai_agent: "An AI agent or LLM tool reading your pages.",
  automation: "A script or headless browser, often pretending to be a person.",
  crawler: "A declared crawler that is not verified.",
  browser: "Looks like a person in a real browser.",
  unknown: "Not enough evidence yet.",
}

export const kindLabel: Record<EnforcementKind, string> = {
  block: "Block",
  challenge: "Challenge",
  rate_limit: "Rate limit",
}

export const kindEffect: Record<EnforcementKind, string> = {
  block: "Every request gets 403.",
  challenge:
    "Shows a browser check first. Real browsers pass in about a second; scripts and default headless browsers can't.",
  rate_limit: "Allows a set number of requests a minute, then answers 429.",
}

export const bandLabel: Record<RiskBand, string> = {
  hostile: "Hostile",
  suspicious: "Suspicious",
  watch: "Watch",
  benign: "Benign",
}

export const bands: RiskBand[] = ["hostile", "suspicious", "watch", "benign"]

export const riskBand = (risk: number): RiskBand =>
  risk >= 80 ? "hostile" : risk >= 50 ? "suspicious" : risk >= 20 ? "watch" : "benign"

export const bandRange: Record<RiskBand, string> = {
  hostile: "80–100",
  suspicious: "50–79",
  watch: "20–49",
  benign: "0–19",
}

export const shortJA4 = (ja4: string) => (ja4 ? ja4.split("_")[0] : "no TLS")

/** Model ids read better without the vendor prefix: "deepseek/deepseek-v4.1-flash" → "deepseek-v4.1-flash". */
export const modelName = (model: string) => model.slice(model.lastIndexOf("/") + 1)

const knownAgents =
  /(Googlebot|bingbot|Applebot|YandexBot|Baiduspider|DuckDuckBot|GPTBot|OAI-SearchBot|ChatGPT-User|ClaudeBot|Claude-User|Claude-SearchBot|PerplexityBot|Perplexity-User|Bytespider|CCBot|Amazonbot|meta-externalagent|HeadlessChrome)/i
const browsers: [RegExp, string][] = [
  [/Edg\//, "Edge"],
  [/Firefox\//, "Firefox"],
  [/CriOS\/|Chrome\//, "Chrome"],
  [/Safari\//, "Safari"],
]
const boilerplate = new Set(["Mozilla", "AppleWebKit", "KHTML", "Gecko", "Version", "Mobile"])
const platforms: [RegExp, string][] = [
  [/iPhone/, "iPhone"],
  [/iPad/, "iPad"],
  [/Android/, "Android"],
  [/Mac OS X/, "Mac"],
  [/Windows/, "Windows"],
  [/Linux/, "Linux"],
]

/**
 * A readable name for what a client *says* it is, from its User-Agent:
 * "Googlebot", "python-requests", "Chrome on Mac". The class says what
 * lookout thinks it really is.
 */
export function claimedName(ua: string): string {
  if (!ua) return "No user agent"
  const agent = ua.match(knownAgents)?.[1]
  if (agent) return agent.toLowerCase() === "headlesschrome" ? "Headless Chrome" : agent
  const compatible = ua.match(/\(compatible; ([^;/)]+)/)?.[1]
  if (compatible) return compatible.trim()
  const browser = browsers.find(([re]) => re.test(ua))?.[1]
  if (browser) {
    const platform = platforms.find(([re]) => re.test(ua))?.[1]
    return platform ? `${browser} on ${platform}` : browser
  }
  // Otherwise the first product token that isn't browser boilerplate: "Mozilla/5.0 zgrab/0.x" → "zgrab".
  const product = [...ua.matchAll(/([A-Za-z][\w.-]*)\//g)]
    .map((m) => m[1] ?? "")
    .find((t) => !boilerplate.has(t))
  return product || ua
}
