/** Plain query strings in the URL, not JSON-encoded values. */
export function parseSearch(search: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(search))
}

export function stringifySearch(search: Record<string, unknown>): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(search)) {
    if (value === undefined || value === null || value === "") continue
    params.set(key, typeof value === "boolean" ? (value ? "1" : "0") : String(value))
  }
  const query = params.toString()
  return query ? `?${query}` : ""
}
