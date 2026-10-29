package agent

import (
	"net/url"
	"strings"
)

// indicator is one matched detection family, with the exact evidence that
// triggered it. The built-in detector only reports what it observed: it never
// claims that a dependency is vulnerable or that a code path is reachable.
type indicator struct {
	category        string
	severity        string
	summary         string
	claim           string
	confidence      string
	evidence        []string
	recommendations []string
}

// signature maps a family to the literal markers that identify it. Order is
// priority: the first family with a match wins, and higher-impact families are
// listed first.
type signature struct {
	category string
	severity string
	markers  []string
	claim    string
	// uaOnly restricts the match to the User-Agent. Scanner families belong
	// there: a path like /integrations/nmap-connector is not a scanner.
	uaOnly bool
}

// signatures is intentionally small and literal. It covers the request shapes
// a reverse proxy can actually see (path, query, body preview, user agent)
// without pretending to be a full WAF rule engine; policy rules handle
// deliberate allow/deny decisions.
var signatures = []signature{
	{
		category: "log4shell",
		severity: "critical",
		markers:  []string{"jndi:", "${jndi", "${lower:jndi", "${env:jndi", "${sys:jndi"},
		claim:    "JNDI lookup payload observed (log4shell-style injection)",
	},
	{
		category: "path-traversal",
		severity: "high",
		markers: []string{
			"../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self/environ",
			"win.ini", "boot.ini", "/windows/win.ini",
		},
		claim: "path traversal indicator observed",
	},
	{
		category: "sqli",
		severity: "high",
		markers: []string{
			"union select", "union all select", "' or '", `" or "`,
			"or 1=1", "or '1'='1", "information_schema", "xp_cmdshell",
			"'; drop table", `"; drop table`, "sleep(", "benchmark(",
		},
		claim: "SQL injection indicator observed",
	},
	{
		category: "xss",
		severity: "high",
		markers: []string{
			"<script", "javascript:", "onerror=", "onload=", `"><svg`,
			"<img src=x onerror",
		},
		claim: "cross-site scripting indicator observed",
	},
	{
		category: "ssrf",
		severity: "high",
		markers: []string{
			"169.254.169.254", "metadata.google.internal", "100.100.100.200",
			"gopher://", "dict://", "file:///",
		},
		claim: "server-side request forgery indicator observed",
	},
	{
		category: "scanner",
		severity: "medium",
		markers: []string{
			"sqlmap", "nikto", "nuclei", "nmap", "masscan", "zgrab",
			"gobuster", "dirbuster", "wpscan", "acunetix", "nessus",
			"whatweb", "w3af", "burpsuite", "hydra",
		},
		claim:  "automated scanner signature observed",
		uaOnly: true,
	},
	{
		category: "sensitive-file",
		severity: "medium",
		markers: []string{
			"/.git/", "/.env", "/.aws/", "/.ssh/", "/.svn/", "/.hg/",
			"/wp-config.php", "/phpinfo.php", "/server-status",
			"/actuator/heapdump", "/actuator/env", "/backup.sql",
			"/.ds_store", "/web.config", "/id_rsa",
		},
		claim: "request for a sensitive file observed",
	},
}

// detectIndicator reports the highest-priority family that matches the
// normalized request signals, or nil when nothing matches.
func detectIndicator(env EnrichedEnvelope) *indicator {
	target, ua := detectionSignals(env)
	haystack := target + " " + ua

	for _, sig := range signatures {
		field := haystack
		if sig.uaOnly {
			field = ua
		}
		for _, marker := range sig.markers {
			if !strings.Contains(field, marker) {
				continue
			}
			return &indicator{
				category:        sig.category,
				severity:        sig.severity,
				summary:         summaryFor(sig.category, env),
				claim:           sig.claim,
				confidence:      confidenceFor(sig.category),
				evidence:        []string{"request matched marker " + quoteMarker(marker)},
				recommendations: recommendationsFor(sig.category, env),
			}
		}
	}
	return nil
}

// detectionSignals flattens the request into the two buffers the detector
// inspects. Percent-encoding is decoded twice so double-encoded traversal and
// script payloads are visible, and backslashes are normalized to forward
// slashes so Windows-style traversal matches the same markers.
func detectionSignals(env EnrichedEnvelope) (target, userAgent string) {
	var b strings.Builder
	b.WriteString(normalize(env.Event.Path))
	b.WriteByte(' ')
	b.WriteString(normalize(env.Event.PayloadPreview))
	return strings.ToLower(b.String()), strings.ToLower(headerValue(env.Event.Headers, "User-Agent"))
}

func normalize(s string) string {
	s = strings.ToLower(s)
	for i := 0; i < 2; i++ {
		decoded, err := url.PathUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return strings.ReplaceAll(s, `\`, "/")
}

func headerValue(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func summaryFor(category string, env EnrichedEnvelope) string {
	process := env.ServerProcess.Name
	if process == "" {
		process = "unknown process"
	}
	switch category {
	case "path-traversal":
		return "Path traversal indicator in request to process " + process
	case "sensitive-file":
		return "Request for a sensitive file reached process " + process
	case "scanner":
		return "Automated scanner user agent reached process " + process
	default:
		return strings.ToUpper(category[:1]) + category[1:] + " indicator in request to process " + process
	}
}

func confidenceFor(category string) string {
	switch category {
	case "path-traversal", "sensitive-file":
		return "high"
	case "log4shell", "sqli", "xss", "ssrf":
		return "medium"
	default:
		return "low"
	}
}

func recommendationsFor(category string, env EnrichedEnvelope) []string {
	switch category {
	case "path-traversal":
		return []string{
			"Verify filesystem mount isolation on " + orUnknown(env.OS.Hostname, "the host"),
			"Audit file-serving handlers in module " + orUnknown(env.DependencyGraph.MainModule, "the main module"),
		}
	case "scanner":
		return []string{
			"Confirm the source is authorized to scan; rate-limit or block it at the edge if not",
		}
	case "sensitive-file":
		return []string{
			"Confirm the file is not served by the matched route or a static handler",
		}
	default:
		return []string{
			"Review the matched handler and validate whether the input reached a query or parser sink",
		}
	}
}

func orUnknown(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// quoteMarker renders a marker for evidence without leaking more of the
// request than the matched substring.
func quoteMarker(marker string) string {
	return "'" + marker + "'"
}
