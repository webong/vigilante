package behavior

import (
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/webong/vigilante/internal/history"
)

func isAsset(f history.Flow) bool {
	switch header(f.Headers, "sec-fetch-dest") {
	case "script", "style", "image", "font", "manifest":
		return true
	}
	switch strings.ToLower(path.Ext(strings.SplitN(f.Path, "?", 2)[0])) {
	case ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webmanifest":
		return true
	}
	return false
}
func isDocument(f history.Flow) bool {
	return f.Method == "GET" && !isAsset(f) && (header(f.Headers, "sec-fetch-dest") == "document" || strings.Contains(header(f.Headers, "accept"), "text/html") || strings.Contains(header(f.Headers, "accept"), "text/markdown"))
}
func browserFamily(ua string) string {
	if !strings.HasPrefix(ua, "Mozilla/5.0") {
		return ""
	}
	lower := strings.ToLower(ua)
	for _, bad := range []string{"bot", "crawl", "spider", "headless", "http"} {
		if strings.Contains(lower, bad) {
			return ""
		}
	}
	if strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/") || strings.Contains(ua, "Edg/") {
		return "chrome"
	}
	if strings.Contains(ua, "Firefox/") {
		return "firefox"
	}
	if strings.Contains(ua, "Safari/") {
		return "safari"
	}
	return ""
}
func automationUA(ua string) string {
	for _, token := range []string{"python-requests", "python-urllib", "aiohttp", "httpx", "curl/", "wget/", "go-http-client", "axios/", "node-fetch", "undici", "okhttp", "java/", "scrapy", "headlesschrome", "puppeteer", "playwright", "selenium", "postmanruntime", "insomnia", "zgrab", "masscan", "nmap", "nikto", "sqlmap", "nuclei", "gobuster", "ffuf", "dirbuster", "wpscan"} {
		if strings.Contains(strings.ToLower(ua), token) {
			return strings.TrimRight(token, "/")
		}
	}
	return ""
}
func timing(gaps []time.Duration) (bool, bool) {
	regular, thinking := 0, 0
	for i, g := range gaps {
		if g < 500*time.Millisecond {
			continue
		}
		if regularTiming(gaps, i, g) {
			regular++
		}
		if i > 0 && g >= 4*gaps[i-1] && g >= 3*time.Second {
			thinking++
		}
	}
	return regular >= 4, thinking >= 2
}
func regularTiming(gaps []time.Duration, i int, g time.Duration) bool {
	if i == 0 {
		return false
	}
	prev := gaps[i-1]
	if prev < 500*time.Millisecond {
		return false
	}
	diff := math.Abs(float64(g - prev))
	return diff < float64((g+prev)/10)
}
func enumeration(flows []history.Flow) (string, int) {
	ids := map[string]map[string]bool{}
	for _, f := range flows {
		segs := strings.Split(strings.SplitN(f.Path, "?", 2)[0], "/")
		var nums []string
		for i, s := range segs {
			if s != "" && strings.Trim(s, "0123456789") == "" {
				nums = append(nums, s)
				segs[i] = "{id}"
			}
		}
		if len(nums) == 0 {
			continue
		}
		tmpl := strings.Join(segs, "/")
		if ids[tmpl] == nil {
			ids[tmpl] = map[string]bool{}
		}
		ids[tmpl][strings.Join(nums, "/")] = true
	}
	best, n := "", 0
	for tmpl, set := range ids {
		if len(set) > n {
			best, n = tmpl, len(set)
		}
	}
	return best, n
}

var attackPattern = regexp.MustCompile(`(?i)(/\.env|/\.git/|/\.aws/|/\.ssh/|/\.htaccess|/\.ds_store|wp-login\.php|/wp-admin|xmlrpc\.php|phpmyadmin|/cgi-bin/|/etc/passwd|\.\./|\.\.\\|union[\s+]+(all[\s+]+)?select|<script|javascript:|/actuator|/server-status|/vendor/phpunit|\.(bak|sql|old|swp)$|/config\.(json|php|ya?ml)$|\$\{jndi:|sleep\(\d+\))`)

func attackHits(flows []history.Flow) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range flows {
		target := f.Path
		if dec, err := url.QueryUnescape(target); err == nil {
			target = dec
		}
		if attackPattern.MatchString(target) {
			p := strings.SplitN(f.Path, "?", 2)[0]
			if !seen[p] && len(out) < 3 {
				seen[p] = true
				if len(p) > 60 {
					p = p[:60]
				}
				out = append(out, p)
			}
		}
	}
	return out
}
func has(signals []Signal, code string) bool {
	return slices.ContainsFunc(signals, func(s Signal) bool { return s.Code == code })
}
func header(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
func claimed(ua string) (string, bool) {
	for _, s := range []string{"bot", "crawler", "spider"} {
		if strings.Contains(strings.ToLower(ua), s) {
			return s, true
		}
	}
	return "", false
}
