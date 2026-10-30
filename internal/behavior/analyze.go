// Package behavior classifies actors from their retained request history.
// It is independent of storage, identity verification, and enforcement.
package behavior

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/identity"
)

type Signal struct {
	Code   string `json:"code"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
}
type Result struct {
	Score    int             `json:"score"`
	Class    string          `json:"class"`
	Signals  []Signal        `json:"signals"`
	Identity identity.Result `json:"identity"`
}

func Analyze(flows []history.Flow, id identity.Result) Result {
	if len(flows) == 0 {
		return Result{Class: "unknown", Identity: id}
	}
	var signals []Signal
	add := func(code string, weight int, detail string) { signals = append(signals, Signal{code, weight, detail}) }
	last := flows[len(flows)-1]
	ua := last.UserAgent
	browser := browserFamily(ua)
	fp := last.TLSFingerprint
	docs, assets, bursts, non200, webdriver := 0, 0, 0, 0, 0
	var gaps []time.Duration
	for i, f := range flows {
		if isDocument(f) {
			docs++
		}
		if isAsset(f) {
			assets++
		}
		if f.Status >= 400 {
			non200++
		}
		if f.Headers["webdriver"] == "1" {
			webdriver++
		}
		if i > 0 {
			gap := f.Timestamp.Sub(flows[i-1].Timestamp)
			if gap <= 5*time.Minute {
				gaps = append(gaps, gap)
				if gap < 500*time.Millisecond {
					bursts++
				}
			}
		}
	}
	if id.Failed != "" {
		add("failed_identity", 80, id.Failed)
	} else if id.Verified != "" {
		add("verified_identity", 0, "Identity verified: "+id.Verified)
	}
	if webdriver > 0 {
		add("webdriver", 70, "A browser challenge reported navigator.webdriver")
	}
	if browser != "" {
		if fp != "" && strings.HasPrefix(fp, "t13") && !strings.Contains(fp, "h2") {
			add("ua_tls_mismatch", 20, "Claims to be a browser but its TLS ClientHello advertises no HTTP/2")
		}
		fetch := header(last.Headers, "sec-fetch-mode") != ""
		lang := header(last.Headers, "accept-language") != ""
		if !fetch && !lang && docs >= 3 {
			add("missing_fetch_metadata", 15, "Claims to be a browser but sends no fetch metadata or Accept-Language")
		}
	}
	if docs >= 3 && assets == 0 && bursts < len(flows)/2 {
		add("no_assets", 10, fmt.Sprintf("%d documents fetched with no JS, CSS, image or font requests", docs))
	}
	if strings.Contains(strings.ToLower(header(last.Headers, "accept")), "text/markdown") {
		add("accepts_markdown", 15, "Requests text/markdown, a common AI-agent preference")
	}
	if len(gaps) >= 5 {
		regular, thinking := timing(gaps)
		if regular {
			add("machine_timing", 15, "Requests arrive at clockwork intervals")
		}
		if thinking && docs >= 3 {
			add("llm_pacing", 10, "Alternates short bursts with irregular pauses between page reads")
		}
	}
	if tmpl, n := enumeration(flows); n >= 10 {
		add("id_enumeration", 30, fmt.Sprintf("Walked %d different IDs under %s", n, tmpl))
	}
	if tool := automationUA(ua); tool != "" {
		add("automation_ua", 15, "User agent announces "+tool)
	}
	if slices.ContainsFunc([]string{"zgrab", "masscan", "nmap", "nikto", "sqlmap", "nuclei", "gobuster", "ffuf"}, func(s string) bool { return strings.Contains(strings.ToLower(ua), s) }) {
		add("scanner_ua", 80, "User agent announces a vulnerability scanner")
	}
	if hits := attackHits(flows); len(hits) > 0 {
		add("attack_probes", 35, "Probed "+strings.Join(hits, ", "))
	}
	if non200 >= 5 && non200*2 >= len(flows) {
		add("mostly_errors", 15, fmt.Sprintf("%d/%d requests returned an error", non200, len(flows)))
	}
	score := 0
	for _, s := range signals {
		score += s.Weight
	}
	class := "unknown"
	if browser != "" {
		class = "browser"
	}
	_, claimed := claimed(ua)
	automation := has(signals, "automation_ua") || has(signals, "no_assets") || has(signals, "webdriver")
	switch {
	case id.Failed != "" || has(signals, "webdriver"):
		class = "impersonator"
	case has(signals, "scanner_ua") || has(signals, "attack_probes"):
		class = "scanner"
	case id.Verified != "":
		class = "verified_bot"
		score = 5
	case identity.IsAI(ua):
		class = "ai_agent"
	case has(signals, "accepts_markdown") || has(signals, "llm_pacing"):
		class = "ai_agent"
	case claimed && automation:
		class = "crawler"
	case automation:
		class = "automation"
	}
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].Weight > signals[j].Weight })
	return Result{Score: score, Class: class, Signals: signals, Identity: id}
}
