// Package eval measures the built-in detector against a labelled corpus.
//
// Detection quality is a number, not an opinion: the corpus marks every case
// as benign or attack, the detector runs on the same enriched envelope a live
// flow produces, and the report gives recall, precision, false-positive rate,
// and a per-category breakdown. Run it in CI so detector changes cannot
// silently regress.
package eval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/webong/vigilante/ext/agent"
)

// Case is one labelled request in the corpus.
type Case struct {
	ID       string            `json:"id"`
	Class    string            `json:"class"` // "attack" or "benign"
	Category string            `json:"category,omitempty"`
	Method   string            `json:"method,omitempty"`
	Path     string            `json:"path"`
	Query    string            `json:"query,omitempty"`
	Body     string            `json:"body,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Note     string            `json:"note,omitempty"`
}

// Result is one case's outcome.
type Result struct {
	ID        string `json:"id"`
	Class     string `json:"class"`
	Category  string `json:"category,omitempty"`
	Detected  bool   `json:"detected"`
	Indicator string `json:"indicator,omitempty"`
	Severity  string `json:"severity"`
	Action    string `json:"action"`
	Pass      bool   `json:"pass"`
}

// Category aggregates results for one detector family.
type Category struct {
	Attacks           int     `json:"attacks"`
	Detected          int     `json:"detected"`
	Benign            int     `json:"benign"`
	FalsePositives    int     `json:"false_positives"`
	Recall            float64 `json:"recall"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
}

// Report is the eval outcome.
type Report struct {
	Corpus            string               `json:"corpus"`
	Total             int                  `json:"total"`
	Attacks           int                  `json:"attacks"`
	Benign            int                  `json:"benign"`
	TruePositives     int                  `json:"true_positives"`
	FalseNegatives    int                  `json:"false_negatives"`
	FalsePositives    int                  `json:"false_positives"`
	TrueNegatives     int                  `json:"true_negatives"`
	Recall            float64              `json:"recall"`
	Precision         float64              `json:"precision"`
	FalsePositiveRate float64              `json:"false_positive_rate"`
	Accuracy          float64              `json:"accuracy"`
	Categories        map[string]*Category `json:"categories"`
	Results           []Result             `json:"results"`
}

// Load reads a corpus. It accepts JSONL (one object per line, blank lines and
// lines starting with '#' ignored) or a JSON array.
func Load(path string) ([]Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("eval: read %s: %w", path, err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("eval: corpus %s is empty", path)
	}
	if trimmed[0] == '[' {
		var cases []Case
		if err := json.Unmarshal(trimmed, &cases); err != nil {
			return nil, fmt.Errorf("eval: parse %s: %w", path, err)
		}
		return validate(cases)
	}

	var cases []Case
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var c Case
		if err := json.Unmarshal([]byte(text), &c); err != nil {
			return nil, fmt.Errorf("eval: %s:%d: %w", path, line, err)
		}
		cases = append(cases, c)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("eval: read %s: %w", path, err)
	}
	return validate(cases)
}

func validate(cases []Case) ([]Case, error) {
	if len(cases) == 0 {
		return nil, fmt.Errorf("eval: corpus has no cases")
	}
	for i := range cases {
		c := &cases[i]
		if c.ID == "" {
			c.ID = fmt.Sprintf("case-%d", i+1)
		}
		c.Class = strings.ToLower(strings.TrimSpace(c.Class))
		if c.Class != "attack" && c.Class != "benign" {
			return nil, fmt.Errorf("eval: case %q: class must be attack or benign, got %q", c.ID, c.Class)
		}
		if c.Path == "" {
			return nil, fmt.Errorf("eval: case %q: path is required", c.ID)
		}
		if c.Category == "" {
			if c.Class == "benign" {
				c.Category = "benign"
			} else {
				c.Category = "unlabelled"
			}
		}
	}
	return cases, nil
}

// Run loads a corpus and evaluates it.
func Run(ctx context.Context, path string) (Report, error) {
	cases, err := Load(path)
	if err != nil {
		return Report{}, err
	}
	return Evaluate(ctx, path, cases)
}

// Evaluate runs the built-in detector over cases and scores the outcome.
func Evaluate(ctx context.Context, corpus string, cases []Case) (Report, error) {
	rep := Report{Corpus: corpus, Categories: map[string]*Category{}}
	for _, c := range cases {
		env := envelopeFor(c)
		v, err := agent.DefaultBuiltInHandler(ctx, env)
		if err != nil {
			return rep, fmt.Errorf("eval: case %q: %w", c.ID, err)
		}
		detected := v.Action == "alert" || v.Severity == "high" || v.Severity == "critical"

		rep.Total++
		res := Result{
			ID:        c.ID,
			Class:     c.Class,
			Category:  c.Category,
			Detected:  detected,
			Indicator: v.Indicator,
			Severity:  v.Severity,
			Action:    v.Action,
		}

		cat := rep.Categories[c.Category]
		if cat == nil {
			cat = &Category{}
			rep.Categories[c.Category] = cat
		}

		if c.Class == "attack" {
			rep.Attacks++
			cat.Attacks++
			if detected {
				rep.TruePositives++
				cat.Detected++
				res.Pass = true
			} else {
				rep.FalseNegatives++
			}
		} else {
			rep.Benign++
			cat.Benign++
			if detected {
				rep.FalsePositives++
				cat.FalsePositives++
			} else {
				rep.TrueNegatives++
				res.Pass = true
			}
		}
		rep.Results = append(rep.Results, res)
	}

	for _, cat := range rep.Categories {
		if cat.Attacks > 0 {
			cat.Recall = ratio(cat.Detected, cat.Attacks)
		}
		if cat.Benign > 0 {
			cat.FalsePositiveRate = ratio(cat.FalsePositives, cat.Benign)
		}
	}
	rep.Recall = ratio(rep.TruePositives, rep.Attacks)
	rep.Precision = ratio(rep.TruePositives, rep.TruePositives+rep.FalsePositives)
	rep.FalsePositiveRate = ratio(rep.FalsePositives, rep.Benign)
	rep.Accuracy = ratio(rep.TruePositives+rep.TrueNegatives, rep.Total)
	return rep, nil
}

func envelopeFor(c Case) agent.EnrichedEnvelope {
	path := c.Path
	if c.Query != "" {
		path += "?" + c.Query
	}
	method := c.Method
	if method == "" {
		method = "GET"
	}
	return agent.EnrichedEnvelope{
		Event: agent.PacketEvent{
			FlowID:         "eval-" + c.ID,
			Protocol:       "http",
			Method:         method,
			Path:           path,
			Headers:        c.Headers,
			PayloadPreview: c.Body,
			PayloadBytes:   len(c.Body),
		},
		OS:            agent.OSContext{Hostname: "eval"},
		ServerProcess: agent.ServerProcessContext{PID: 1, Name: "eval"},
		TriggerReason: "eval",
	}
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

// Categories returns the per-family metrics sorted by name.
func (r Report) SortedCategories() []string {
	names := make([]string, 0, len(r.Categories))
	for name := range r.Categories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Misses returns the attack cases the detector did not flag.
func (r Report) Misses() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Class == "attack" && !res.Detected {
			out = append(out, res)
		}
	}
	return out
}

// FlaggedBenign returns the benign cases the detector flagged (false positives).
func (r Report) FlaggedBenign() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Class == "benign" && res.Detected {
			out = append(out, res)
		}
	}
	return out
}
