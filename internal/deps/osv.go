package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OSVClient looks up advisories for an exact package version. It is called on
// demand by an agent, never while building the process inventory.
type OSVClient struct {
	HTTPClient *http.Client
	URL        string
	BatchURL   string
	mu         sync.Mutex
	cache      map[string]cachedOSV
}

type cachedOSV struct {
	advisories []OSVAdvisory
	expires    time.Time
}

// OSVAdvisory preserves the source's claims so an agent can assess applicability
// rather than treating a package match as proof of exploitability.
type OSVAdvisory struct {
	ID         string            `json:"id"`
	Aliases    []string          `json:"aliases,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Details    string            `json:"details,omitempty"`
	Modified   string            `json:"modified,omitempty"`
	Affected   []json.RawMessage `json:"affected,omitempty"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references,omitempty"`
	URL string `json:"url"`
}

type BatchMatch struct {
	Module          Module
	Advisories      []OSVAdvisory
	DetailsComplete bool
}

// LookupBatch checks exact dependency versions in one OSV request. It returns
// advisory candidates, never a claim that traffic exercised vulnerable code.
func (c *OSVClient) LookupBatch(ctx context.Context, modules []Module) ([]BatchMatch, int, int, error) {
	type query struct {
		Package map[string]string `json:"package"`
		Version string            `json:"version"`
	}
	queries := make([]query, 0, min(len(modules), 256))
	selected := make([]Module, 0, cap(queries))
	skipped := 0
	for _, m := range modules {
		ecosystem := osvEcosystem(m.Ecosystem)
		if ecosystem == "" || m.Path == "" || m.Version == "" || strings.ContainsAny(m.Version[:1], "^~<>=") || len(selected) >= 256 {
			skipped++
			continue
		}
		queries = append(queries, query{Package: map[string]string{"ecosystem": ecosystem, "name": m.Path}, Version: m.Version})
		selected = append(selected, m)
	}
	if len(queries) == 0 {
		return nil, 0, skipped, nil
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, 0, skipped, err
	}
	endpoint := c.BatchURL
	if endpoint == "" {
		endpoint = "https://api.osv.dev/v1/querybatch"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, skipped, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, 0, skipped, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, skipped, fmt.Errorf("OSV batch returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Results []struct {
			Vulns         []OSVAdvisory `json:"vulns"`
			NextPageToken string        `json:"next_page_token"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		return nil, 0, skipped, fmt.Errorf("decode OSV batch: %w", err)
	}
	if len(result.Results) != len(selected) {
		return nil, 0, skipped, fmt.Errorf("OSV batch returned %d results for %d queries", len(result.Results), len(selected))
	}
	var matches []BatchMatch
	for i, item := range result.Results {
		if item.NextPageToken != "" {
			return nil, 0, skipped, fmt.Errorf("OSV batch results are paginated")
		}
		if len(item.Vulns) == 0 {
			continue
		}
		for j := range item.Vulns {
			item.Vulns[j].URL = "https://osv.dev/vulnerability/" + item.Vulns[j].ID
		}
		matches = append(matches, BatchMatch{Module: selected[i], Advisories: item.Vulns})
	}
	for i := range matches {
		if i >= 8 || ctx.Err() != nil {
			break
		}
		full, err := c.Lookup(ctx, matches[i].Module.Ecosystem, matches[i].Module.Path, matches[i].Module.Version)
		if err == nil && len(full) > 0 {
			matches[i].Advisories = full
			matches[i].DetailsComplete = true
		}
	}
	return matches, len(selected), skipped, nil
}

func (c *OSVClient) Lookup(ctx context.Context, ecosystem, name, version string) ([]OSVAdvisory, error) {
	ecosystem = strings.TrimSpace(ecosystem)
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil, fmt.Errorf("package name and version are required")
	}
	originalEcosystem := ecosystem
	ecosystem = osvEcosystem(ecosystem)
	if ecosystem == "" {
		return nil, fmt.Errorf("unsupported ecosystem %q", originalEcosystem)
	}
	key := ecosystem + "\x00" + name + "\x00" + version
	c.mu.Lock()
	if entry, ok := c.cache[key]; ok && time.Now().Before(entry.expires) {
		out := append([]OSVAdvisory(nil), entry.advisories...)
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()
	body, err := json.Marshal(map[string]any{
		"package": map[string]string{"ecosystem": ecosystem, "name": name},
		"version": version,
	})
	if err != nil {
		return nil, err
	}
	endpoint := c.URL
	if endpoint == "" {
		endpoint = "https://api.osv.dev/v1/query"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Vulns         []OSVAdvisory `json:"vulns"`
		NextPageToken string        `json:"next_page_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	if result.NextPageToken != "" {
		return nil, fmt.Errorf("OSV response is paginated; advisory results are incomplete")
	}
	for i := range result.Vulns {
		result.Vulns[i].URL = "https://osv.dev/vulnerability/" + result.Vulns[i].ID
		// Keep reverse-call responses bounded even for long advisory records.
		if len(result.Vulns[i].Details) > 2048 {
			result.Vulns[i].Details = result.Vulns[i].Details[:2048]
		}
	}
	c.mu.Lock()
	if c.cache == nil {
		c.cache = make(map[string]cachedOSV)
	}
	if len(c.cache) >= 1024 {
		for key, entry := range c.cache {
			if time.Now().After(entry.expires) {
				delete(c.cache, key)
			}
		}
		if len(c.cache) >= 1024 {
			c.cache = make(map[string]cachedOSV)
		}
	}
	c.cache[key] = cachedOSV{advisories: append([]OSVAdvisory(nil), result.Vulns...), expires: time.Now().Add(15 * time.Minute)}
	c.mu.Unlock()
	return result.Vulns, nil
}

func (c *OSVClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 4 * time.Second}
}

func osvEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "go":
		return "Go"
	case "npm":
		return "npm"
	case "cargo", "crates.io":
		return "crates.io"
	case "pypi":
		return "PyPI"
	default:
		return ""
	}
}
