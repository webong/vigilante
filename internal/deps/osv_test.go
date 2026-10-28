package deps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOSVLookupUsesExactVersionAndCaches(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var in struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
		}
		if in.Package.Ecosystem != "PyPI" || in.Package.Name != "urllib3" || in.Version != "2.0.5" {
			t.Errorf("unexpected query: %+v", in)
		}
		_, _ = w.Write([]byte(`{"vulns":[{"id":"TEST-1","summary":"example"}]}`))
	}))
	defer server.Close()
	c := &OSVClient{URL: server.URL}
	for i := 0; i < 2; i++ {
		got, err := c.Lookup(context.Background(), "pypi", "urllib3", "2.0.5")
		if err != nil || len(got) != 1 || got[0].URL != "https://osv.dev/vulnerability/TEST-1" {
			t.Fatalf("lookup: %+v, %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected one request, got %d", calls)
	}
}

func TestOSVLookupRejectsUnsupportedEcosystem(t *testing.T) {
	c := &OSVClient{}
	if _, err := c.Lookup(context.Background(), "shared-lib", "/lib/test.so", "test.so"); err == nil {
		t.Fatal("expected unsupported ecosystem error")
	}
}

func TestOSVLookupBatchMapsResultsToDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/query" {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"TEST-1","summary":"full detail"}]}`))
			return
		}
		var in struct {
			Queries []json.RawMessage `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
		}
		if len(in.Queries) != 2 {
			t.Errorf("expected two exact-version queries, got %d", len(in.Queries))
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"TEST-1","modified":"2026-01-01T00:00:00Z"}]},{}]}`))
	}))
	defer server.Close()
	c := &OSVClient{BatchURL: server.URL + "/v1/querybatch", URL: server.URL + "/v1/query"}
	matches, checked, skipped, err := c.LookupBatch(context.Background(), []Module{
		{Ecosystem: "npm", Path: "express", Version: "4.18.2"},
		{Ecosystem: "pypi", Path: "urllib3", Version: "2.0.5"},
		{Ecosystem: "shared-lib", Path: "/lib/x.so", Version: "x.so"},
	})
	if err != nil || checked != 2 || skipped != 1 || len(matches) != 1 || matches[0].Module.Path != "express" || matches[0].Advisories[0].Summary != "full detail" || !matches[0].DetailsComplete {
		t.Fatalf("batch: matches=%+v checked=%d skipped=%d err=%v", matches, checked, skipped, err)
	}
}
