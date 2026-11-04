package lookout

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/pkg/ext-go/engine/transport/jsonline"
)

//go:embed all:web/dist
var dist embed.FS

// UI is the built console, rooted at index.html. Empty until `bun run build`
// in ext/lookout/web.
func UI() fs.FS {
	sub, _ := fs.Sub(dist, "web/dist/app")
	return sub
}

// Options configures the guest.
type Options struct {
	// Token is the operator token. Empty disables every authenticated route,
	// including login.
	Token string
}

// operator labels console-initiated actions in the host's audit trail.
const operator = "lookout/operator"

// Console is the guest's HTTP application.
type Console struct {
	token string
	host  Host
	ui    fs.FS
}

// NewConsole returns the console over host. Inside the guest host is the
// reverse-call client; tests may pass a CoreHost directly.
func NewConsole(opts Options, host Host) *Console {
	return &Console{token: opts.Token, host: host, ui: UI()}
}

func (e *Console) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if rest, ok := strings.CutPrefix(path, "api/"); ok {
		e.dashboardAPI(w, r, rest)
		return
	}
	e.serveSPA(w, r, path)
}

// serveSPA serves the built UI. Paths that are not files fall back to
// index.html so client-side routes survive a reload.
func (e *Console) serveSPA(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if path != "" {
		if data, err := fs.ReadFile(e.ui, path); err == nil {
			if strings.HasPrefix(path, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeContent(w, r, path, time.Time{}, bytes.NewReader(data))
			return
		}
	}
	index, err := fs.ReadFile(e.ui, "index.html")
	if err != nil {
		fail(w, http.StatusNotFound, "console not built: run `bun run build` in ext/lookout/web")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
}

// BuildGuest constructs the lookout ext.plugin/v1 guest. It declares
// vigilante.console@v1 as the reverse contract it calls.
func BuildGuest(opts Options) (engine.Descriptor, *engine.Guest, error) {
	console := NewConsole(opts, reverseHost{})
	reg, err := author.New(GuestIdentity())
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, ServeHTTPMethod(), func(ctx context.Context, _ engine.Request, in HTTPRequest) (HTTPResponse, error) {
		return serveOne(ctx, console, in)
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	desc, guestOpts, err := reg.Snapshot(author.Options{
		Authorize:       func(context.Context, engine.Request) error { return nil },
		MaxCallDuration: 2 * time.Minute, // actor triage calls a model
	})
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	desc.Reverse = []engine.Contract{{
		ContractRef: engine.ContractRef{Name: ConsoleContractName, Version: ConsoleContractVersion},
		Operations:  consoleOperations(),
	}}
	guest, err := engine.NewGuest(desc, guestOpts)
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	return desc, guest, nil
}

// ServeConn runs the guest out of process over conn.
func ServeConn(ctx context.Context, conn io.ReadWriteCloser, opts Options) error {
	_, guest, err := BuildGuest(opts)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return jsonline.ServeGuest(ctx, conn, guest)
}

// serveOne runs one forwarded request through the console.
func serveOne(ctx context.Context, h http.Handler, in HTTPRequest) (HTTPResponse, error) {
	if !strings.HasPrefix(in.Path, "/") {
		return HTTPResponse{Status: http.StatusBadRequest}, nil
	}
	u := &url.URL{Path: in.Path, RawQuery: in.Query}
	r, err := http.NewRequestWithContext(ctx, in.Method, u.String(), bytes.NewReader(in.Body))
	if err != nil {
		return HTTPResponse{Status: http.StatusBadRequest}, nil
	}
	for k, v := range in.Headers {
		r.Header.Set(k, v)
	}
	if in.TLS {
		r.TLS = &tls.ConnectionState{}
	}
	rec := &recorder{header: http.Header{}}
	h.ServeHTTP(rec, r)
	out := HTTPResponse{Status: rec.status, Body: rec.body.Bytes()}
	if out.Status == 0 {
		out.Status = http.StatusOK
	}
	for k, v := range rec.header {
		if out.Headers == nil {
			out.Headers = map[string]string{}
		}
		out.Headers[k] = strings.Join(v, ", ")
	}
	// Set-Cookie must not be comma-joined; the console sets at most one.
	if c := rec.header.Values("Set-Cookie"); len(c) > 0 {
		out.Headers["Set-Cookie"] = c[len(c)-1]
	}
	return out, nil
}

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func extensionJSON(w http.ResponseWriter, v any, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
			status = http.StatusNotFound
		}
		fail(w, status, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func queryLimit(r *http.Request) int {
	limit := 100
	_, _ = fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	return limit
}
