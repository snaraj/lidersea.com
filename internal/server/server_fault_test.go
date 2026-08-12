// Fault-path and hardening tests drive the handler through hand-written deep
// fakes — an instrumented filesystem that records calls and injects failures —
// proving behavior the happy-path suite and the real bundle can never reach:
// the fail-closed 500 branch, the read-once construction contract, and
// terminal rejection of ambiguous request paths. Everything here is standard
// library only and is written to be portable verbatim to naranjo.online.
package server

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// faultFS is a deep mock around an in-memory filesystem: it records every
// ReadFile call for later verification and injects per-path read errors after
// a successful Open/Stat. fstest.MapFS alone can never fail between Stat and
// read, so this seam is the only way to exercise the handler's 500 branch.
type faultFS struct {
	files    fstest.MapFS
	readErrs map[string]error

	mu    sync.Mutex
	reads []string
}

// Open serves metadata from the healthy in-memory files so Stat succeeds even
// for paths whose reads are configured to fail.
func (f *faultFS) Open(name string) (fs.File, error) { return f.files.Open(name) }

// ReadFile records the call, then either injects the configured fault or
// delegates to the in-memory data.
func (f *faultFS) ReadFile(name string) ([]byte, error) {
	f.mu.Lock()
	f.reads = append(f.reads, name)
	f.mu.Unlock()
	if err, ok := f.readErrs[name]; ok {
		return nil, err
	}
	return f.files.ReadFile(name)
}

// readsOf counts recorded reads of one path under the recording lock so
// assertions never race the handler.
func (f *faultFS) readsOf(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, read := range f.reads {
		if read == name {
			count++
		}
	}
	return count
}

// TestReadFailureAfterStatIsFailClosed forces the gap between a successful
// Stat and a failed read — a torn image or filesystem fault — and requires an
// opaque 500 that never leaks the internal error while still carrying the
// full security-header baseline, because securityHeaders wraps every
// response, including failures.
func TestReadFailureAfterStatIsFailClosed(t *testing.T) {
	t.Parallel()
	fsys := &faultFS{
		files:    testsupport.FrontendFS(),
		readErrs: map[string]error{"assets/app-abc123.js": errors.New("injected read fault")},
	}
	siteHandler, err := New(fsys)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Edge-declared TLS like a real visitor hitting the broken asset: even
	// the fail-closed 500 must carry the full baseline, HSTS included.
	faultRequest := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
	faultRequest.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	siteHandler.ServeHTTP(response, faultRequest)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if body := response.Body.String(); strings.Contains(body, "injected read fault") {
		t.Errorf("500 body leaks internal error detail: %q", body)
	}
	for _, header := range []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
	} {
		if response.Header().Get(header) == "" {
			t.Errorf("500 response missing %s", header)
		}
	}
	if got := fsys.readsOf("assets/app-abc123.js"); got != 1 {
		t.Errorf("failing asset read %d times, want exactly 1", got)
	}
}

// TestIndexReadOnceAtConstruction verifies the availability contract that a
// broken bundle fails during New — before Kubernetes can route traffic to the
// pod — rather than on a visitor's first request: the entrypoint is read
// exactly once at construction and never again while serving.
func TestIndexReadOnceAtConstruction(t *testing.T) {
	t.Parallel()
	fsys := &faultFS{files: testsupport.FrontendFS()}
	siteHandler, err := New(fsys)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := fsys.readsOf("index.html"); got != 1 {
		t.Fatalf("index.html read %d times during construction, want 1", got)
	}
	for range 3 {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("root status = %d", response.Code)
		}
	}
	if got := fsys.readsOf("index.html"); got != 1 {
		t.Errorf("index.html read %d times after serving, want still 1", got)
	}
}

// TestAmbiguousPathsAreTerminalNotFound pins the pre-router guard shared with
// naranjo.online: traversal, dot segments, duplicate separators, trailing
// slashes, backslashes, and NUL bytes are answered with a terminal 404 and
// are never redirect-canonicalized onto a different route. Targets are
// assigned to URL.Path directly because several are deliberately not
// parseable request URLs.
func TestAmbiguousPathsAreTerminalNotFound(t *testing.T) {
	t.Parallel()
	fsys := &faultFS{files: testsupport.FrontendFS()}
	siteHandler, err := New(fsys)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for name, target := range map[string]string{
		"parent traversal":    "/../index.html",
		"dot segment":         "/./index.html",
		"leading duplicate":   "//assets/app-abc123.js",
		"interior duplicate":  "/assets//app-abc123.js",
		"trailing slash":      "/assets/app-abc123.js/",
		"backslash separator": "/assets\\app-abc123.js",
		"embedded nul":        "/assets/app\x00.js",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.URL.Path = target
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("GET %q status = %d, want %d", target, response.Code, http.StatusNotFound)
			}
		})
	}
}
