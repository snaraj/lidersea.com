// Package server tests the origin HTTP contract independently from the frontend
// toolchain by supplying a small in-memory filesystem.
package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// testHandler builds the production handler around the canonical in-memory
// bundle, isolating HTTP policy tests from frontend compilation details.
func testHandler(t *testing.T) http.Handler {
	t.Helper()
	siteHandler, err := New(testsupport.FrontendFS())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return siteHandler
}

// TestRootAndSecurityHeaders protects the uncached document response and the
// browser-security baseline that must remain present behind the edge. The
// request carries the edge's TLS declaration the way every forwarded visitor
// request does, so the full baseline — HSTS included — must answer it.
func TestRootAndSecurityHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	testHandler(t).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	// The sentinel decouples the assertion from real site copy: the document
	// body is fixture-owned structure, not a content contract.
	if !strings.Contains(response.Body.String(), testsupport.FrontendShellSentinel) {
		t.Fatalf("body does not contain the fixture sentinel: %q", response.Body.String())
	}
	for _, header := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing header %s", header)
		}
	}
	if got := response.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("Strict-Transport-Security = %q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q", got)
	}
}

// TestForwardedProtoPolicy pins the origin's entire X-Forwarded-Proto
// decision surface, which is deliberately exact-match and fail-closed: only
// the lowercase declaration "http" triggers the permanent redirect to TLS,
// only the lowercase declaration "https" earns the HSTS promise, and every
// other state — no header (cluster probes, port-forward validation, local
// dev), a case variant like "HTTPS", or an unknown proto like "ws" — serves
// normally with no redirect and no promise. The header influences nothing
// beyond this scheme decision. Header-NAME case over real transport is
// pinned in the cmd/server contract suite, where a wire parser exists to
// canonicalize it; here requests are built canonically by net/http.
func TestForwardedProtoPolicy(t *testing.T) {
	siteHandler := testHandler(t)
	tests := []struct {
		name   string
		method string
		// target is the full request target; its host feeds the redirect's
		// Location, and its path and query must survive byte for byte.
		target string
		// proto is the X-Forwarded-Proto value; empty means no header at all.
		proto      string
		wantStatus int
		// wantLocation is asserted exactly when non-empty.
		wantLocation string
		// wantHSTS is the exact Strict-Transport-Security value; empty means
		// the header must be absent.
		wantHSTS string
	}{
		{
			name:         "edge declares plain http: GET bounces permanently to TLS",
			method:       http.MethodGet,
			target:       "http://lidersea.example/services?berth=12",
			proto:        "http",
			wantStatus:   http.StatusMovedPermanently,
			wantLocation: "https://lidersea.example/services?berth=12",
		},
		{
			name:         "edge declares plain http: HEAD bounces identically with no body",
			method:       http.MethodHead,
			target:       "http://lidersea.example/services?berth=12",
			proto:        "http",
			wantStatus:   http.StatusMovedPermanently,
			wantLocation: "https://lidersea.example/services?berth=12",
		},
		{
			name:         "escaped path and query survive the bounce byte for byte",
			method:       http.MethodGet,
			target:       "http://lidersea.example/fleet%20care/deep?hull=1&finish=%2Fgelcoat&empty=",
			proto:        "http",
			wantStatus:   http.StatusMovedPermanently,
			wantLocation: "https://lidersea.example/fleet%20care/deep?hull=1&finish=%2Fgelcoat&empty=",
		},
		{
			name:         "surface API routes are bounced too when the edge says plain http",
			method:       http.MethodGet,
			target:       "http://lidersea.example/api/board",
			proto:        "http",
			wantStatus:   http.StatusMovedPermanently,
			wantLocation: "https://lidersea.example/api/board",
		},
		{
			name:       "edge declares TLS: GET serves with the exact HSTS promise",
			method:     http.MethodGet,
			target:     "/",
			proto:      "https",
			wantStatus: http.StatusOK,
			wantHSTS:   "max-age=31536000",
		},
		{
			name:       "edge declares TLS: HEAD carries the same promise",
			method:     http.MethodHead,
			target:     "/",
			proto:      "https",
			wantStatus: http.StatusOK,
			wantHSTS:   "max-age=31536000",
		},
		{
			name:       "no declaration: cluster-internal serving is untouched",
			method:     http.MethodGet,
			target:     "/",
			proto:      "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "no declaration: readiness stays served with no promise",
			method:     http.MethodGet,
			target:     "/readyz",
			proto:      "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "case variant HTTPS is not our edge: no promise is minted",
			method:     http.MethodGet,
			target:     "/",
			proto:      "HTTPS",
			wantStatus: http.StatusOK,
		},
		{
			name:       "case variant HTTP is not our edge: no bounce is issued",
			method:     http.MethodGet,
			target:     "/",
			proto:      "HTTP",
			wantStatus: http.StatusOK,
		},
		{
			name:       "unknown proto ws fails closed to normal serving",
			method:     http.MethodGet,
			target:     "/",
			proto:      "ws",
			wantStatus: http.StatusOK,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, nil)
			if test.proto != "" {
				request.Header.Set("X-Forwarded-Proto", test.proto)
			}
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("%s %s = %d, want %d", test.method, test.target, response.Code, test.wantStatus)
			}
			if got := response.Header().Get("Location"); got != test.wantLocation {
				t.Errorf("Location = %q, want %q", got, test.wantLocation)
			}
			if got := response.Header().Get("Strict-Transport-Security"); got != test.wantHSTS {
				t.Errorf("Strict-Transport-Security = %q, want %q (empty means absent)", got, test.wantHSTS)
			}
			if test.method == http.MethodHead && response.Body.Len() != 0 {
				t.Errorf("HEAD carried %d body bytes, want none", response.Body.Len())
			}
			if test.wantStatus == http.StatusMovedPermanently {
				// The bounce is written inside the securityHeaders wrapper, so
				// even the redirect carries the baseline policy (HSTS excluded:
				// the plain leg has not earned the promise).
				if got := response.Header().Get("Content-Security-Policy"); got != testsupport.SiteContentSecurityPolicy {
					t.Errorf("redirect Content-Security-Policy = %q, want the site policy", got)
				}
			}
		})
	}
}

// TestNoRequestMethodCanEverMutate is the executable safety contract that
// permits TLS 1.3 0-RTT (early data) at the edge. 0-RTT carries a replay risk,
// so it is only admissible where no request can change server state. Every
// route here answers reads and refuses every mutating method, and this test
// exists so that property can never silently regress into a replayable one.
func TestNoRequestMethodCanEverMutate(t *testing.T) {
	siteHandler := testHandler(t)
	mutating := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}
	routes := []string{"/", "/livez", "/readyz", "/assets/app-abc123.js", "/missing"}
	for _, route := range routes {
		for _, method := range mutating {
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, httptest.NewRequest(method, route, nil))
			if response.Code == http.StatusOK {
				t.Errorf("%s %s was accepted; 0-RTT requires every route to be read-only", method, route)
			}
		}
	}
}

// TestAssetCachingAndConditionalRequest verifies that hashed assets are durable
// cache entries while still participating in standard conditional requests.
func TestAssetCachingAndConditionalRequest(t *testing.T) {
	siteHandler := testHandler(t)
	first := httptest.NewRecorder()
	siteHandler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}
	if got := first.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", got)
	}
	secondRequest := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
	secondRequest.Header.Set("If-None-Match", first.Header().Get("ETag"))
	second := httptest.NewRecorder()
	siteHandler.ServeHTTP(second, secondRequest)
	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d", second.Code)
	}
}

// TestAssetRangeRequest locks partial-response support to net/http's bounded
// reader instead of adding a second ad hoc implementation for static UI assets.
func TestAssetRangeRequest(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
	request.Header.Set("Range", "bytes=0-6")
	response := httptest.NewRecorder()
	testHandler(t).ServeHTTP(response, request)
	if response.Code != http.StatusPartialContent {
		t.Fatalf("range status = %d", response.Code)
	}
	if response.Body.String() != "console" {
		t.Errorf("range body = %q", response.Body.String())
	}
}

// TestHealthMethodsAndMissingPath keeps probes read-only and confirms that
// unknown, traversal, and repository-placeholder paths are never served.
func TestHealthMethodsAndMissingPath(t *testing.T) {
	siteHandler := testHandler(t)
	for _, endpoint := range []string{"/livez", "/readyz"} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, endpoint, nil))
		if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
			t.Errorf("%s = %d %q", endpoint, response.Code, response.Body.String())
		}
		head := httptest.NewRecorder()
		siteHandler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, endpoint, nil))
		if head.Code != http.StatusOK || head.Body.Len() != 0 {
			t.Errorf("HEAD %s = %d %q", endpoint, head.Code, head.Body.String())
		}
	}
	post := httptest.NewRecorder()
	siteHandler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/", nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST = %d Allow=%q", post.Code, post.Header().Get("Allow"))
	}
	missing := httptest.NewRecorder()
	siteHandler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if missing.Code != http.StatusNotFound {
		t.Errorf("missing status = %d", missing.Code)
	}
	placeholder := httptest.NewRecorder()
	siteHandler.ServeHTTP(placeholder, httptest.NewRequest(http.MethodGet, "/.gitkeep", nil))
	if placeholder.Code != http.StatusNotFound {
		t.Errorf(".gitkeep status = %d", placeholder.Code)
	}
	traversal := httptest.NewRecorder()
	direct := &handler{assets: fstest.MapFS{}, index: []byte("index")}
	direct.ServeHTTP(traversal, httptest.NewRequest(http.MethodGet, "/../index.html", nil))
	if traversal.Code != http.StatusNotFound {
		t.Errorf("traversal status = %d", traversal.Code)
	}
}

// TestNewRejectsMissingEntrypoint keeps readiness fail-closed when a frontend
// build is absent or the image assembly copied the wrong directory.
func TestNewRejectsMissingEntrypoint(t *testing.T) {
	if _, err := New(fstest.MapFS{}); err == nil {
		t.Fatal("New() succeeded without index.html")
	}
}
