// visitor.go is the mock-browser harness for end-to-end suites: a hand-written
// wrapper over a real http.Client that behaves the way a visitor's browser
// does, so scenario tests read as user stories over real transport.

package testsupport

import (
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"
)

// SiteContentSecurityPolicy is the browser policy the origin applies to every
// response. The harness pins it as an independent expected value on purpose:
// it must never be imported from the server package, or the assertion would
// become a tautology.
const SiteContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"

// exactSecurityHeaders is the browser-security baseline that must accompany
// every navigation result — success, redirect-free 404, or conditional 304 —
// with these exact values.
var exactSecurityHeaders = map[string]string{
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy":           "camera=(), geolocation=(), microphone=()",
	"Referrer-Policy":              "no-referrer",
	"Strict-Transport-Security":    "max-age=31536000",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
}

// assetReference matches the document's content-addressed asset URLs the same
// way the embed and e2e suites hunt them, so every layer follows identical
// references.
var assetReference = regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`)

// VisitorResponse is one fully read navigation result. Bodies are always
// consumed before returning so connections are reusable and assertions stay
// linear.
type VisitorResponse struct {
	// StatusCode is the response status.
	StatusCode int
	// Header is the complete response header set.
	Header http.Header
	// Body is the full response body.
	Body []byte
}

// Visitor is a mock browser over real transport. It remembers ETags per URL
// and replays them as If-None-Match the way a browser cache revalidates, can
// follow a document's asset references, and asserts the security-header
// baseline on every navigation so no scenario can forget it.
type Visitor struct {
	// t owns failure reporting; every navigation asserts through it.
	t *testing.T
	// client is a plain http.Client — real sockets, no test transport.
	client *http.Client
	// base is the scheme://host:port prefix of the site under visit.
	base string
	// cache maps a visited path to the ETag a 200 response carried, exactly
	// the validator a browser would replay on its next navigation.
	cache map[string]string
}

// NewVisitor opens a fresh browsing session — an empty cache — against base.
func NewVisitor(t *testing.T, base string) *Visitor {
	t.Helper()
	return &Visitor{
		t:      t,
		client: &http.Client{Timeout: 5 * time.Second},
		base:   base,
		cache:  make(map[string]string),
	}
}

// On returns a view of the same browsing session — shared connection pool and
// shared browser cache — whose assertions report through t. Scenario chapters
// running as subtests must each take their own view, because fatal assertions
// have to stop the subtest goroutine that navigated, never the parent's.
func (v *Visitor) On(t *testing.T) *Visitor {
	t.Helper()
	return &Visitor{t: t, client: v.client, base: v.base, cache: v.cache}
}

// Navigate performs a browser-like GET of path: a validator remembered from a
// previous visit is replayed as If-None-Match, the security baseline is
// asserted, and a 200 response's ETag is remembered for the next visit.
func (v *Visitor) Navigate(path string) VisitorResponse {
	v.t.Helper()
	request, err := http.NewRequest(http.MethodGet, v.base+path, nil)
	if err != nil {
		v.t.Fatalf("build request for %s: %v", path, err)
	}
	if etag, revisit := v.cache[path]; revisit {
		request.Header.Set("If-None-Match", etag)
	}
	return v.do(path, request)
}

// AssetReferences returns the content-addressed asset URLs the document
// references, in order of appearance — the set a browser would fetch next.
func (v *Visitor) AssetReferences(document []byte) []string {
	v.t.Helper()
	var references []string
	for _, match := range assetReference.FindAllSubmatch(document, -1) {
		references = append(references, string(match[1]))
	}
	return references
}

// do executes one prepared request, reads the whole body, enforces the
// security baseline, and files a 200's validator into the browser cache.
func (v *Visitor) do(path string, request *http.Request) VisitorResponse {
	v.t.Helper()
	response, err := v.client.Do(request)
	if err != nil {
		v.t.Fatalf("GET %s: %v", request.URL, err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		v.t.Fatalf("read %s body: %v", request.URL, err)
	}
	v.assertSecurityBaseline(path, response.Header)
	if etag := response.Header.Get("ETag"); response.StatusCode == http.StatusOK && etag != "" {
		v.cache[path] = etag
	}
	return VisitorResponse{StatusCode: response.StatusCode, Header: response.Header, Body: body}
}

// assertSecurityBaseline fails the scenario if any navigation — any path, any
// status — is missing the exact origin security headers or carries a
// Content-Security-Policy other than the one documented site policy.
func (v *Visitor) assertSecurityBaseline(path string, header http.Header) {
	v.t.Helper()
	for name, want := range exactSecurityHeaders {
		if got := header.Get(name); got != want {
			v.t.Errorf("%s: %s = %q, want %q on every navigation", path, name, got, want)
		}
	}
	if got := header.Get("Content-Security-Policy"); got != SiteContentSecurityPolicy {
		v.t.Errorf("%s: Content-Security-Policy = %q, want the documented site policy", path, got)
	}
}
