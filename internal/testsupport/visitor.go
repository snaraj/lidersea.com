// visitor.go is the mock-browser harness for end-to-end suites: a hand-written
// wrapper over a real http.Client that behaves the way a visitor's browser
// does, so scenario tests read as user stories over real transport.

package testsupport

import (
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// SiteContentSecurityPolicy is the browser policy the origin applies to every
// response. The harness pins it as an independent expected value on purpose:
// it must never be imported from the server package, or the assertion would
// become a tautology.
const SiteContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"

// StrictTransportSecurityPolicy is the exact HSTS promise the origin sends
// with — and only with — responses whose request the edge declared as TLS.
// Pinned independently like the CSP above, never imported from the server
// package.
const StrictTransportSecurityPolicy = "max-age=31536000"

// forwardedProtoHeader is the edge's scheme declaration the harness stamps
// on every navigation, exactly as the TLS-terminating edge does when it
// forwards a visitor's request to the origin.
const forwardedProtoHeader = "X-Forwarded-Proto"

// exactSecurityHeaders is the browser-security baseline that must accompany
// every navigation result — success, redirect, redirect-free 404, or
// conditional 304 — with these exact values. HSTS is asserted separately in
// assertSecurityBaseline because it is proto-conditional: required on
// TLS-declared sessions, forbidden on every other.
var exactSecurityHeaders = map[string]string{
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy":           "camera=(), geolocation=(), microphone=()",
	"Referrer-Policy":              "no-referrer",
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
// baseline on every navigation so no scenario can forget it. Real visitors
// reach the origin through the TLS-terminating edge, so the session carries
// the edge's scheme declaration on every request; the baseline requires the
// HSTS promise exactly on TLS-declared sessions and forbids it on every
// other.
type Visitor struct {
	// t owns failure reporting; every navigation asserts through it.
	t *testing.T
	// client is a plain http.Client — real sockets, no test transport. It
	// surfaces redirects to the scenario instead of chasing them: the one
	// redirect this origin ever issues points at the TLS edge, which stands
	// outside the process under test, so the response itself is the story.
	client *http.Client
	// base is the scheme://host:port prefix of the site under visit.
	base string
	// proto is the X-Forwarded-Proto declaration stamped on every request —
	// what the edge states about the visitor's public leg. Empty means no
	// header at all: a connection that never crossed the edge, like a
	// cluster probe or an operator's port-forward.
	proto string
	// cache maps a visited path to the ETag a 200 response carried, exactly
	// the validator a browser would replay on its next navigation.
	cache map[string]string
	// jar holds the cookies this session sends on every navigation, exactly
	// as a browser replays a preference a page stored earlier. Nothing on
	// this origin ever writes one, so the jar is only ever filled by a
	// scenario stating what the visitor already chose.
	jar map[string]string
}

// NewVisitor opens a fresh browsing session — an empty cache — against base,
// arriving the way every real visitor does: over TLS through the edge, which
// declares https for them.
func NewVisitor(t *testing.T, base string) *Visitor {
	t.Helper()
	return newSession(t, base, "https")
}

// NewInsecureVisitor opens a session for the visitor who typed http://: the
// edge forwards their plain-HTTP request with an http declaration, and every
// navigation should be bounced to TLS before any content is served.
func NewInsecureVisitor(t *testing.T, base string) *Visitor {
	t.Helper()
	return newSession(t, base, "http")
}

// NewDirectVisitor opens a session that never crossed the edge — a cluster
// probe or an operator port-forwarding straight to the pod — so no forwarded
// proto accompanies its requests and no HSTS promise may answer them.
func NewDirectVisitor(t *testing.T, base string) *Visitor {
	t.Helper()
	return newSession(t, base, "")
}

// newSession is the shared constructor behind the three arrival stories.
func newSession(t *testing.T, base, proto string) *Visitor {
	t.Helper()
	return &Visitor{
		t: t,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		base:  base,
		proto: proto,
		cache: make(map[string]string),
		jar:   make(map[string]string),
	}
}

// On returns a view of the same browsing session — shared connection pool,
// shared browser cache, same arrival proto — whose assertions report through
// t. Scenario chapters running as subtests must each take their own view,
// because fatal assertions have to stop the subtest goroutine that
// navigated, never the parent's.
func (v *Visitor) On(t *testing.T) *Visitor {
	t.Helper()
	return &Visitor{t: t, client: v.client, base: v.base, proto: v.proto, cache: v.cache, jar: v.jar}
}

// Prefers records a cookie the session sends on every later navigation, the
// way a browser replays a preference the visitor set on an earlier visit.
// The value is written raw so a scenario can state exactly what reaches the
// origin, hostile bytes included.
func (v *Visitor) Prefers(name, value string) {
	v.t.Helper()
	v.jar[name] = value
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

// do executes one prepared request, stamps the session's edge declaration
// onto it, reads the whole body, enforces the security baseline, and files a
// 200's validator into the browser cache.
func (v *Visitor) do(path string, request *http.Request) VisitorResponse {
	v.t.Helper()
	if v.proto != "" {
		request.Header.Set(forwardedProtoHeader, v.proto)
	}
	if len(v.jar) > 0 {
		pairs := make([]string, 0, len(v.jar))
		for name, value := range v.jar {
			pairs = append(pairs, name+"="+value)
		}
		sort.Strings(pairs)
		request.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
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
// Content-Security-Policy other than the one documented site policy. HSTS is
// held to the proto contract: a TLS-declared session must carry the exact
// promise on every navigation, and any other session must never see one — an
// HSTS pin on an undeclared or plain leg would teach a browser a transport
// guarantee the connection never demonstrated.
func (v *Visitor) assertSecurityBaseline(path string, header http.Header) {
	v.t.Helper()
	for name, want := range exactSecurityHeaders {
		if got := header.Get(name); got != want {
			v.t.Errorf("%s: %s = %q, want %q on every navigation", path, name, got, want)
		}
	}
	if hsts := header.Get("Strict-Transport-Security"); v.proto == "https" {
		if hsts != StrictTransportSecurityPolicy {
			v.t.Errorf("%s: Strict-Transport-Security = %q, want %q on every TLS-declared navigation", path, hsts, StrictTransportSecurityPolicy)
		}
	} else if hsts != "" {
		v.t.Errorf("%s: Strict-Transport-Security = %q on a session the edge never declared as TLS; the promise must be absent", path, hsts)
	}
	if got := header.Get("Content-Security-Policy"); got != SiteContentSecurityPolicy {
		v.t.Errorf("%s: Content-Security-Policy = %q, want the documented site policy", path, got)
	}
}
