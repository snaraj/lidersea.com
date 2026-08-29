// Theme-delivery tests pin the half of the reading-theme mechanism that
// lives at the HTTP boundary: which precomputed shell answers a request,
// what the response tells caches about that choice, and the two things the
// origin must never do — write a cookie, or let a cookie's bytes reach a
// document.

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/snaraj/lidersea.com/internal/testsupport"
	"github.com/snaraj/lidersea.com/internal/theme"
)

// themedRequest builds an edge-forwarded navigation carrying the site's
// theme cookie. The header is written raw rather than through
// http.Request.AddCookie, whose client-side sanitiser would strip exactly
// the bytes a hostile visitor sends: the server's own parser and the theme
// domain are what must reject them.
func themedRequest(method, target, cookieValue string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	if cookieValue != "" {
		request.Header.Set("Cookie", theme.CookieName+"="+cookieValue)
	}
	return request
}

// TestShellVariantFollowsTheThemeCookie sweeps the selection contract. Every
// value that names no catalog theme — absent, unknown, oversized, hostile —
// must be answered with the default shell, and no request byte may appear in
// the document that answers it.
func TestShellVariantFollowsTheThemeCookie(t *testing.T) {
	t.Parallel()
	siteHandler := testHandler(t)
	tests := []struct {
		name   string
		cookie string
		want   theme.Theme
		// rejected marks a row whose cookie names no catalog theme, so the
		// answer must be the default shell AND must not echo the value.
		rejected bool
	}{
		{name: "first visit", cookie: "", want: theme.Default},
		{name: "system", cookie: "system", want: theme.System},
		{name: "light", cookie: "light", want: theme.Light},
		{name: "dark", cookie: "dark", want: theme.Dark},
		{name: "sepia", cookie: "sepia", want: theme.Sepia},
		{name: "unknown theme", cookie: "browntown", want: theme.Default, rejected: true},
		{name: "capitalised", cookie: "Dark", want: theme.Default, rejected: true},
		// Two cookies of the same name: the first wins, deterministically,
		// so a second injected copy cannot change the answer.
		{name: "duplicate cookie", cookie: "dark; " + theme.CookieName + "=light", want: theme.Dark},
		{
			name:     "oversized",
			cookie:   strings.Repeat("d", theme.MaxCookieValueBytes+1),
			want:     theme.Default,
			rejected: true,
		},
		{name: "attribute injection", cookie: `dark"onload=alert(1)`, want: theme.Default, rejected: true},
		{name: "tag injection", cookie: "dark><script>", want: theme.Default, rejected: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, themedRequest(http.MethodGet, "/", test.cookie))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d", response.Code)
			}
			body := response.Body.String()
			want := theme.Attribute + `="` + string(test.want) + `"`
			if !strings.Contains(body, want) {
				t.Fatalf("shell does not carry %s: %q", want, body)
			}
			if strings.Count(body, theme.Attribute) != 1 {
				t.Fatalf("shell carries %d theme attributes, want 1: %q", strings.Count(body, theme.Attribute), body)
			}
			if test.rejected && strings.Contains(body, test.cookie) {
				t.Fatalf("shell echoes the rejected cookie value %q: %q", test.cookie, body)
			}
			if got := response.Header().Get("Vary"); got != "Cookie" {
				t.Errorf("Vary = %q, want %q so a shared cache keeps the variants apart", got, "Cookie")
			}

			head := httptest.NewRecorder()
			siteHandler.ServeHTTP(head, themedRequest(http.MethodHead, "/", test.cookie))
			if head.Code != http.StatusOK || head.Body.Len() != 0 {
				t.Errorf("HEAD / = status %d, %d bytes", head.Code, head.Body.Len())
			}
			for _, header := range []string{"ETag", "Vary", "Cache-Control", "Content-Type"} {
				if head.Header().Get(header) != response.Header().Get(header) {
					t.Errorf("HEAD %s = %q, want the GET value %q", header, head.Header().Get(header), response.Header().Get(header))
				}
			}
		})
	}
}

// TestEachThemeHasItsOwnCacheIdentity proves the variants are separate
// cached resources: distinct ETags, stable across requests, and a validator
// from one theme never satisfies a request for another.
func TestEachThemeHasItsOwnCacheIdentity(t *testing.T) {
	t.Parallel()
	siteHandler := testHandler(t)
	etags := make(map[string]theme.Theme, len(theme.Catalog))
	for _, candidate := range theme.Catalog {
		first := httptest.NewRecorder()
		siteHandler.ServeHTTP(first, themedRequest(http.MethodGet, "/", string(candidate)))
		etag := first.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("%q shell has no ETag", candidate)
		}
		if earlier, collides := etags[etag]; collides {
			t.Fatalf("%q and %q shells share the ETag %s", earlier, candidate, etag)
		}
		etags[etag] = candidate

		repeat := httptest.NewRecorder()
		siteHandler.ServeHTTP(repeat, themedRequest(http.MethodGet, "/", string(candidate)))
		if got := repeat.Header().Get("ETag"); got != etag {
			t.Errorf("%q shell ETag changed between requests: %s then %s", candidate, etag, got)
		}

		// The browser's own revalidation of the theme it already holds.
		revalidate := themedRequest(http.MethodGet, "/", string(candidate))
		revalidate.Header.Set("If-None-Match", etag)
		conditional := httptest.NewRecorder()
		siteHandler.ServeHTTP(conditional, revalidate)
		if conditional.Code != http.StatusNotModified {
			t.Errorf("revalidating the %q shell = %d, want %d", candidate, conditional.Code, http.StatusNotModified)
		}

		// The same validator against a different theme must miss: a shared
		// cache that ignored Vary would otherwise serve the wrong document.
		other := theme.Light
		if candidate == theme.Light {
			other = theme.Dark
		}
		crossed := themedRequest(http.MethodGet, "/", string(other))
		crossed.Header.Set("If-None-Match", etag)
		mismatch := httptest.NewRecorder()
		siteHandler.ServeHTTP(mismatch, crossed)
		if mismatch.Code != http.StatusOK {
			t.Errorf("%q validator against the %q shell = %d, want %d", candidate, other, mismatch.Code, http.StatusOK)
		}
	}
}

// TestOnlyTheShellDeclaresCookieVariance keeps the declaration honest in
// both directions: the shell is the one response a cookie can change, and
// every other route stays a single cacheable resource.
func TestOnlyTheShellDeclaresCookieVariance(t *testing.T) {
	t.Parallel()
	siteHandler := testHandler(t)
	for _, path := range []string{
		"/assets/app-abc123.js", "/api/board", "/api/reviews", "/api/ratings",
		"/livez", "/readyz", "/missing",
	} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, themedRequest(http.MethodGet, path, "dark"))
		if got := response.Header().Get("Vary"); got != "" {
			t.Errorf("%s Vary = %q, want no cookie variance outside the shell", path, got)
		}
	}
}

// TestOriginNeverSetsACookie pins the read-only posture of the theme
// mechanism: the browser writes the preference, the origin only ever reads
// it. A Set-Cookie anywhere would make the origin stateful and would defeat
// caching on every route it appeared on.
func TestOriginNeverSetsACookie(t *testing.T) {
	t.Parallel()
	siteHandler := testHandler(t)
	for _, path := range []string{
		"/", "/assets/app-abc123.js", "/api/board", "/api/reviews", "/api/ratings",
		"/livez", "/readyz", "/missing",
	} {
		for _, cookie := range []string{"", "dark", "sepia", "browntown"} {
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, themedRequest(http.MethodGet, path, cookie))
			if got := response.Header().Values("Set-Cookie"); len(got) != 0 {
				t.Errorf("%s (cookie %q) sets cookies %v; the origin must never write one", path, cookie, got)
			}
		}
	}
}

// TestThemedShellsAreStampedOnceAtConstruction is the read-once contract, in
// both halves. Availability: a broken bundle fails during New — before
// Kubernetes can route traffic to the pod — rather than on a visitor's first
// request. Performance: every theme's document is built during New, so no
// navigation, of any theme in any order, reads or transforms the entrypoint
// again. The read counter is the faultFS's, so both halves are measured
// rather than reasoned about.
func TestThemedShellsAreStampedOnceAtConstruction(t *testing.T) {
	t.Parallel()
	fsys := &faultFS{files: testsupport.FrontendFS()}
	siteHandler, err := New(fsys)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := fsys.readsOf("index.html"); got != 1 {
		t.Fatalf("index.html read %d times during construction, want 1", got)
	}
	for range 2 {
		for _, candidate := range theme.Catalog {
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, themedRequest(http.MethodGet, "/", string(candidate)))
			if response.Code != http.StatusOK {
				t.Fatalf("%q shell status = %d", candidate, response.Code)
			}
		}
	}
	if got := fsys.readsOf("index.html"); got != 1 {
		t.Errorf("index.html read %d times after serving every theme twice, want still 1", got)
	}
}

// TestNewRejectsAnUnstampableShell keeps readiness fail-closed for the theme
// mechanism the same way a missing entrypoint already does: a bundle whose
// document cannot carry the attribute would serve every visitor an unthemed
// page, so it must stop the process before Kubernetes routes traffic to it.
func TestNewRejectsAnUnstampableShell(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"no root element":   "<!doctype html><main data-static-fallback>shell</main>",
		"two root elements": `<html lang="en"></html><html lang="fr"></html>`,
		"already stamped":   `<html ` + theme.Attribute + `="dark" lang="en"></html>`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bundle := testsupport.FrontendFS()
			bundle["index.html"] = &fstest.MapFile{Data: []byte(document)}
			if _, err := New(bundle); err == nil {
				t.Fatal("New() succeeded with a shell that cannot be stamped")
			}
		})
	}
}
