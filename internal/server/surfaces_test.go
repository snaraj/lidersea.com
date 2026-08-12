// surfaces_test pins the surface API in the DEFAULT build — the exact
// handler production runs with zero configuration: read-only surfaces under
// the sitewide contract, opaque 404s for everything ungranted (unknown /api/
// paths, the gated estimates route, the disabled media class), stable cache
// identities, and the payload budgets the delivery lane promises.

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaraj/lidersea.com/internal/board"
	"github.com/snaraj/lidersea.com/internal/surface"
	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// Payload budgets: every surface page must fit its pinned ceiling so the UI
// can rely on cheap first paints over any connection.
const (
	boardPageBudgetBytes   = 48 * 1024
	reviewsPageBudgetBytes = 16 * 1024
	// The ratings strip renders in the footer of every page view, so its
	// ceiling is the tightest of the three.
	ratingsStripBudgetBytes = 8 * 1024
)

// envelopeShape decodes the wire envelope for structural assertions.
type envelopeShape struct {
	Schema      string          `json:"schema"`
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Title       string          `json:"title"`
	GeneratedAt string          `json:"generatedAt"`
	Status      string          `json:"status"`
	Data        json.RawMessage `json:"data"`
}

// getSurface fetches one surface path from the default handler, arriving the
// way every real surface reader does: forwarded by the TLS-terminating edge,
// whose declaration the full security baseline — HSTS included — answers.
func getSurface(t *testing.T, siteHandler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	siteHandler.ServeHTTP(response, request)
	return response
}

// decodeEnvelope asserts the response is a well-formed surface envelope and
// returns it.
func decodeEnvelope(t *testing.T, response *httptest.ResponseRecorder, wantID, wantKind string) envelopeShape {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("surface status = %d, body %q", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	var env envelopeShape
	if err := json.Unmarshal(response.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not a JSON envelope: %v", err)
	}
	if env.Schema != "surface/v1" || env.ID != wantID || env.Kind != wantKind {
		t.Errorf("envelope identity = %q %q %q, want surface/v1 %s %s", env.Schema, env.ID, env.Kind, wantID, wantKind)
	}
	if env.Title == "" || env.Status != "ok" {
		t.Errorf("envelope title/status = %q %q", env.Title, env.Status)
	}
	if _, err := time.Parse(time.RFC3339, env.GeneratedAt); err != nil {
		t.Errorf("generatedAt %q is not RFC 3339", env.GeneratedAt)
	}
	return env
}

// TestBoardSurfaceServesEnvelopedPages walks GET /api/board's cursor chain
// over HTTP: every page is an enveloped media-mosaic/v1 payload within the
// byte budget, pages carry the fixed generation instant that keeps their
// ETags stable, and the walk terminates with full coverage.
func TestBoardSurfaceServesEnvelopedPages(t *testing.T) {
	siteHandler := testHandler(t)
	seen := map[string]bool{}
	path := surface.Board.Route
	pages := 0
	for {
		response := getSurface(t, siteHandler, path)
		env := decodeEnvelope(t, response, "board", "media-mosaic/v1")
		if response.Body.Len() > boardPageBudgetBytes {
			t.Errorf("board page %d is %d bytes, over the %d budget", pages, response.Body.Len(), boardPageBudgetBytes)
		}
		if got := response.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("board Cache-Control = %q, want no-cache", got)
		}
		var data struct {
			Blocks []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"blocks"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("board data does not decode: %v", err)
		}
		for _, block := range data.Blocks {
			if seen[block.ID] {
				t.Errorf("block %q served on two pages", block.ID)
			}
			seen[block.ID] = true
		}
		pages++
		if data.NextCursor == "" {
			break
		}
		if pages > 10 {
			t.Fatal("cursor chain did not terminate")
		}
		path = surface.Board.Route + "?cursor=" + data.NextCursor
	}
	if pages < 2 {
		t.Errorf("board served %d page(s); the sample must exercise the cursor", pages)
	}
	if len(seen) == 0 {
		t.Fatal("board walk yielded no blocks")
	}
}

// TestBoardSurfaceCacheIdentity proves the sample board revalidates like
// every other resource on this origin: a stable digest ETag and a 304 on
// replay, which only holds because sample envelopes carry a fixed
// generatedAt instead of a per-request clock read.
func TestBoardSurfaceCacheIdentity(t *testing.T) {
	siteHandler := testHandler(t)
	first := getSurface(t, siteHandler, surface.Board.Route)
	etag := first.Header().Get("ETag")
	if len(etag) != 66 || !strings.HasPrefix(etag, `"`) {
		t.Fatalf("board ETag = %q, want a quoted sha256 digest", etag)
	}
	second := getSurface(t, siteHandler, surface.Board.Route)
	if second.Header().Get("ETag") != etag {
		t.Fatalf("board ETag changed between identical requests: %q then %q", etag, second.Header().Get("ETag"))
	}
	revalidate := httptest.NewRequest(http.MethodGet, surface.Board.Route, nil)
	revalidate.Header.Set("If-None-Match", etag)
	response := httptest.NewRecorder()
	siteHandler.ServeHTTP(response, revalidate)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Errorf("revalidation = %d with %d bytes, want empty 304", response.Code, response.Body.Len())
	}
}

// TestBoardSurfaceRejectsUnknownCursor keeps the one client input strict: a
// cursor no page ever issued is a 400 that echoes nothing back.
func TestBoardSurfaceRejectsUnknownCursor(t *testing.T) {
	response := getSurface(t, testHandler(t), surface.Board.Route+"?cursor=fabricated")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown cursor status = %d, want 400", response.Code)
	}
	if body := response.Body.String(); strings.Contains(body, "fabricated") {
		t.Errorf("400 body echoes client input: %q", body)
	}
}

// TestReviewsSurfaceServesAggregateAndList pins GET /api/reviews: an
// enveloped reviews/v1 payload within budget whose server-computed aggregate
// matches the served list exactly.
func TestReviewsSurfaceServesAggregateAndList(t *testing.T) {
	siteHandler := testHandler(t)
	response := getSurface(t, siteHandler, surface.Reviews.Route)
	env := decodeEnvelope(t, response, "reviews", "reviews/v1")
	if response.Body.Len() > reviewsPageBudgetBytes {
		t.Errorf("reviews page is %d bytes, over the %d budget", response.Body.Len(), reviewsPageBudgetBytes)
	}
	var data struct {
		Aggregate struct {
			Count     int     `json:"count"`
			Average   float64 `json:"average"`
			Histogram [5]int  `json:"histogram"`
		} `json:"aggregate"`
		Reviews []struct {
			Rating int    `json:"rating"`
			Source string `json:"source"`
		} `json:"reviews"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("reviews data does not decode: %v", err)
	}
	if data.Aggregate.Count != len(data.Reviews) || data.Aggregate.Count == 0 {
		t.Fatalf("aggregate count %d for %d reviews", data.Aggregate.Count, len(data.Reviews))
	}
	histogramTotal, sum := 0, 0
	for _, n := range data.Aggregate.Histogram {
		histogramTotal += n
	}
	for _, review := range data.Reviews {
		if review.Rating < 1 || review.Rating > 5 || review.Source != "first-party" {
			t.Errorf("served review out of contract: %+v", review)
		}
		sum += review.Rating
	}
	if histogramTotal != data.Aggregate.Count {
		t.Errorf("histogram sums to %d, want %d", histogramTotal, data.Aggregate.Count)
	}
	tenths := (sum*10 + data.Aggregate.Count/2) / data.Aggregate.Count
	if want := float64(tenths) / 10; data.Aggregate.Average != want {
		t.Errorf("average = %v, want the server's integer-tenths %v", data.Aggregate.Average, want)
	}
}

// TestDefaultBuildKeepsUngrantedRoutesInvisible pins the opaque-404 policy
// of everything the zero configuration does not grant: unknown /api/ paths,
// the gated estimates route (every method), and the disabled media class —
// all indistinguishable from paths that never existed.
func TestDefaultBuildKeepsUngrantedRoutesInvisible(t *testing.T) {
	siteHandler := testHandler(t)
	sampleMediaPath := "/media/immutable/" + strings.Repeat("a", 64) + "/sample.mp4"
	for name, target := range map[string]string{
		"unknown api path":        "/api/nope",
		"api root":                "/api/",
		"board subpath":           "/api/board/extra",
		"estimates gated off":     surface.Estimates.Route,
		"media disabled":          sampleMediaPath,
		"media root disabled":     "/media/immutable/",
		"case-mangled api route":  "/api/Board",
		"api without leading dir": "/apiboard",
	} {
		t.Run(name, func(t *testing.T) {
			response := getSurface(t, siteHandler, target)
			if response.Code != http.StatusNotFound {
				t.Fatalf("GET %s = %d, want 404", target, response.Code)
			}
			if got := strings.TrimSpace(response.Body.String()); got != "404 page not found" {
				t.Errorf("GET %s body = %q; it must stay the opaque default", target, got)
			}
		})
	}
	// The gated estimates route must be invisible for EVERY method, not just
	// reads: POST answering anything but 404 would reveal the surface.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(method, surface.Estimates.Route, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 while gated off", method, surface.Estimates.Route, response.Code)
		}
	}
}

// TestSurfaceRoutesStayReadOnlyByDefault extends the sitewide mutation
// contract to every surface and media path in the default build, mirroring
// TestNoRequestMethodCanEverMutate (which stays untouched) over the new
// routes: no mutating method may ever succeed anywhere.
func TestSurfaceRoutesStayReadOnlyByDefault(t *testing.T) {
	siteHandler := testHandler(t)
	routes := []string{
		surface.Board.Route,
		surface.Reviews.Route,
		surface.Ratings.Route,
		"/api/unknown",
		"/media/immutable/" + strings.Repeat("b", 64) + "/clip.mp4",
	}
	for _, route := range routes {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, httptest.NewRequest(method, route, nil))
			if response.Code >= 200 && response.Code < 300 {
				t.Errorf("%s %s = %d; the default build must never accept a mutation", method, route, response.Code)
			}
		}
	}
	// The registered read surfaces answer mutations with the sitewide 405
	// shape, exactly like every other route behind allowReadMethod.
	for _, route := range []string{surface.Board.Route, surface.Reviews.Route, surface.Ratings.Route} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, route, nil))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("POST %s = %d Allow=%q, want 405 GET, HEAD", route, response.Code, response.Header().Get("Allow"))
		}
	}
}

// TestSurfaceResponsesCarryTheSecurityBaseline requires the one sitewide
// header policy — the pinned CSP included — on surface successes and
// failures alike: the API adds routes, never a second policy.
func TestSurfaceResponsesCarryTheSecurityBaseline(t *testing.T) {
	siteHandler := testHandler(t)
	for _, path := range []string{surface.Board.Route, surface.Reviews.Route, surface.Ratings.Route, "/api/unknown"} {
		response := getSurface(t, siteHandler, path)
		if got := response.Header().Get("Content-Security-Policy"); got != testsupport.SiteContentSecurityPolicy {
			t.Errorf("%s CSP = %q, want the documented site policy", path, got)
		}
		for _, header := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"} {
			if response.Header().Get(header) == "" {
				t.Errorf("%s missing %s", path, header)
			}
		}
	}
}

// TestSurfaceHeadMatchesGet keeps HEAD truthful on surface routes: identical
// identity headers, empty body.
func TestSurfaceHeadMatchesGet(t *testing.T) {
	siteHandler := testHandler(t)
	for _, path := range []string{surface.Board.Route, surface.Reviews.Route, surface.Ratings.Route} {
		full := getSurface(t, siteHandler, path)
		head := httptest.NewRecorder()
		siteHandler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, path, nil))
		if head.Code != http.StatusOK || head.Body.Len() != 0 {
			t.Errorf("HEAD %s = %d with %d bytes", path, head.Code, head.Body.Len())
		}
		for _, name := range []string{"Content-Type", "ETag", "Cache-Control"} {
			if head.Header().Get(name) != full.Header().Get(name) {
				t.Errorf("HEAD %s %s does not match GET", path, name)
			}
		}
	}
}

// TestRegistryRoutesAgreeWithTheMux cross-checks the surface catalog against
// the wired handler: every registered read surface answers 200, and the
// gated estimates descriptor stays dark by default — so registry and mux can
// never silently drift apart.
func TestRegistryRoutesAgreeWithTheMux(t *testing.T) {
	siteHandler := testHandler(t)
	for _, descriptor := range surface.Registry {
		response := getSurface(t, siteHandler, descriptor.Route)
		switch descriptor.ID {
		case "estimates":
			if response.Code != http.StatusNotFound {
				t.Errorf("gated %s = %d, want 404 by default", descriptor.Route, response.Code)
			}
		default:
			if response.Code != http.StatusOK {
				t.Errorf("registered %s = %d, want 200", descriptor.Route, response.Code)
			}
		}
	}
}

// TestServeSurfaceJSONFailsClosed drives the marshal-failure branch directly
// with an unmarshalable payload: an opaque 500, never a partial envelope.
func TestServeSurfaceJSONFailsClosed(t *testing.T) {
	t.Parallel()
	poisoned := surface.NewEnvelope(surface.Board, surface.StatusOK, board.PublishedAt(), func() {})
	response := httptest.NewRecorder()
	serveSurfaceJSON(response, httptest.NewRequest(http.MethodGet, surface.Board.Route, nil), poisoned)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("marshal failure status = %d, want 500", response.Code)
	}
	if strings.Contains(response.Body.String(), "func") {
		t.Errorf("500 body leaks marshal detail: %q", response.Body.String())
	}
	write := httptest.NewRecorder()
	writeSurfaceJSON(write, http.StatusOK, poisoned)
	if write.Code != http.StatusInternalServerError {
		t.Fatalf("write-path marshal failure status = %d, want 500", write.Code)
	}
}
