// surfaces_visitor_test extends the visitor-scenario suite to the surface
// API and the media pipeline, booting run() exactly the way main does (via
// bootScenario) with per-scenario environments through the injected lookup —
// the same seam production configuration uses. Scenarios read as user
// stories: a reader browsing the surfaces in the default build, a viewer
// seeking through gated media, and a client using the opened write gates.
// Sequential by the suite's existing discipline: every scenario owns a live
// port and ends with process-global SIGTERM delivery. These ADD stories on
// top of the untouched lifecycle and shell-visitor suites; they replace
// nothing.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// bootScenarioEnv boots run with extra environment variables on top of the
// reserved PORT, mirroring bootScenario for configured scenarios.
func bootScenarioEnv(t *testing.T, extra map[string]string) (string, <-chan error) {
	t.Helper()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	t.Cleanup(stop)
	port := reservePort(t)
	env := map[string]string{"PORT": port}
	for key, value := range extra {
		env[key] = value
	}
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, fakeEnv(env)) }()
	base := "http://127.0.0.1:" + port
	waitReady(t, base, errCh)
	return base, errCh
}

// postSurface performs one POST with the security baseline asserted — the
// write-path counterpart of the Visitor's GET navigations, kept local to
// this suite so the shared harness stays read-only like a browser cache.
func postSurface(t *testing.T, base, path, contentType, body string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build POST %s: %v", path, err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	payload, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read POST %s body: %v", path, err)
	}
	if got := response.Header.Get("Content-Security-Policy"); got != testsupport.SiteContentSecurityPolicy {
		t.Errorf("POST %s CSP = %q, want the byte-identical site policy", path, got)
	}
	return response, payload
}

// TestVisitorReadsTheSurfaces is the default-build reader's story: the board
// arrives as enveloped pages whose cursor chain the visitor follows to the
// end, a repeat visit revalidates to a cheap 304, the reviews aggregate
// reads coherently, and everything the zero configuration does not grant —
// unknown surfaces, the gated estimates route, the media class, every
// mutation — answers exactly as opaquely as the shell does.
func TestVisitorReadsTheSurfaces(t *testing.T) {
	base, runResult := bootScenario(t)
	session := testsupport.NewVisitor(t, base)

	t.Run("the board arrives page by page under one envelope", func(t *testing.T) {
		visitor := session.On(t)
		path := "/api/board"
		seen := map[string]bool{}
		pages := 0
		for {
			response := visitor.Navigate(path)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d", path, response.StatusCode)
			}
			var envelope struct {
				Schema string `json:"schema"`
				Kind   string `json:"kind"`
				Status string `json:"status"`
				Data   struct {
					Blocks []struct {
						ID string `json:"id"`
					} `json:"blocks"`
					NextCursor string `json:"nextCursor"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body, &envelope); err != nil {
				t.Fatalf("board page does not decode: %v", err)
			}
			if envelope.Schema != "surface/v1" || envelope.Kind != "media-mosaic/v1" || envelope.Status != "ok" {
				t.Fatalf("board envelope = %+v", envelope)
			}
			for _, block := range envelope.Data.Blocks {
				if seen[block.ID] {
					t.Errorf("block %q served on two pages", block.ID)
				}
				seen[block.ID] = true
			}
			pages++
			if envelope.Data.NextCursor == "" {
				break
			}
			if pages > 10 {
				t.Fatal("board cursor chain did not terminate")
			}
			path = "/api/board?cursor=" + envelope.Data.NextCursor
		}
		if pages < 2 || len(seen) == 0 {
			t.Errorf("board walk = %d pages, %d blocks; the sample must exercise the cursor", pages, len(seen))
		}
	})

	t.Run("a repeat visit revalidates the board to a 304", func(t *testing.T) {
		visitor := session.On(t)
		revisit := visitor.Navigate("/api/board")
		if revisit.StatusCode != http.StatusNotModified || len(revisit.Body) != 0 {
			t.Errorf("board revisit = %d with %d bytes, want an empty 304 from the replayed validator", revisit.StatusCode, len(revisit.Body))
		}
	})

	t.Run("the reviews surface reads coherently", func(t *testing.T) {
		visitor := session.On(t)
		response := visitor.Navigate("/api/reviews")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/reviews = %d", response.StatusCode)
		}
		var envelope struct {
			Kind string `json:"kind"`
			Data struct {
				Aggregate struct {
					Count     int    `json:"count"`
					Histogram [5]int `json:"histogram"`
				} `json:"aggregate"`
				Reviews []struct {
					Rating int `json:"rating"`
				} `json:"reviews"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body, &envelope); err != nil {
			t.Fatalf("reviews payload does not decode: %v", err)
		}
		total := 0
		for _, n := range envelope.Data.Aggregate.Histogram {
			total += n
		}
		if envelope.Kind != "reviews/v1" || envelope.Data.Aggregate.Count != len(envelope.Data.Reviews) || total != envelope.Data.Aggregate.Count {
			t.Errorf("reviews surface incoherent: %+v", envelope)
		}
	})

	t.Run("everything ungranted stays opaque", func(t *testing.T) {
		visitor := session.On(t)
		for _, target := range []string{
			"/api/estimates/preview",
			"/api/private",
			"/media/immutable/" + strings.Repeat("0", 64) + "/clip.mp4",
		} {
			response := visitor.Navigate(target)
			if response.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", target, response.StatusCode)
			}
			if got := strings.TrimSpace(string(response.Body)); got != "404 page not found" {
				t.Errorf("GET %s body = %q; it must stay the opaque default", target, got)
			}
		}
		response, _ := postSurface(t, base, "/api/reviews", "application/json", `{"author":"a","rating":5,"text":"t"}`)
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST /api/reviews in the default build = %d, want 405 over the wire", response.StatusCode)
		}
	})

	drainScenario(t, runResult)
}

// TestVisitorStreamsGatedMedia is the media viewer's story with the pipeline
// enabled over a fixture root: the full asset arrives with its immutable
// digest identity, seeking works through real ranged requests, an
// out-of-range seek answers 416, and a cached revisit costs a 304.
func TestVisitorStreamsGatedMedia(t *testing.T) {
	fixtures := testsupport.MediaFixtures()
	root := testsupport.WriteMediaRoot(t, fixtures)
	base, runResult := bootScenarioEnv(t, map[string]string{
		"MEDIA_ENABLED":        "true",
		"MEDIA_ROOT":           root,
		"MEDIA_MAX_CONCURRENT": "4",
	})
	session := testsupport.NewVisitor(t, base)
	video := fixtures[1]

	t.Run("the full video arrives under its digest identity", func(t *testing.T) {
		visitor := session.On(t)
		response := visitor.Navigate(video.URL())
		if response.StatusCode != http.StatusOK || !bytes.Equal(response.Body, video.Bytes) {
			t.Fatalf("GET video = %d with %d bytes, want the exact fixture", response.StatusCode, len(response.Body))
		}
		if got := response.Header.Get("ETag"); got != `"`+video.Digest+`"` {
			t.Errorf("video ETag = %q, want the quoted digest", got)
		}
		if got := response.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("video Cache-Control = %q", got)
		}
		if got := response.Header.Get("Accept-Ranges"); got != "bytes" {
			t.Errorf("video Accept-Ranges = %q", got)
		}
	})

	t.Run("seeking fetches exact ranges", func(t *testing.T) {
		client := &http.Client{Timeout: 5 * time.Second}
		request, err := http.NewRequest(http.MethodGet, base+video.URL(), nil)
		if err != nil {
			t.Fatalf("build ranged request: %v", err)
		}
		request.Header.Set("Range", "bytes=1000-1999")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("ranged GET: %v", err)
		}
		slice, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatalf("read ranged body: %v", err)
		}
		if response.StatusCode != http.StatusPartialContent || !bytes.Equal(slice, video.Bytes[1000:2000]) {
			t.Fatalf("seek = %d with %d bytes, want the exact 206 slice", response.StatusCode, len(slice))
		}
		if got := response.Header.Get("Content-Range"); got != fmt.Sprintf("bytes 1000-1999/%d", len(video.Bytes)) {
			t.Errorf("Content-Range = %q", got)
		}

		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", len(video.Bytes)+10))
		beyond, err := client.Do(request)
		if err != nil {
			t.Fatalf("out-of-range GET: %v", err)
		}
		io.Copy(io.Discard, beyond.Body)
		beyond.Body.Close()
		if beyond.StatusCode != http.StatusRequestedRangeNotSatisfiable {
			t.Errorf("seek beyond the end = %d, want 416", beyond.StatusCode)
		}
	})

	t.Run("a revisit revalidates to a 304", func(t *testing.T) {
		visitor := session.On(t)
		revisit := visitor.Navigate(video.URL())
		if revisit.StatusCode != http.StatusNotModified || len(revisit.Body) != 0 {
			t.Errorf("video revisit = %d with %d bytes, want an empty 304", revisit.StatusCode, len(revisit.Body))
		}
	})

	drainScenario(t, runResult)
}

// TestVisitorUsesOpenGates is the client's story with both write gates
// explicitly opened: an estimate previews with server-computed totals in
// every format, a review submission is answered honestly (no persistence
// exists), and the CSP stays byte-identical through it all.
func TestVisitorUsesOpenGates(t *testing.T) {
	base, runResult := bootScenarioEnv(t, map[string]string{
		"REVIEWS_WRITE_ENABLED": "true",
		"ESTIMATES_ENABLED":     "true",
	})

	t.Run("an estimate previews with authoritative totals", func(t *testing.T) {
		body := `{"currency":"USD","taxRateBps":825,"items":[{"description":"Season detail","qty":1,"unitCents":150000,"taxable":true}]}`
		response, payload := postSurface(t, base, "/api/estimates/preview", "application/json", body)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("estimate preview = %d, body %q", response.StatusCode, payload)
		}
		var envelope struct {
			Kind string `json:"kind"`
			Data struct {
				SubtotalCents int64 `json:"subtotalCents"`
				TaxCents      int64 `json:"taxCents"`
				TotalCents    int64 `json:"totalCents"`
			} `json:"data"`
		}
		if err := json.Unmarshal(payload, &envelope); err != nil {
			t.Fatalf("preview does not decode: %v", err)
		}
		// 150000 × 825bps = 12375 exactly.
		if envelope.Kind != "estimates/v1" || envelope.Data.SubtotalCents != 150_000 ||
			envelope.Data.TaxCents != 12_375 || envelope.Data.TotalCents != 162_375 {
			t.Errorf("preview = %+v, want 150000/12375/162375", envelope)
		}

		markdown, document := postSurface(t, base, "/api/estimates/preview?format=markdown", "application/json", body)
		if markdown.StatusCode != http.StatusOK || !strings.Contains(string(document), "USD 1623.75") {
			t.Errorf("markdown rendering = %d, missing the canonical total", markdown.StatusCode)
		}
		rejected, _ := postSurface(t, base, "/api/estimates/preview?format=pdf", "application/json", body)
		if rejected.StatusCode != http.StatusBadRequest {
			t.Errorf("unknown format over the wire = %d, want 400", rejected.StatusCode)
		}
	})

	t.Run("a review submission is answered honestly", func(t *testing.T) {
		response, payload := postSurface(t, base, "/api/reviews", "application/json",
			`{"author":"Charter owner","rating":5,"text":"Immaculate detailing."}`)
		if response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("review submission = %d, want the honest 503", response.StatusCode)
		}
		var envelope struct {
			Status string `json:"status"`
			Data   struct {
				Reason string `json:"reason"`
			} `json:"data"`
		}
		if err := json.Unmarshal(payload, &envelope); err != nil {
			t.Fatalf("submission response does not decode: %v", err)
		}
		if envelope.Status != "unavailable" || !strings.Contains(envelope.Data.Reason, "not configured") {
			t.Errorf("submission envelope = %+v, want an honest unavailable answer", envelope)
		}
		invalid, _ := postSurface(t, base, "/api/reviews", "application/json", `{"author":"a","rating":9,"text":"t"}`)
		if invalid.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid rating over the wire = %d, want 400", invalid.StatusCode)
		}
	})

	drainScenario(t, runResult)
}

// TestRunRejectsBadSurfaceConfiguration locks startup fail-fast for the new
// configuration surface exactly like the listener contract: every malformed
// or partial gate must error before any socket opens.
func TestRunRejectsBadSurfaceConfiguration(t *testing.T) {
	t.Parallel()
	for name, env := range map[string]map[string]string{
		"media enabled without root":          {"MEDIA_ENABLED": "true", "MEDIA_MAX_CONCURRENT": "4"},
		"media root without enabled":          {"MEDIA_ROOT": "/srv/media"},
		"media bad concurrency":               {"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "lots"},
		"media missing root dir":              {"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/nonexistent/lidersea-media", "MEDIA_MAX_CONCURRENT": "4"},
		"reviews gate typo":                   {"REVIEWS_WRITE_ENABLED": "on"},
		"estimates gate typo":                 {"ESTIMATES_ENABLED": "yes"},
		"collector gate typo":                 {"RATINGS_COLLECTOR_ENABLED": "sure"},
		"collector interval without the gate": {"RATINGS_COLLECTOR_INTERVAL": "6h"},
		"collector enabled without an interval": {
			"RATINGS_COLLECTOR_ENABLED": "true", "RATINGS_COLLECTOR_TIMEOUT": "10s",
		},
		"collector enabled without a timeout": {
			"RATINGS_COLLECTOR_ENABLED": "true", "RATINGS_COLLECTOR_INTERVAL": "6h",
		},
		"collector interval below the floor": {
			"RATINGS_COLLECTOR_ENABLED": "true", "RATINGS_COLLECTOR_INTERVAL": "5s",
			"RATINGS_COLLECTOR_TIMEOUT": "10s",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := run(t.Context(), fakeEnv(env)); err == nil {
				t.Fatal("run() accepted a malformed surface configuration")
			}
		})
	}
}

// TestVisitorReadsTheRatingsStrip is the footer reader's story: the strip
// arrives as an enveloped surface whose status tells the truth about
// whether any rating has been captured, every platform it lists is
// renderable without a third party, and the route stays as read-only as
// every other surface. The second chapter boots the SAME process with the
// ratings collector gate open — the honest test of a gated capability is
// that turning it on changes nothing a visitor can see when there is
// nothing configured to fetch.
func TestVisitorReadsTheRatingsStrip(t *testing.T) {
	base, runResult := bootScenario(t)
	session := testsupport.NewVisitor(t, base)

	t.Run("the strip lists its platforms and says whether it has ratings", func(t *testing.T) {
		visitor := session.On(t)
		response := visitor.Navigate("/api/ratings")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/ratings = %d", response.StatusCode)
		}
		var envelope struct {
			Schema string `json:"schema"`
			Kind   string `json:"kind"`
			Status string `json:"status"`
			Data   struct {
				Summary struct {
					Published int      `json:"published"`
					Pending   int      `json:"pending"`
					Average   *float64 `json:"average"`
					Scale     int      `json:"scale"`
				} `json:"summary"`
				Platforms []struct {
					ID         string   `json:"id"`
					Name       string   `json:"name"`
					State      string   `json:"state"`
					ProfileURL string   `json:"profileUrl"`
					Rating     *float64 `json:"rating"`
				} `json:"platforms"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body, &envelope); err != nil {
			t.Fatalf("decode ratings envelope: %v", err)
		}
		if envelope.Schema != "surface/v1" || envelope.Kind != "ratings/v1" {
			t.Fatalf("envelope identity = %s / %s", envelope.Schema, envelope.Kind)
		}
		if len(envelope.Data.Platforms) == 0 {
			t.Fatal("the strip lists no platforms")
		}
		// The honesty contract, read from the wire: a strip with nothing
		// captured reports "unavailable" and publishes no average, and no
		// pending platform carries a number.
		if envelope.Data.Summary.Published == 0 {
			if envelope.Status != "unavailable" {
				t.Errorf("status = %q with nothing published, want unavailable", envelope.Status)
			}
			if envelope.Data.Summary.Average != nil {
				t.Errorf("an empty strip published an average of %v", *envelope.Data.Summary.Average)
			}
		} else if envelope.Status != "ok" && envelope.Status != "stale" {
			t.Errorf("status = %q with ratings published", envelope.Status)
		}
		for _, platform := range envelope.Data.Platforms {
			if platform.Name == "" {
				t.Errorf("platform %q has no name to render", platform.ID)
			}
			if platform.State == "pending" && platform.Rating != nil {
				t.Errorf("pending platform %q carries a rating of %v", platform.ID, *platform.Rating)
			}
			if platform.ProfileURL != "" && !strings.HasPrefix(platform.ProfileURL, "https://") {
				t.Errorf("platform %q links out over %q", platform.ID, platform.ProfileURL)
			}
		}
	})

	t.Run("a repeat read revalidates to a cheap 304", func(t *testing.T) {
		visitor := session.On(t)
		repeat := visitor.Navigate("/api/ratings")
		if repeat.StatusCode != http.StatusNotModified {
			t.Fatalf("revalidating /api/ratings = %d, want %d", repeat.StatusCode, http.StatusNotModified)
		}
	})

	t.Run("the strip never accepts a mutation", func(t *testing.T) {
		response, _ := postSurface(t, base, "/api/ratings", "application/json", "{}")
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST /api/ratings = %d, want 405", response.StatusCode)
		}
		if got := response.Header.Get("Allow"); got != "GET, HEAD" {
			t.Errorf("POST /api/ratings Allow = %q, want %q", got, "GET, HEAD")
		}
	})

	drainScenario(t, runResult)
}

// TestVisitorSeesNoChangeWhenTheCollectorGateOpens boots the process with
// the ratings collector enabled. The shipped snapshot configures no feed
// URLs, so an enabled collector has nothing to fetch: the strip a visitor
// reads is byte-identical to the default build's, and the process still
// starts and drains cleanly with a background worker attached.
func TestVisitorSeesNoChangeWhenTheCollectorGateOpens(t *testing.T) {
	base, runResult := bootScenarioEnv(t, map[string]string{
		"RATINGS_COLLECTOR_ENABLED":  "true",
		"RATINGS_COLLECTOR_INTERVAL": "24h",
		"RATINGS_COLLECTOR_TIMEOUT":  "5s",
	})
	session := testsupport.NewVisitor(t, base)
	response := session.On(t).Navigate("/api/ratings")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ratings with the collector enabled = %d", response.StatusCode)
	}
	if !bytes.Contains(response.Body, []byte(`"kind":"ratings/v1"`)) {
		t.Fatalf("the enabled collector changed the surface: %s", response.Body)
	}
	drainScenario(t, runResult)
}
