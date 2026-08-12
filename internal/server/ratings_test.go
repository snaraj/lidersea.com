// Ratings-delivery tests pin the boundary between the ratings domain and
// the surface envelope: which status a snapshot earns, what the response
// tells caches, and the two things this route must never do — accept a
// mutation, or put operator plumbing in front of a visitor.

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaraj/lidersea.com/internal/ratings"
	"github.com/snaraj/lidersea.com/internal/ratings/collect"
	"github.com/snaraj/lidersea.com/internal/surface"
	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// ratingsFixture builds a snapshot store from an authored file, failing the
// test if the fixture itself is invalid — a fixture that cannot be built is
// a broken test, not a finding about the code.
func ratingsFixture(t *testing.T, file ratings.File) *ratings.Store {
	t.Helper()
	data, err := ratings.Build(file)
	if err != nil {
		t.Fatalf("build ratings fixture: %v", err)
	}
	return ratings.NewStore(data)
}

// publishedFile is a snapshot with one published platform and one pending
// one, captured at the given instant.
func publishedFile(captured string) ratings.File {
	return ratings.File{
		PublishedAt: "2026-08-12T00:00:00Z",
		Platforms: []ratings.FilePlatform{
			{
				ID: "google", Name: "Google", State: ratings.StatePublished,
				ProfileURL: "https://www.google.com/maps/place/example",
				// A POPULATED feed URL, deliberately: the served payload must
				// omit this field because it is operator plumbing, and an
				// assertion exercised only against empty values would pass
				// just as happily if the field were serialised with
				// omitempty. This fixture is what makes that assertion bite.
				FeedURL:      "https://www.google.com/lidersea-ratings.json",
				RatingTenths: 49, ReviewCount: 128, CapturedAt: captured,
			},
			{ID: "yelp", Name: "Yelp", State: ratings.StatePending},
		},
	}
}

// pendingFile is a snapshot shaped like the shipped one: platforms listed,
// no rating captured for any of them.
func pendingFile() ratings.File {
	return ratings.File{
		PublishedAt: "2026-08-12T00:00:00Z",
		Platforms: []ratings.FilePlatform{
			{ID: "google", Name: "Google", State: ratings.StatePending},
			{ID: "yelp", Name: "Yelp", State: ratings.StatePending},
		},
	}
}

// ratingsHandler builds the site handler around an explicit snapshot.
func ratingsHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	siteHandler, err := NewSite(testsupport.FrontendFS(), cfg)
	if err != nil {
		t.Fatalf("NewSite() error = %v", err)
	}
	return siteHandler
}

// TestRatingsSurfaceServesTheStrip pins the envelope the strip is delivered
// in and the payload's own shape.
func TestRatingsSurfaceServesTheStrip(t *testing.T) {
	t.Parallel()
	siteHandler := ratingsHandler(t, Config{Ratings: ratingsFixture(t, publishedFile("2026-08-11T12:00:00Z"))})
	response := getSurface(t, siteHandler, surface.Ratings.Route)
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", surface.Ratings.Route, response.Code)
	}

	var envelope struct {
		Schema      string       `json:"schema"`
		ID          string       `json:"id"`
		Kind        string       `json:"kind"`
		Title       string       `json:"title"`
		GeneratedAt string       `json:"generatedAt"`
		Status      string       `json:"status"`
		Data        ratings.Data `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode ratings envelope: %v", err)
	}
	if envelope.Schema != "surface/v1" || envelope.Kind != "ratings/v1" || envelope.ID != "ratings" {
		t.Errorf("envelope identity = %+v", envelope)
	}
	if envelope.Title == "" {
		t.Error("the ratings envelope carries no title")
	}
	// The envelope's instant is the snapshot's provenance, not the moment it
	// was served, so response bytes and their digest ETag stay stable.
	if envelope.GeneratedAt != "2026-08-12T00:00:00Z" {
		t.Errorf("generatedAt = %q, want the snapshot's own instant", envelope.GeneratedAt)
	}
	if len(envelope.Data.Platforms) != 2 || envelope.Data.Summary.Published != 1 {
		t.Errorf("payload = %+v", envelope.Data)
	}
	if envelope.Data.Platforms[0].Rating != 4.9 {
		t.Errorf("rating = %v, want 4.9", envelope.Data.Platforms[0].Rating)
	}
	// Operator plumbing never reaches a visitor.
	if strings.Contains(response.Body.String(), "feedUrl") {
		t.Errorf("the ratings payload exposes feed plumbing: %s", response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	// Perf budget: the strip is a footer band on every page view, so its
	// payload has a pinned ceiling like every other surface here.
	if size := response.Body.Len(); size > ratingsStripBudgetBytes {
		t.Errorf("ratings payload is %d bytes, over its %d-byte budget", size, ratingsStripBudgetBytes)
	}
}

// TestRatingsStatusFollowsFreshness pins the honesty mapping end to end: an
// empty strip answers "unavailable" instead of dressing nothing up as a
// result, a snapshot inside its refresh window answers "ok", and one past
// it answers "stale" rather than pretending to be current.
func TestRatingsStatusFollowsFreshness(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  func(t *testing.T) Config
		want surface.Status
	}{
		{
			name: "no ratings captured",
			cfg: func(t *testing.T) Config {
				return Config{Ratings: ratingsFixture(t, pendingFile())}
			},
			want: surface.StatusUnavailable,
		},
		{
			name: "published with no refresh contract",
			cfg: func(t *testing.T) Config {
				return Config{Ratings: ratingsFixture(t, publishedFile("2020-01-01T00:00:00Z"))}
			},
			want: surface.StatusOK,
		},
		{
			name: "published inside the refresh window",
			cfg: func(t *testing.T) Config {
				return Config{
					Ratings:          ratingsFixture(t, publishedFile(time.Now().UTC().Add(-time.Hour).Format(time.RFC3339))),
					RatingsCollector: collect.Config{Enabled: true, Interval: 6 * time.Hour, Timeout: time.Second},
				}
			},
			want: surface.StatusOK,
		},
		{
			name: "published past the refresh window",
			cfg: func(t *testing.T) Config {
				return Config{
					Ratings:          ratingsFixture(t, publishedFile("2020-01-01T00:00:00Z")),
					RatingsCollector: collect.Config{Enabled: true, Interval: 6 * time.Hour, Timeout: time.Second},
				}
			},
			want: surface.StatusStale,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			siteHandler := ratingsHandler(t, test.cfg(t))
			response := getSurface(t, siteHandler, surface.Ratings.Route)
			var envelope struct {
				Status surface.Status `json:"status"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode ratings envelope: %v", err)
			}
			if envelope.Status != test.want {
				t.Fatalf("status = %q, want %q", envelope.Status, test.want)
			}
		})
	}
}

// TestShippedRatingsSnapshotIsServedByDefault proves the production path:
// a handler built with no explicit store loads and validates the embedded
// snapshot itself and serves it.
func TestShippedRatingsSnapshotIsServedByDefault(t *testing.T) {
	t.Parallel()
	response := getSurface(t, testHandler(t), surface.Ratings.Route)
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", surface.Ratings.Route, response.Code)
	}
	var envelope struct {
		Data ratings.Data `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode ratings envelope: %v", err)
	}
	if len(envelope.Data.Platforms) == 0 {
		t.Fatal("the default build serves an empty ratings strip")
	}
	for _, platform := range envelope.Data.Platforms {
		if platform.ProfileURL != "" && !strings.HasPrefix(platform.ProfileURL, "https://") {
			t.Errorf("platform %q links out over %q", platform.ID, platform.ProfileURL)
		}
	}
}

// TestRatingsSurfaceCacheIdentity keeps the strip a proper cacheable
// resource: a stable digest ETag and working revalidation, because the
// snapshot's instant — not the serving moment — stamps the envelope.
func TestRatingsSurfaceCacheIdentity(t *testing.T) {
	t.Parallel()
	siteHandler := ratingsHandler(t, Config{Ratings: ratingsFixture(t, publishedFile("2026-08-11T12:00:00Z"))})
	first := getSurface(t, siteHandler, surface.Ratings.Route)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("the ratings surface carries no ETag")
	}
	repeat := getSurface(t, siteHandler, surface.Ratings.Route)
	if got := repeat.Header().Get("ETag"); got != etag {
		t.Fatalf("ETag changed between requests: %s then %s", etag, got)
	}

	revalidate := httptest.NewRequest(http.MethodGet, surface.Ratings.Route, nil)
	revalidate.Header.Set("If-None-Match", etag)
	conditional := httptest.NewRecorder()
	siteHandler.ServeHTTP(conditional, revalidate)
	if conditional.Code != http.StatusNotModified {
		t.Errorf("revalidating the strip = %d, want %d", conditional.Code, http.StatusNotModified)
	}
}

// TestRatingsSurfaceStaysReadOnlyWithEveryGateOpen is the ratings route's
// own slice of the sitewide mutation contract: opening the two documented
// write carve-outs must not make a THIRD route writable.
func TestRatingsSurfaceStaysReadOnlyWithEveryGateOpen(t *testing.T) {
	t.Parallel()
	siteHandler := ratingsHandler(t, Config{ReviewsWriteEnabled: true, EstimatesEnabled: true})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(method, surface.Ratings.Route, nil))
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405 with every gate open", method, surface.Ratings.Route, response.Code)
		}
		if got := response.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s %s Allow = %q, want %q", method, surface.Ratings.Route, got, "GET, HEAD")
		}
	}
}

// TestRatingsPublishedAtRefusesToInventAnInstant covers the defensive
// branch behind the envelope's provenance stamp. The instant is validated
// when a snapshot is built, so this state is unreachable through the
// surface; the branch exists so that if it ever became reachable the
// response would carry the zero instant rather than silently stamping the
// serving moment and claiming freshness it never had.
func TestRatingsPublishedAtRefusesToInventAnInstant(t *testing.T) {
	t.Parallel()
	if got := ratingsPublishedAt(ratings.Data{PublishedAt: "not an instant"}); !got.IsZero() {
		t.Fatalf("ratingsPublishedAt() = %v, want the zero instant", got)
	}
	valid := ratingsPublishedAt(ratings.Data{PublishedAt: "2026-08-12T00:00:00Z"})
	if valid.UTC().Format(time.RFC3339) != "2026-08-12T00:00:00Z" {
		t.Fatalf("ratingsPublishedAt() = %v, want the snapshot instant", valid)
	}
}

// TestRatingsStatusMappingIsTotal keeps the freshness-to-status table
// exhaustive: an unmapped verdict would serve an empty status, and an empty
// status is a lie the envelope has no vocabulary for.
func TestRatingsStatusMappingIsTotal(t *testing.T) {
	t.Parallel()
	for _, freshness := range []ratings.Freshness{
		ratings.FreshnessCurrent,
		ratings.FreshnessAged,
		ratings.FreshnessNoRatings,
	} {
		if status, mapped := ratingsStatus[freshness]; !mapped || status == "" {
			t.Errorf("freshness %q maps to %q (mapped=%t)", freshness, status, mapped)
		}
	}
	if len(ratingsStatus) != 3 {
		t.Errorf("the freshness mapping holds %d entries, want one per verdict", len(ratingsStatus))
	}
}
