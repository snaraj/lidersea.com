// Package collect's suite proves the two properties that make an outbound
// capability safe to ship on a deny-egress origin: every refusal keeps the
// data the site already had, and no input — feed body, redirect, or data
// file — can reach a host nobody approved.
package collect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/snaraj/lidersea.com/internal/ratings"
)

// feedURL is an allowlisted Google feed address every fetch test uses. No
// request ever leaves the process: the transport below answers them all.
const feedURL = "https://www.google.com/lidersea-ratings.json"

// roundTripFunc adapts a function to http.RoundTripper so a test can answer
// a request with exact bytes, headers, and status — including shapes a real
// server would struggle to produce on demand.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip answers one request.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// respond builds a canned response with a status, content type, and body.
func respond(request *http.Request, status int, contentType, body string) *http.Response {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

// testConfig is an enabled configuration with the shortest legal timings,
// so no test waits on a clock.
func testConfig() Config {
	return Config{Enabled: true, Interval: MinInterval, Timeout: MinTimeout}
}

// snapshotWithFeed builds a valid snapshot whose Google entry carries feed,
// so a pass has exactly one platform to read.
func snapshotWithFeed(t *testing.T, feed string, googleState string) ratings.Data {
	t.Helper()
	google := ratings.FilePlatform{
		ID: "google", Name: "Google", State: googleState,
		ProfileURL: "https://www.google.com/maps/place/example",
		FeedURL:    feed,
	}
	if googleState == ratings.StatePublished {
		google.RatingTenths = 40
		google.ReviewCount = 10
		google.CapturedAt = "2026-08-01T00:00:00Z"
	}
	data, err := ratings.Build(ratings.File{
		PublishedAt: "2026-08-12T00:00:00Z",
		Platforms: []ratings.FilePlatform{
			google,
			{ID: "yelp", Name: "Yelp", State: ratings.StatePending},
		},
	})
	if err != nil {
		t.Fatalf("build snapshot fixture: %v", err)
	}
	return data
}

// TestConfigFromEnvIsFailClosed sweeps the environment door. The collector
// is enabled only by the complete, valid set; every partial or malformed
// set is a startup error rather than a half-configured background worker.
func TestConfigFromEnvIsFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr bool
	}{
		{name: "absent is disabled", env: map[string]string{}},
		{name: "explicitly false is disabled", env: map[string]string{envEnabled: "false"}},
		{
			name: "enabled with a complete set",
			env:  map[string]string{envEnabled: "true", envInterval: "6h", envTimeout: "10s"},
			want: Config{Enabled: true, Interval: 6 * time.Hour, Timeout: 10 * time.Second},
		},
		{
			name:    "interval without the gate",
			env:     map[string]string{envInterval: "6h"},
			wantErr: true,
		},
		{
			name:    "timeout without the gate",
			env:     map[string]string{envEnabled: "false", envTimeout: "10s"},
			wantErr: true,
		},
		{
			name:    "gate without an interval",
			env:     map[string]string{envEnabled: "true", envTimeout: "10s"},
			wantErr: true,
		},
		{
			name:    "gate without a timeout",
			env:     map[string]string{envEnabled: "true", envInterval: "6h"},
			wantErr: true,
		},
		{
			name:    "unparseable gate",
			env:     map[string]string{envEnabled: "yes"},
			wantErr: true,
		},
		{
			name:    "unparseable interval",
			env:     map[string]string{envEnabled: "true", envInterval: "soon", envTimeout: "10s"},
			wantErr: true,
		},
		{
			name:    "interval below the floor",
			env:     map[string]string{envEnabled: "true", envInterval: "1m", envTimeout: "10s"},
			wantErr: true,
		},
		{
			name:    "interval above the ceiling",
			env:     map[string]string{envEnabled: "true", envInterval: "9000h", envTimeout: "10s"},
			wantErr: true,
		},
		{
			name:    "timeout below the floor",
			env:     map[string]string{envEnabled: "true", envInterval: "6h", envTimeout: "1ms"},
			wantErr: true,
		},
		{
			name:    "timeout above the ceiling",
			env:     map[string]string{envEnabled: "true", envInterval: "6h", envTimeout: "5m"},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ConfigFromEnv(func(name string) string { return test.env[name] })
			if test.wantErr {
				if err == nil {
					t.Fatalf("ConfigFromEnv() = %+v, want an error", got)
				}
				if got.Enabled {
					t.Fatalf("a rejected configuration reported enabled: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ConfigFromEnv() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ConfigFromEnv() = %+v, want %+v", got, test.want)
			}
		})
	}
}

// TestReadRefusalMatrix sweeps every way a feed can fail to be a feed. Each
// refusal is a named error, so a caller — and a log reader — learns which
// rule stopped the read without a byte of the third party's response.
func TestReadRefusalMatrix(t *testing.T) {
	t.Parallel()
	oversized := `{"ratingTenths":49,"reviewCount":1,"capturedAt":"2026-08-12T00:00:00Z","` +
		strings.Repeat("x", MaxFeedBytes) + `":1}`
	tests := []struct {
		name      string
		transport roundTripFunc
		want      error
	}{
		{
			name: "redirect is refused, never followed",
			transport: func(request *http.Request) (*http.Response, error) {
				response := respond(request, http.StatusFound, "application/json", "")
				response.Header.Set("Location", "https://www.google.com/elsewhere.json")
				return response, nil
			},
			want: ErrRedirectRefused,
		},
		{
			name: "non-200",
			transport: func(request *http.Request) (*http.Response, error) {
				return respond(request, http.StatusTeapot, "application/json", "{}"), nil
			},
			want: ErrFeedStatus,
		},
		{
			name: "wrong content type",
			transport: func(request *http.Request) (*http.Response, error) {
				return respond(request, http.StatusOK, "text/html; charset=utf-8", "{}"), nil
			},
			want: ErrFeedContentType,
		},
		{
			name: "no content type",
			transport: func(request *http.Request) (*http.Response, error) {
				return respond(request, http.StatusOK, "", "{}"), nil
			},
			want: ErrFeedContentType,
		},
		{
			name: "body over the cap",
			transport: func(request *http.Request) (*http.Response, error) {
				return respond(request, http.StatusOK, "application/json", oversized), nil
			},
			want: ErrFeedTooLarge,
		},
		{
			name: "not JSON",
			transport: func(request *http.Request) (*http.Response, error) {
				return respond(request, http.StatusOK, "application/json", "not json"), nil
			},
			want: ErrFeedUnreadable,
		},
		{
			name: "unknown field",
			transport: func(request *http.Request) (*http.Response, error) {
				return respond(request, http.StatusOK, "application/json", `{"ratingTenths":49,"stars":5}`), nil
			},
			want: ErrFeedUnreadable,
		},
		{
			name: "two documents",
			transport: func(request *http.Request) (*http.Response, error) {
				return respond(request, http.StatusOK, "application/json", `{"ratingTenths":49} {"ratingTenths":10}`), nil
			},
			want: ErrFeedUnreadable,
		},
		{
			name: "unparseable feed address",
			transport: func(*http.Request) (*http.Response, error) {
				t.Error("the collector dialled an unparseable address")
				return nil, nil
			},
			want: ErrFeedUnreadable,
		},
		{
			name: "transport failure",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial refused")
			},
			want: ErrFeedUnreadable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			target := feedURL
			if test.name == "unparseable feed address" {
				target = "https://www.google.com/%zz"
			}
			collector := newCollector(testConfig(), test.transport)
			reading, err := collector.read(t.Context(), "google", target)
			if !errors.Is(err, test.want) {
				t.Fatalf("read() error = %v, want %v", err, test.want)
			}
			if reading != (Reading{}) {
				t.Fatalf("a refused read returned %+v", reading)
			}
		})
	}
}

// TestReadRefusesUnapprovedDestinationsWithoutDialling proves the allowlist
// is enforced BEFORE any connection is attempted: a URL nobody approved
// must not even produce a DNS lookup, let alone a request.
func TestReadRefusesUnapprovedDestinationsWithoutDialling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		platform string
		url      string
		want     error
	}{
		{name: "plain http", platform: "google", url: "http://www.google.com/f.json", want: ErrSchemeNotAllowed},
		{name: "file scheme", platform: "google", url: "file:///etc/passwd", want: ErrSchemeNotAllowed},
		{name: "foreign host", platform: "google", url: "https://feeds.example.invalid/f.json", want: ErrHostNotAllowed},
		{name: "another platform's host", platform: "google", url: "https://www.yelp.com/f.json", want: ErrHostNotAllowed},
		{name: "lookalike host", platform: "google", url: "https://www.google.com.evil.invalid/f.json", want: ErrHostNotAllowed},
		{name: "host with a port", platform: "google", url: "https://www.google.com:8443/f.json", want: ErrHostNotAllowed},
		{name: "unregistered platform", platform: "somewhere", url: "https://www.google.com/f.json", want: ErrHostNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			collector := newCollector(testConfig(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
				t.Errorf("the collector dialled %s despite the allowlist", request.URL)
				return respond(request, http.StatusOK, "application/json", "{}"), nil
			}))
			if _, err := collector.read(t.Context(), test.platform, test.url); !errors.Is(err, test.want) {
				t.Fatalf("read() error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestNewBuildsTheProductionCollector guards against the suite's own
// transport injection hiding a real defect: the exported constructor must
// produce a collector that enforces the package allowlist, and it must do
// so without reaching the network.
func TestNewBuildsTheProductionCollector(t *testing.T) {
	t.Parallel()
	collector := New(testConfig())
	if _, err := collector.read(t.Context(), "google", "https://feeds.example.invalid/f.json"); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("the production collector accepted an unapproved host: %v", err)
	}
	if collector.client.CheckRedirect == nil {
		t.Fatal("the production collector follows redirects")
	}
	if err := collector.client.CheckRedirect(nil, nil); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("redirect policy = %v, want %v", err, ErrRedirectRefused)
	}
}

// TestCollectPublishesAGoodReading is the happy path: a valid feed moves a
// pending platform to published, stamps the pass instant, and leaves every
// other platform alone.
func TestCollectPublishesAGoodReading(t *testing.T) {
	t.Parallel()
	collector := newCollector(testConfig(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return respond(request, http.StatusOK, "application/json",
			`{"ratingTenths":49,"reviewCount":128,"capturedAt":"2026-08-12T04:00:00Z"}`), nil
	}))
	now := time.Date(2026, time.August, 12, 6, 0, 0, 0, time.UTC)
	collected := collector.Collect(t.Context(), snapshotWithFeed(t, feedURL, ratings.StatePending), now)

	if collected.PublishedAt != now.Format(time.RFC3339) {
		t.Errorf("publishedAt = %q, want the pass instant %q", collected.PublishedAt, now.Format(time.RFC3339))
	}
	google := collected.Platforms[0]
	if google.State != ratings.StatePublished || google.Rating != 4.9 || google.ReviewCount != 128 {
		t.Fatalf("collected platform = %+v", google)
	}
	if google.CapturedAt != "2026-08-12T04:00:00Z" {
		t.Errorf("capturedAt = %q, want the platform's own instant", google.CapturedAt)
	}
	if collected.Platforms[1].State != ratings.StatePending {
		t.Errorf("a platform with no feed changed state: %+v", collected.Platforms[1])
	}
	if collected.Summary.Published != 1 || collected.Summary.Reviews != 128 {
		t.Errorf("summary was not recomputed: %+v", collected.Summary)
	}
}

// TestCollectIsFailSoft is the property the whole design exists for: no
// failure mode may blank a rating the site already publishes. Each row
// fails differently; every one must leave the snapshot exactly as it was.
func TestCollectIsFailSoft(t *testing.T) {
	t.Parallel()
	tests := map[string]roundTripFunc{
		"transport failure": func(*http.Request) (*http.Response, error) {
			return nil, errors.New("no route to host")
		},
		"server error": func(request *http.Request) (*http.Response, error) {
			return respond(request, http.StatusInternalServerError, "application/json", "{}"), nil
		},
		"garbage body": func(request *http.Request) (*http.Response, error) {
			return respond(request, http.StatusOK, "application/json", "<html>"), nil
		},
		"reading outside the rating range": func(request *http.Request) (*http.Response, error) {
			return respond(request, http.StatusOK, "application/json",
				`{"ratingTenths":99,"reviewCount":5,"capturedAt":"2026-08-12T04:00:00Z"}`), nil
		},
		"reading with no reviews behind it": func(request *http.Request) (*http.Response, error) {
			return respond(request, http.StatusOK, "application/json",
				`{"ratingTenths":49,"reviewCount":0,"capturedAt":"2026-08-12T04:00:00Z"}`), nil
		},
		"reading with a local capture offset": func(request *http.Request) (*http.Response, error) {
			return respond(request, http.StatusOK, "application/json",
				`{"ratingTenths":49,"reviewCount":5,"capturedAt":"2026-08-12T04:00:00+02:00"}`), nil
		},
	}
	for name, transport := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			before := snapshotWithFeed(t, feedURL, ratings.StatePublished)
			collector := newCollector(testConfig(), transport)
			after := collector.Collect(t.Context(), before, time.Now().UTC())
			if after.PublishedAt != before.PublishedAt {
				t.Errorf("publishedAt moved on a failed pass: %q", after.PublishedAt)
			}
			if len(after.Platforms) != len(before.Platforms) {
				t.Fatalf("the strip changed length: %d, want %d", len(after.Platforms), len(before.Platforms))
			}
			for index, platform := range after.Platforms {
				if platform != before.Platforms[index] {
					t.Errorf("platform %q changed on a failed pass: %+v, want %+v",
						platform.ID, platform, before.Platforms[index])
				}
			}
		})
	}
}

// TestCollectWithNoFeedsIsANoOp is the shipped configuration: the embedded
// snapshot carries no feed URLs, so an enabled collector reads nothing,
// changes nothing, and — critically — never opens a connection.
func TestCollectWithNoFeedsIsANoOp(t *testing.T) {
	t.Parallel()
	before := snapshotWithFeed(t, "", ratings.StatePublished)
	collector := newCollector(testConfig(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Errorf("the collector dialled %s with no feed configured", request.URL)
		return respond(request, http.StatusOK, "application/json", "{}"), nil
	}))
	after := collector.Collect(t.Context(), before, time.Now().UTC())
	if after.PublishedAt != before.PublishedAt || len(after.Platforms) != len(before.Platforms) {
		t.Fatalf("a no-op pass changed the snapshot: %+v", after)
	}
}

// TestShippedSnapshotConfiguresNoFeeds pins the honest claim the surface
// makes: nothing in the binary points the collector anywhere, so enabling
// the gate on a stock build fetches nothing at all.
func TestShippedSnapshotConfiguresNoFeeds(t *testing.T) {
	t.Parallel()
	snapshot, err := ratings.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	for _, platform := range snapshot.File().Platforms {
		if platform.FeedURL != "" {
			t.Errorf("platform %q ships with a feed URL; the collector would fetch on a stock build", platform.ID)
		}
	}
}

// TestRunStopsWithItsContext pins the lifecycle contract the process
// depends on: a disabled collector runs nothing, and an enabled one returns
// promptly when its context is cancelled, so shutdown is never held open.
func TestRunStopsWithItsContext(t *testing.T) {
	t.Parallel()
	t.Run("disabled runs nothing", func(t *testing.T) {
		t.Parallel()
		store := ratings.NewStore(snapshotWithFeed(t, "", ratings.StatePending))
		done := make(chan struct{})
		go func() {
			defer close(done)
			Run(t.Context(), Config{}, store)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run() with a disabled configuration did not return")
		}
	})

	t.Run("passes repeat on the refresh window", func(t *testing.T) {
		t.Parallel()
		// The interval is set on the struct directly, below the floor
		// ConfigFromEnv enforces, so the loop's tick path is exercised
		// without the suite waiting on a production-scale window. The
		// snapshot carries no feed URL, so the repeated passes touch no
		// network at all.
		store := ratings.NewStore(snapshotWithFeed(t, "", ratings.StatePending))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			Run(ctx, Config{Enabled: true, Interval: time.Millisecond, Timeout: MinTimeout}, store)
		}()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case <-deadline:
				t.Fatal("the collector loop did not keep running")
			case <-time.After(20 * time.Millisecond):
			}
			if store.Load().Summary.Pending == 2 {
				break
			}
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run() did not return within 5s of cancellation")
		}
	})

	t.Run("enabled returns on cancellation", func(t *testing.T) {
		t.Parallel()
		store := ratings.NewStore(snapshotWithFeed(t, "", ratings.StatePending))
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			Run(ctx, testConfig(), store)
		}()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run() did not return within 5s of cancellation")
		}
	})
}
