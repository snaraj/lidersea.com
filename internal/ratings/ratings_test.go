// Package ratings' suite proves the honesty rules the surface rests on: a
// half-filled platform is unrepresentable, an outbound URL can only ever
// name an allowlisted host, the summary is server math, and a snapshot that
// breaks any rule is rejected whole rather than partially served.
package ratings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// validFile is a complete, publishable snapshot every table row starts
// from. Rows mutate one thing, so each failure names exactly one rule.
func validFile() File {
	return File{
		PublishedAt: "2026-08-12T00:00:00Z",
		Platforms: []FilePlatform{
			{
				ID: "google", Name: "Google", State: StatePublished,
				ProfileURL: "https://www.google.com/maps/place/example",
				// Populated on purpose — see TestValidFileBuilds: the feed URL
				// must survive authoring and round-tripping while never
				// reaching the wire, and an all-empty fixture could not tell
				// "never serialised" from "empty and omitted".
				FeedURL:      "https://www.google.com/lidersea-ratings.json",
				RatingTenths: 48, ReviewCount: 120, CapturedAt: "2026-08-11T12:00:00Z",
			},
			{ID: "yelp", Name: "Yelp", State: StatePending},
		},
	}
}

// TestShippedSnapshotIsWellFormed proves the file the binary embeds passes
// every rule the server enforces at construction. It asserts STRUCTURE, not
// content: the owner publishes ratings by editing that file, and doing so
// must never break a test.
func TestShippedSnapshotIsWellFormed(t *testing.T) {
	t.Parallel()
	data, err := Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(data.Platforms) == 0 {
		t.Fatal("the shipped snapshot lists no platforms")
	}
	if data.Summary.Scale != Scale {
		t.Errorf("summary scale = %d, want %d", data.Summary.Scale, Scale)
	}
	if got := data.Summary.Published + data.Summary.Pending; got != len(data.Platforms) {
		t.Errorf("summary counts %d platforms, strip holds %d", got, len(data.Platforms))
	}
	seen := make(map[string]bool, len(data.Platforms))
	for _, platform := range data.Platforms {
		if seen[platform.ID] {
			t.Errorf("platform %q appears twice", platform.ID)
		}
		seen[platform.ID] = true
		if !RegisteredPlatform(platform.ID) {
			t.Errorf("platform %q has no host allowlist", platform.ID)
		}
		if platform.State != StatePublished && platform.State != StatePending {
			t.Errorf("platform %q is in state %q", platform.ID, platform.State)
		}
		if platform.State == StatePending && (platform.Rating != 0 || platform.ReviewCount != 0 || platform.CapturedAt != "") {
			t.Errorf("pending platform %q carries a rating", platform.ID)
		}
	}
	// The feed URL is operator plumbing and must never reach a visitor.
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(payload), "feedUrl") {
		t.Errorf("the served payload exposes feed plumbing: %s", payload)
	}
}

// TestSnapshotValidationMatrix is the fail-closed sweep. Each row breaks
// exactly one rule and must be rejected with that rule's error, because a
// snapshot is owner-edited text and a silent partial acceptance is how an
// invented number reaches a page.
func TestSnapshotValidationMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*File)
		want   error
	}{
		{name: "no platforms", mutate: func(f *File) { f.Platforms = nil }, want: ErrNoPlatforms},
		{
			name: "more platforms than the strip admits",
			mutate: func(f *File) {
				f.Platforms = make([]FilePlatform, MaxPlatforms+1)
			},
			want: ErrTooManyPlatforms,
		},
		{
			name:   "publishedAt is not an instant",
			mutate: func(f *File) { f.PublishedAt = "yesterday" },
			want:   ErrPublishedAtInstant,
		},
		{
			name:   "publishedAt carries a local offset",
			mutate: func(f *File) { f.PublishedAt = "2026-08-12T00:00:00+02:00" },
			want:   ErrPublishedAtInstant,
		},
		{
			name:   "platform id is not the documented shape",
			mutate: func(f *File) { f.Platforms[0].ID = "Google" },
			want:   ErrPlatformID,
		},
		{
			name:   "platform id repeats",
			mutate: func(f *File) { f.Platforms[1].ID = f.Platforms[0].ID },
			want:   ErrDuplicatePlatform,
		},
		{
			name:   "platform has no host allowlist",
			mutate: func(f *File) { f.Platforms[1].ID = "some-directory" },
			want:   ErrUnknownPlatform,
		},
		{
			name:   "platform name is empty",
			mutate: func(f *File) { f.Platforms[0].Name = "" },
			want:   ErrPlatformName,
		},
		{
			name:   "platform name exceeds the cap",
			mutate: func(f *File) { f.Platforms[0].Name = strings.Repeat("n", MaxNameBytes+1) },
			want:   ErrPlatformName,
		},
		{
			name:   "unknown state",
			mutate: func(f *File) { f.Platforms[1].State = "draft" },
			want:   ErrPlatformState,
		},
		{
			name:   "published without a profile URL",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "" },
			want:   ErrPublishedNeedsURL,
		},
		{
			name:   "published below the rating floor",
			mutate: func(f *File) { f.Platforms[0].RatingTenths = MinRatingTenths - 1 },
			want:   ErrRatingOutOfRange,
		},
		{
			name:   "published above the rating ceiling",
			mutate: func(f *File) { f.Platforms[0].RatingTenths = MaxRatingTenths + 1 },
			want:   ErrRatingOutOfRange,
		},
		{
			name:   "published with no reviews behind it",
			mutate: func(f *File) { f.Platforms[0].ReviewCount = 0 },
			want:   ErrReviewCountRange,
		},
		{
			name:   "published with an implausible review count",
			mutate: func(f *File) { f.Platforms[0].ReviewCount = MaxReviewCount + 1 },
			want:   ErrReviewCountRange,
		},
		{
			name:   "published without a capture instant",
			mutate: func(f *File) { f.Platforms[0].CapturedAt = "" },
			want:   ErrCaptureInstant,
		},
		{
			name:   "pending but carrying a rating",
			mutate: func(f *File) { f.Platforms[1].RatingTenths = 50 },
			want:   ErrPendingHasRating,
		},
		{
			name:   "pending but carrying a review count",
			mutate: func(f *File) { f.Platforms[1].ReviewCount = 3 },
			want:   ErrPendingHasRating,
		},
		{
			name:   "pending but carrying a capture instant",
			mutate: func(f *File) { f.Platforms[1].CapturedAt = "2026-08-11T12:00:00Z" },
			want:   ErrPendingHasRating,
		},
		{
			name:   "profile URL is not https",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "http://www.google.com/maps" },
			want:   ErrURLScheme,
		},
		{
			name:   "profile URL is a javascript URL",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "javascript:alert(1)" },
			want:   ErrURLScheme,
		},
		{
			name:   "profile URL host is off the allowlist",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "https://google.example.invalid/maps" },
			want:   ErrURLHost,
		},
		{
			name: "profile URL host belongs to another platform",
			mutate: func(f *File) {
				f.Platforms[0].ProfileURL = "https://www.yelp.com/biz/example"
			},
			want: ErrURLHost,
		},
		{
			name:   "profile URL carries credentials",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "https://user:pass@www.google.com/maps" },
			want:   ErrURLShape,
		},
		{
			name:   "profile URL carries a fragment",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "https://www.google.com/maps#x" },
			want:   ErrURLShape,
		},
		{
			name:   "profile URL is unparseable",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "https://www.google.com/%zz" },
			want:   ErrURLShape,
		},
		{
			name:   "profile URL carries a control byte",
			mutate: func(f *File) { f.Platforms[0].ProfileURL = "https://www.google.com/ma\nps" },
			want:   ErrURLShape,
		},
		{
			name: "profile URL exceeds the length cap",
			mutate: func(f *File) {
				f.Platforms[0].ProfileURL = "https://www.google.com/maps/" + strings.Repeat("p", MaxURLBytes)
			},
			want: ErrURLLength,
		},
		{
			name:   "feed URL host is off the allowlist",
			mutate: func(f *File) { f.Platforms[0].FeedURL = "https://feeds.example.invalid/google.json" },
			want:   ErrURLHost,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			file := validFile()
			test.mutate(&file)
			data, err := Build(file)
			if !errors.Is(err, test.want) {
				t.Fatalf("Build() error = %v, want %v", err, test.want)
			}
			if data.Platforms != nil || data.Summary.Published != 0 {
				t.Fatalf("a rejected snapshot returned data: %+v", data)
			}
		})
	}
}

// TestValidFileBuilds keeps the matrix above honest: the unmutated base
// must succeed, or every row would be passing for the wrong reason.
func TestValidFileBuilds(t *testing.T) {
	t.Parallel()
	data, err := Build(validFile())
	if err != nil {
		t.Fatalf("Build(validFile()) error = %v", err)
	}
	if len(data.Platforms) != 2 || data.Summary.Published != 1 || data.Summary.Pending != 1 {
		t.Fatalf("unexpected build result: %+v", data)
	}
	if data.Platforms[0].Rating != 4.8 {
		t.Errorf("rating = %v, want 4.8 derived from 48 tenths", data.Platforms[0].Rating)
	}
	if data.Platforms[1].Rating != 0 || data.Platforms[1].ReviewCount != 0 {
		t.Errorf("pending platform carries values: %+v", data.Platforms[1])
	}
	// The feed URL is operator plumbing: it must survive authoring — the
	// collector reads it — and must never reach a visitor. The fixture
	// carries a NON-EMPTY one, so this assertion fails if the field is ever
	// given a JSON name, with or without omitempty.
	if data.Platforms[0].FeedURL == "" {
		t.Fatal("the fixture lost its feed URL; the serialisation assertion below would be vacuous")
	}
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if strings.Contains(string(payload), "feedUrl") || strings.Contains(string(payload), "lidersea-ratings.json") {
		t.Fatalf("the served payload exposes feed plumbing: %s", payload)
	}
}

// TestDecodeRejectsMalformedDocuments covers the JSON door itself, which
// the file-shape matrix above cannot reach.
func TestDecodeRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"not json":            "not json at all",
		"wrong root type":     `[]`,
		"trailing document":   `{"publishedAt":"2026-08-12T00:00:00Z","platforms":[]} {}`,
		"wrong field type":    `{"publishedAt":1,"platforms":[]}`,
		"empty":               ``,
		"unknown top field":   `{"publishedAt":"2026-08-12T00:00:00Z","platforms":[],"extra":1}`,
		"unknown inner field": `{"publishedAt":"2026-08-12T00:00:00Z","platforms":[{"id":"google","typo":1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Decode([]byte(document)); err == nil {
				t.Fatal("Decode() accepted a malformed document")
			}
		})
	}
}

// TestDecodeNamesUnknownFields proves the unknown-field refusal is its own
// answer, not folded into the generic parse failure: a typo in a field name
// would otherwise silently publish a default.
func TestDecodeNamesUnknownFields(t *testing.T) {
	t.Parallel()
	document := `{"publishedAt":"2026-08-12T00:00:00Z","platforms":[],"ratingTenths":50}`
	if _, err := Decode([]byte(document)); !errors.Is(err, ErrSnapshotUnknownKeys) {
		t.Fatalf("Decode() error = %v, want %v", err, ErrSnapshotUnknownKeys)
	}
}

// TestSummaryIsWeightedServerMath pins the aggregate as a server
// computation: weighted by review count, derived in integer tenths, and
// rounded half up so the value is identical on every platform.
func TestSummaryIsWeightedServerMath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		ratings     [2]int
		counts      [2]int
		wantAverage float64
		wantReviews int
	}{
		{name: "weighted toward the busier platform", ratings: [2]int{50, 40}, counts: [2]int{300, 100}, wantAverage: 4.8, wantReviews: 400},
		{name: "equal weights", ratings: [2]int{50, 40}, counts: [2]int{100, 100}, wantAverage: 4.5, wantReviews: 200},
		{name: "rounds half up", ratings: [2]int{45, 44}, counts: [2]int{1, 1}, wantAverage: 4.5, wantReviews: 2},
		{name: "rounds down below the half", ratings: [2]int{44, 44}, counts: [2]int{1, 2}, wantAverage: 4.4, wantReviews: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			file := validFile()
			file.Platforms[1] = FilePlatform{
				ID: "yelp", Name: "Yelp", State: StatePublished,
				ProfileURL: "https://www.yelp.com/biz/example",
				CapturedAt: "2026-08-11T12:00:00Z",
			}
			file.Platforms[0].RatingTenths, file.Platforms[1].RatingTenths = test.ratings[0], test.ratings[1]
			file.Platforms[0].ReviewCount, file.Platforms[1].ReviewCount = test.counts[0], test.counts[1]
			data, err := Build(file)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if data.Summary.Average != test.wantAverage {
				t.Errorf("average = %v, want %v", data.Summary.Average, test.wantAverage)
			}
			if data.Summary.Reviews != test.wantReviews {
				t.Errorf("reviews = %d, want %d", data.Summary.Reviews, test.wantReviews)
			}
			if data.Summary.Published != 2 {
				t.Errorf("published = %d, want 2", data.Summary.Published)
			}
		})
	}
}

// TestNothingPublishedOmitsTheAverage is the honesty rule in its sharpest
// form: an absent average must be ABSENT, because a zero there reads as a
// rating of zero rather than as no data.
func TestNothingPublishedOmitsTheAverage(t *testing.T) {
	t.Parallel()
	file := validFile()
	file.Platforms[0] = FilePlatform{ID: "google", Name: "Google", State: StatePending}
	data, err := Build(file)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if data.Summary.Average != 0 || data.Summary.Published != 0 {
		t.Fatalf("unexpected summary: %+v", data.Summary)
	}
	payload, err := json.Marshal(data.Summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	if strings.Contains(string(payload), "average") {
		t.Fatalf("an empty strip published an average: %s", payload)
	}
}

// TestFreshness pins the presentation verdict the serving layer maps onto
// the envelope's status.
func TestFreshness(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
	published := func(captured string) Data {
		file := validFile()
		file.Platforms[0].CapturedAt = captured
		data, err := Build(file)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		return data
	}
	empty := func() Data {
		file := validFile()
		file.Platforms[0] = FilePlatform{ID: "google", Name: "Google", State: StatePending}
		data, err := Build(file)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		return data
	}

	tests := []struct {
		name   string
		data   Data
		maxAge time.Duration
		want   Freshness
	}{
		{name: "nothing published", data: empty(), maxAge: time.Hour, want: FreshnessNoRatings},
		{name: "no refresh contract", data: published("2020-01-01T00:00:00Z"), want: FreshnessCurrent},
		{name: "inside the window", data: published("2026-08-11T23:00:00Z"), maxAge: 6 * time.Hour, want: FreshnessCurrent},
		{name: "exactly at the window", data: published("2026-08-11T18:00:00Z"), maxAge: 6 * time.Hour, want: FreshnessCurrent},
		{name: "past the window", data: published("2026-08-01T00:00:00Z"), maxAge: 6 * time.Hour, want: FreshnessAged},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.data.Freshness(now, test.maxAge); got != test.want {
				t.Fatalf("Freshness() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestAllowedHostIsClosed pins the outbound-destination gate. It is the one
// rule no data file and no environment setting can widen.
func TestAllowedHostIsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		platform string
		host     string
		want     bool
	}{
		{platform: "google", host: "www.google.com", want: true},
		{platform: "google", host: "g.page", want: true},
		{platform: "google", host: "www.yelp.com"},
		{platform: "google", host: "evil.www.google.com"},
		{platform: "google", host: "www.google.com.evil.invalid"},
		{platform: "google", host: "WWW.GOOGLE.COM"},
		{platform: "google", host: "www.google.com:8443"},
		{platform: "yelp", host: "www.yelp.com", want: true},
		{platform: "unregistered", host: "www.google.com"},
		{platform: "", host: ""},
	}
	for _, test := range tests {
		t.Run(test.platform+"/"+test.host, func(t *testing.T) {
			t.Parallel()
			if got := AllowedHost(test.platform, test.host); got != test.want {
				t.Fatalf("AllowedHost(%q, %q) = %t, want %t", test.platform, test.host, got, test.want)
			}
		})
	}
	if RegisteredPlatform("unregistered") {
		t.Error(`RegisteredPlatform("unregistered") = true`)
	}
}

// TestFileRoundTripsThroughBuild proves the collector's re-authorisation
// path is lossless: taking a served snapshot back to its authored form and
// rebuilding it yields the same payload, so a refresh that changes nothing
// changes nothing.
func TestFileRoundTripsThroughBuild(t *testing.T) {
	t.Parallel()
	original, err := Build(validFile())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	rebuilt, err := Build(original.File())
	if err != nil {
		t.Fatalf("Build(original.File()) error = %v", err)
	}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal original: %v", err)
	}
	after, err := json.Marshal(rebuilt)
	if err != nil {
		t.Fatalf("marshal rebuilt: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("round trip changed the payload:\n before %s\n after  %s", before, after)
	}
}

// TestStoreServesTheLatestSnapshot covers the seam the gated collector
// writes through.
func TestStoreServesTheLatestSnapshot(t *testing.T) {
	t.Parallel()
	first, err := Build(validFile())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	store := NewStore(first)
	if got := store.Load(); got.PublishedAt != first.PublishedAt {
		t.Fatalf("Load() = %q, want %q", got.PublishedAt, first.PublishedAt)
	}
	next := validFile()
	next.PublishedAt = "2026-08-12T06:00:00Z"
	replacement, err := Build(next)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	store.Replace(replacement)
	if got := store.Load(); got.PublishedAt != replacement.PublishedAt {
		t.Fatalf("Load() after Replace = %q, want %q", got.PublishedAt, replacement.PublishedAt)
	}
}
