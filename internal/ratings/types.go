// types.go collects the package's type declarations and package-level
// const/var blocks so the ratings/v1 data model, the outbound-host
// allowlist, and the validation vocabulary can be surveyed in one place.
// Decoding, validation, and summary math stay in ratings.go.

package ratings

import (
	_ "embed"
	"errors"
	"regexp"
	"sync/atomic"
)

// Scale is the star scale every supported platform publishes on. It is a
// property of the platforms, not a setting: a snapshot that claimed another
// scale would make the ratings incomparable and is rejected.
const Scale = 5

// Rating bounds in integer tenths. Ratings are stored and validated as
// integers so a snapshot is exact on every platform and its JSON is
// byte-stable; the served one-decimal number is derived, never authored.
const (
	// MinRatingTenths is a one-star rating.
	MinRatingTenths = 10
	// MaxRatingTenths is a five-star rating.
	MaxRatingTenths = Scale * 10
)

// Snapshot field caps. They bound what a hand-edited data file can put in
// front of a visitor, so a typo is a startup failure rather than a page of
// runaway text.
const (
	// MaxNameBytes caps a platform's display name.
	MaxNameBytes = 40
	// MaxURLBytes caps a profile or feed URL.
	MaxURLBytes = 300
	// MaxPlatforms caps the strip's length. The strip is a footer band, not
	// a directory.
	MaxPlatforms = 12
	// MaxReviewCount caps a platform's published review count. Beyond this a
	// figure is a data-entry error, not a business fact.
	MaxReviewCount = 1_000_000
)

// Platform states. A platform is either publishing a captured rating or it
// is not; there is no partially-populated state, which is what stops a
// half-filled data file from presenting an invented number as a result.
const (
	// StatePublished means a rating and a review count were captured from
	// the platform and may be shown.
	StatePublished = "published"
	// StatePending means no rating has been captured yet. The platform is
	// listed — with its profile link when one exists — and says so.
	StatePending = "pending"
)

// Freshness is how a snapshot should be presented. The domain decides it;
// the serving layer maps it onto the envelope's status vocabulary.
type Freshness string

const (
	// FreshnessCurrent means at least one platform publishes a rating and
	// the newest capture is within the refresh window.
	FreshnessCurrent Freshness = "current"
	// FreshnessAged means ratings exist but the newest capture is older than
	// the refresh window the operator configured — readable, and honest
	// about not having been refreshed.
	FreshnessAged Freshness = "aged"
	// FreshnessNoRatings means no platform publishes a rating. The strip
	// still lists the platforms; it just has no numbers to report and must
	// not dress that up as a result.
	FreshnessNoRatings Freshness = "no-ratings"
)

// Validation errors. They are static and name the rule, never the offending
// bytes: a snapshot failure is read from a pod log, and echoing file
// content into logs is how private data escapes.
var (
	ErrNoPlatforms         = errors.New("ratings snapshot lists no platforms")
	ErrTooManyPlatforms    = errors.New("ratings snapshot lists more platforms than the strip admits")
	ErrDuplicatePlatform   = errors.New("ratings snapshot repeats a platform id")
	ErrUnknownPlatform     = errors.New("ratings snapshot names a platform with no registered hosts")
	ErrPlatformID          = errors.New("platform id must be lowercase letters, digits, and hyphens")
	ErrPlatformName        = errors.New("platform name is empty or exceeds the length cap")
	ErrPlatformState       = errors.New("platform state must be published or pending")
	ErrRatingOutOfRange    = errors.New("published rating must be between 1.0 and 5.0 in tenths")
	ErrReviewCountRange    = errors.New("published review count must be at least 1 and within the cap")
	ErrCaptureInstant      = errors.New("capture instant must be an RFC 3339 UTC timestamp")
	ErrPublishedNeedsURL   = errors.New("a published platform must carry its profile URL")
	ErrPendingHasRating    = errors.New("a pending platform must carry no rating, count, or capture instant")
	ErrURLScheme           = errors.New("outbound URLs must be absolute https URLs")
	ErrURLHost             = errors.New("outbound URL host is not on the platform's allowlist")
	ErrURLLength           = errors.New("outbound URL exceeds the length cap")
	ErrURLShape            = errors.New("outbound URL carries credentials, a fragment, or unprintable bytes")
	ErrPublishedAtInstant  = errors.New("snapshot publishedAt must be an RFC 3339 UTC timestamp")
	ErrSnapshotUnreadable  = errors.New("ratings snapshot is not valid JSON in the documented shape")
	ErrSnapshotUnknownKeys = errors.New("ratings snapshot carries fields the schema does not define")
)

// platformIDPattern is the identifier shape the strip's markup and the
// allowlist key agree on.
var platformIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// allowedHosts is the complete set of hosts this site will ever link a
// visitor to, or read a rating feed from, per platform.
//
// It lives in Go source ON PURPOSE, while the platform list, display names,
// and URLs live in the data file. The distinction is the point: adding a
// platform's PROFILE is a content edit the owner makes in
// platforms.json, but adding an outbound DESTINATION is a security
// decision that belongs in reviewed code. A data file can therefore never
// point a visitor — or a fetch — at a host nobody approved.
var allowedHosts = map[string][]string{
	"google":     {"www.google.com", "maps.google.com", "search.google.com", "g.page"},
	"yelp":       {"www.yelp.com", "m.yelp.com", "biz.yelp.com"},
	"facebook":   {"www.facebook.com", "web.facebook.com", "m.facebook.com"},
	"trustpilot": {"www.trustpilot.com"},
	"bbb":        {"www.bbb.org"},
}

// snapshotJSON is the owner-editable ratings snapshot, embedded so the
// binary stays one immutable artifact with no runtime file dependency. Its
// update procedure is documented in the file itself.
//
//go:embed platforms.json
var snapshotJSON []byte

// File is the on-disk shape of the snapshot: exactly what an owner edits.
// It is deliberately NOT the served shape — ratings are authored as integer
// tenths and served as a one-decimal number, so the file is exact and the
// response is readable.
type File struct {
	// PublishedAt is the RFC 3339 UTC instant this snapshot was last
	// edited or collected. It stamps the envelope, so responses stay
	// byte-stable and their digest ETags keep 304 revalidation working.
	PublishedAt string `json:"publishedAt"`
	// Platforms is the ordered strip, rendered left to right.
	Platforms []FilePlatform `json:"platforms"`
}

// FilePlatform is one platform as authored in the data file.
type FilePlatform struct {
	// ID keys the host allowlist and the strip's markup.
	ID string `json:"id"`
	// Name is the platform's display name.
	Name string `json:"name"`
	// State is StatePublished or StatePending.
	State string `json:"state"`
	// ProfileURL is the public profile a visitor is linked to. Required for
	// a published platform, optional for a pending one (a listed profile
	// with no rating yet is a legitimate, honest state).
	ProfileURL string `json:"profileUrl"`
	// FeedURL is the machine-readable endpoint the gated collector reads.
	// Empty in the shipped snapshot: no supported platform offers a
	// rating read without an account credential (see the PR that
	// introduced this file), so nothing is fetched today.
	FeedURL string `json:"feedUrl"`
	// RatingTenths is the captured rating in integer tenths, 10 to 50.
	// Zero on a pending platform.
	RatingTenths int `json:"ratingTenths"`
	// ReviewCount is the number of reviews behind the rating. Zero on a
	// pending platform.
	ReviewCount int `json:"reviewCount"`
	// CapturedAt is the RFC 3339 UTC instant the rating was read from the
	// platform. Empty on a pending platform.
	CapturedAt string `json:"capturedAt"`
}

// Data is the ratings/v1 payload: the platform strip plus a server-computed
// summary. Clients render the summary; they never derive it.
type Data struct {
	// PublishedAt is the snapshot's provenance instant, RFC 3339 UTC.
	PublishedAt string `json:"publishedAt"`
	// Summary aggregates the published platforms.
	Summary Summary `json:"summary"`
	// Platforms is the strip in render order.
	Platforms []Platform `json:"platforms"`
}

// Summary is the strip's server-computed aggregate.
type Summary struct {
	// Published counts platforms reporting a rating.
	Published int `json:"published"`
	// Pending counts platforms listed without one.
	Pending int `json:"pending"`
	// Reviews is the total review count across published platforms.
	Reviews int `json:"reviews"`
	// Average is the review-count-weighted mean across published
	// platforms, rounded half up to one decimal, on the site's star Scale.
	// It is omitted when nothing is published, because a zero there would
	// read as a rating of zero rather than as an absence.
	Average float64 `json:"average,omitempty"`
	// Scale is the star scale Average and every platform rating use.
	Scale int `json:"scale"`
}

// Platform is one entry in the strip, as served.
type Platform struct {
	// ID is the stable platform identifier.
	ID string `json:"id"`
	// Name is the platform's display name.
	Name string `json:"name"`
	// State is StatePublished or StatePending, so the UI renders an honest
	// entry without inferring it from a missing number.
	State string `json:"state"`
	// ProfileURL is the public profile to link to, when one exists.
	ProfileURL string `json:"profileUrl,omitempty"`
	// Rating is the captured rating rounded to one decimal on Scale.
	// Omitted on a pending platform.
	Rating float64 `json:"rating,omitempty"`
	// ReviewCount is the number of reviews behind Rating. Omitted on a
	// pending platform.
	ReviewCount int `json:"reviewCount,omitempty"`
	// CapturedAt is when Rating was read from the platform, RFC 3339 UTC.
	// Omitted on a pending platform.
	CapturedAt string `json:"capturedAt,omitempty"`
	// FeedURL is the machine-readable endpoint the gated collector reads.
	// It is deliberately NEVER serialised: it is operator configuration,
	// not something a visitor needs, and keeping it off the wire keeps the
	// public payload free of internal plumbing.
	FeedURL string `json:"-"`
}

// Store holds the snapshot the ratings surface serves. It exists because
// the gated collector may replace the snapshot while requests are in
// flight: readers take a pointer atomically and never lock, so a refresh
// costs a serving request nothing. With the collector off — the default —
// nothing ever writes to it.
type Store struct {
	current atomic.Pointer[Data]
}
