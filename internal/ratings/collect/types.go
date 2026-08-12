// types.go collects the package's type declarations and package-level
// const/var blocks so the collector's configuration, transport hardening,
// and refusal vocabulary can be surveyed in one place. Configuration
// parsing, fetching, and the refresh loop stay in collect.go.

package collect

import (
	"errors"
	"net/http"
	"time"
)

// Transport and response limits. They bound what one collection pass can
// cost the origin, because a rating feed is a few hundred bytes and
// anything larger is not a rating feed.
const (
	// MaxFeedBytes caps a feed response body. Reading one byte past it is a
	// refusal, not a truncation: a truncated JSON document would fail to
	// parse anyway, and refusing explicitly says why.
	MaxFeedBytes = 16 * 1024
	// maxIdleConns bounds the pooled connections one collector may hold.
	maxIdleConns = 4
	// dialTimeout bounds the TCP connect of a single feed request.
	dialTimeout = 5 * time.Second
	// tlsHandshakeTimeout bounds the TLS handshake of a single feed request.
	tlsHandshakeTimeout = 5 * time.Second
)

// Configuration bounds. A refresh window shorter than the floor would poll
// a third party rudely; one longer than the ceiling is not a refresh
// contract at all.
const (
	// MinInterval is the shortest refresh window the collector accepts.
	MinInterval = 15 * time.Minute
	// MaxInterval is the longest.
	MaxInterval = 7 * 24 * time.Hour
	// MinTimeout is the shortest per-request timeout the collector accepts.
	MinTimeout = time.Second
	// MaxTimeout is the longest.
	MaxTimeout = 30 * time.Second
)

// Environment variable names. All three move together: the collector is
// enabled only by the complete, valid set.
const (
	envEnabled  = "RATINGS_COLLECTOR_ENABLED"
	envInterval = "RATINGS_COLLECTOR_INTERVAL"
	envTimeout  = "RATINGS_COLLECTOR_TIMEOUT"
)

// Refusals. Every one of them is a per-platform outcome, never a fatal
// error: a collection pass that cannot read a platform keeps the value it
// already had, so a bad network day can never blank a published rating.
var (
	// ErrRedirectRefused reports a feed that tried to redirect. A redirect
	// is the standard way out of an allowlist, so the collector refuses to
	// follow one rather than re-validating a moving target.
	ErrRedirectRefused = errors.New("ratings feed attempted a redirect")
	// ErrHostNotAllowed reports a feed URL whose host is not on the
	// platform's allowlist. Snapshot validation already rejects one; this
	// is the same check at fetch time, because an allowlist worth having is
	// worth enforcing at the moment of the call.
	ErrHostNotAllowed = errors.New("ratings feed host is not on the platform's allowlist")
	// ErrSchemeNotAllowed reports a feed URL that is not https.
	ErrSchemeNotAllowed = errors.New("ratings feeds must be https")
	// ErrFeedStatus reports a non-200 response.
	ErrFeedStatus = errors.New("ratings feed did not answer 200")
	// ErrFeedContentType reports a response that is not JSON.
	ErrFeedContentType = errors.New("ratings feed did not answer application/json")
	// ErrFeedTooLarge reports a body over MaxFeedBytes.
	ErrFeedTooLarge = errors.New("ratings feed body exceeds the size cap")
	// ErrFeedUnreadable reports a body that is not one JSON reading in the
	// documented shape.
	ErrFeedUnreadable = errors.New("ratings feed is not a single JSON reading")
	// ErrRejectedSnapshot reports a collected snapshot that failed the same
	// validation the shipped data file passes. The pass is discarded whole.
	ErrRejectedSnapshot = errors.New("collected snapshot failed snapshot validation")
)

// Config is the collector's runtime configuration, parsed fail-closed by
// ConfigFromEnv. The zero value is the production default: disabled.
// Enabling it adds a read-only outbound capability and can never weaken a
// control — the host allowlist lives in the ratings package and no setting
// here, or anywhere, can widen it.
type Config struct {
	// Enabled reports whether any collection happens at all.
	Enabled bool
	// Interval is the refresh window between collection passes. It is also
	// the age past which a snapshot is reported as aged rather than
	// current, so a collector that stops succeeding says so.
	Interval time.Duration
	// Timeout bounds one feed request end to end.
	Timeout time.Duration
}

// Collector performs collection passes. It holds a hardened client whose
// redirect policy, timeouts, and connection pool are fixed at construction
// — none of them is reachable from configuration or from a data file.
type Collector struct {
	// client refuses redirects and bounds every phase of a request.
	client *http.Client
	// timeout bounds one feed request end to end, applied as a context
	// deadline so a cancelled shutdown wins immediately.
	timeout time.Duration
}

// Reading is the documented shape of a rating feed's response: the same
// integer-tenths discipline the snapshot file uses, so a feed can never
// introduce a value the authored format could not express.
type Reading struct {
	// RatingTenths is the platform's rating in integer tenths.
	RatingTenths int `json:"ratingTenths"`
	// ReviewCount is the number of reviews behind it.
	ReviewCount int `json:"reviewCount"`
	// CapturedAt is the RFC 3339 UTC instant the platform published it.
	CapturedAt string `json:"capturedAt"`
}
