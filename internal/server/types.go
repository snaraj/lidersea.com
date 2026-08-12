// types.go collects the package's type declarations and package-level
// const/var blocks so the data model can be surveyed in one place. The
// construction, routing, and serving logic stays in server.go; surface API
// serving stays in surfaces.go; configuration parsing stays in config.go.

package server

import (
	"io/fs"

	"github.com/snaraj/lidersea.com/internal/media"
	"github.com/snaraj/lidersea.com/internal/theme"
)

// Request body caps for the gated write routes, far below the transport's
// tolerance: a review is a paragraph and an estimate is at most one hundred
// short lines, so anything larger is not a client.
const (
	// maxReviewRequestBytes bounds a POST /api/reviews body.
	maxReviewRequestBytes = 16 * 1024
	// maxEstimateRequestBytes bounds a POST /api/estimates/preview body.
	maxEstimateRequestBytes = 32 * 1024
)

// reviewStorageUnavailableReason is the honest answer of the review write
// path until the platform storage layer exists: the contract is live, the
// persistence is not, and the response says so instead of pretending to
// accept the submission.
const reviewStorageUnavailableReason = "review storage is not configured; submissions are not persisted yet"

// The edge's scheme declaration and the two exact tokens the origin acts on.
// This is the origin's only use of forwarded metadata, and it is fail-closed
// by exact matching: the TLS-terminating edge sends lowercase tokens, so a
// case variant, an unknown proto, or an absent header (cluster probes,
// port-forward validation, local dev) is not our edge speaking and serves
// normally — no redirect issued, no HSTS promise minted.
const (
	// forwardedProtoHeader names the edge's declaration of the scheme the
	// visitor used on the public leg. The origin reads it for exactly one
	// decision — the scheme policy in securityHeaders and
	// redirectForwardedHTTP — and must never trust it for anything else:
	// on any connection that did not cross the edge these are
	// client-controlled bytes.
	forwardedProtoHeader = "X-Forwarded-Proto"
	// forwardedProtoHTTP is the only declaration answered with the
	// permanent redirect to TLS.
	forwardedProtoHTTP = "http"
	// forwardedProtoHTTPS is the only declaration that earns the HSTS
	// policy: no spoofed or malformed value can mint a transport promise
	// for a leg the edge never declared secure.
	forwardedProtoHTTPS = "https"
)

// Config selects which optional capabilities the handler serves. The zero
// value is the production default and the strictest state: every gate off,
// media disabled, the origin purely read-only. Each field only ever ADDS a
// narrowly-scoped capability — no setting here (or anywhere) can weaken the
// security-header policy, the CSP, or the read-only contract of any other
// route, and malformed configuration fails startup in ConfigFromEnv rather
// than defaulting anything on.
type Config struct {
	// Media configures the digest-immutable media pipeline (read-only GETs).
	Media media.Config
	// ReviewsWriteEnabled admits POST on exactly /api/reviews
	// (REVIEWS_WRITE_ENABLED). Default off.
	ReviewsWriteEnabled bool
	// EstimatesEnabled registers the POST-only /api/estimates/preview
	// compute route (ESTIMATES_ENABLED). Default off: the route is an opaque
	// 404, indistinguishable from any unknown /api/ path.
	EstimatesEnabled bool
}

// handler serves the immutable frontend files after New has validated the
// bundle's entrypoint. It remains private so callers cannot bypass the mux's
// health endpoints or the securityHeaders wrapper.
type handler struct {
	// assets is the read-only, build-generated frontend filesystem.
	assets fs.FS
	// shells holds one precomputed document per catalog theme, each already
	// carrying its data-theme attribute. The entrypoint is read and stamped
	// during construction so a broken image fails before the process becomes
	// ready rather than on the first visitor request, and so serving a themed
	// document is a map lookup rather than request-path work.
	shells map[theme.Theme][]byte
}

// apiHandler serves the surface catalog under /api/: the registry's explicit
// routes and nothing else. It is private for the same reason handler is —
// every response must pass through the securityHeaders wrapper.
type apiHandler struct {
	// cfg carries the write-path gates; the zero value serves reads only.
	cfg Config
}

// reviewWriteUnavailable is the data payload of the honest 503 the review
// write path returns while no persistence exists.
type reviewWriteUnavailable struct {
	// Reason is reviewStorageUnavailableReason.
	Reason string `json:"reason"`
}
