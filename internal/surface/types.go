// types.go collects the package's type declarations and package-level
// const/var blocks so the envelope contract and the surface catalog can be
// surveyed in one place. Envelope construction stays in surface.go.

package surface

// Schema is the envelope version every surface response declares. It is this
// site's own vocabulary — lidersea.com talks about "surfaces" — and versions
// the envelope shape itself, while each surface's payload shape is versioned
// separately by its Kind (media-mosaic/v1, reviews/v1, estimates/v1).
const Schema = "surface/v1"

// Status is the envelope-level truthfulness signal: it reports whether Data
// is current, aged, or honestly absent, so the UI never has to guess from a
// missing field.
type Status string

const (
	// StatusOK means Data is present and current.
	StatusOK Status = "ok"
	// StatusStale means Data is served from an aged snapshot; the surface is
	// readable but its source has not refreshed it.
	StatusStale Status = "stale"
	// StatusUnavailable means the surface cannot produce Data right now and
	// says so instead of fabricating an empty success.
	StatusUnavailable Status = "unavailable"
)

// Envelope is the one JSON shape every surface response uses, so the UI can
// route, title, and freshness-check any surface without knowing its payload.
type Envelope struct {
	// Schema is always the Schema constant.
	Schema string `json:"schema"`
	// ID names the surface instance (for example "board").
	ID string `json:"id"`
	// Kind names the payload contract inside Data (for example
	// "media-mosaic/v1").
	Kind string `json:"kind"`
	// Title is the human heading the UI may show for the surface.
	Title string `json:"title"`
	// GeneratedAt is the RFC 3339 UTC instant Data was produced. Embedded
	// sample data carries its domain's fixed publication instant so
	// responses stay byte-stable and their digest ETags keep 304
	// revalidation working.
	GeneratedAt string `json:"generatedAt"`
	// Status reports Data's truthfulness per the Status constants.
	Status Status `json:"status"`
	// Data is the Kind-specific payload, produced by the surface's domain
	// package (internal/board, internal/reviews, internal/estimates).
	Data any `json:"data"`
}

// Descriptor registers one surface: its identity, payload contract, human
// title, and the explicit route that serves it. Routes are wired explicitly
// by the server — never pattern-derived — so an unknown /api/ path can only
// ever be an opaque 404.
type Descriptor struct {
	// ID is the stable surface identifier used in envelopes and cursors.
	ID string
	// Kind is the payload contract version served inside the envelope.
	Kind string
	// Title is the human heading carried in the envelope.
	Title string
	// Route is the exact request path that serves this surface.
	Route string
}

var (
	// Board is the mosaic media board surface (issue #19); its domain lives
	// in internal/board.
	Board = Descriptor{
		ID:    "board",
		Kind:  "media-mosaic/v1",
		Title: "Portfolio board",
		Route: "/api/board",
	}
	// Reviews is the client reviews surface (issue #20); its domain lives in
	// internal/reviews.
	Reviews = Descriptor{
		ID:    "reviews",
		Kind:  "reviews/v1",
		Title: "Client reviews",
		Route: "/api/reviews",
	}
	// Ratings is the third-party ratings strip served at the foot of the
	// site; its domain lives in internal/ratings, with the optional gated
	// producer in internal/ratings/collect.
	Ratings = Descriptor{
		ID:    "ratings",
		Kind:  "ratings/v1",
		Title: "Ratings across platforms",
		Route: "/api/ratings",
	}
	// Estimates is the estimate preview surface (issue #21); its domain
	// lives in internal/estimates (with rendering and delivery contracts in
	// its subpackages). The route is compute-only (POST) and ships gated off
	// by default.
	Estimates = Descriptor{
		ID:    "estimates",
		Kind:  "estimates/v1",
		Title: "Estimate preview",
		Route: "/api/estimates/preview",
	}
)

// Registry is the ordered catalog of every surface this site defines. The
// server wires exactly these routes; tests pin the catalog's internal
// consistency so a new surface is a conscious registration, never drift.
var Registry = []Descriptor{Board, Reviews, Ratings, Estimates}
