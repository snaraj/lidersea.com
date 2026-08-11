// types.go collects the package's type declarations and package-level
// const/var blocks so the whole surface data model can be surveyed in one
// place. Envelope construction stays in surface.go; each surface's logic
// stays in its own file (board.go, reviews.go, estimates.go).

package surface

import "time"

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
	// sample data carries a fixed publication instant so responses stay
	// byte-stable and their digest ETags keep 304 revalidation working.
	GeneratedAt string `json:"generatedAt"`
	// Status reports Data's truthfulness per the Status constants.
	Status Status `json:"status"`
	// Data is the Kind-specific payload.
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
	// Board is the mosaic media board surface (issue #19).
	Board = Descriptor{
		ID:    "board",
		Kind:  "media-mosaic/v1",
		Title: "Portfolio board",
		Route: "/api/board",
	}
	// Reviews is the client reviews surface (issue #20).
	Reviews = Descriptor{
		ID:    "reviews",
		Kind:  "reviews/v1",
		Title: "Client reviews",
		Route: "/api/reviews",
	}
	// Estimates is the estimate preview surface (issue #21). Its route is
	// compute-only (POST) and ships gated off by default.
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
var Registry = []Descriptor{Board, Reviews, Estimates}

// samplePublishedAt is the fixed publication instant of every embedded
// sample payload. A fixed instant — rather than time.Now — keeps sample
// responses byte-identical across requests, replicas, and restarts, which
// keeps their digest ETags stable and 304 revalidation honest. Live data,
// when the platform storage layer lands, will carry its real generation
// time instead.
var samplePublishedAt = time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC)

// Block kinds for the media-mosaic/v1 payload.
const (
	// BlockKindImage is a photo block backed by the media pipeline.
	BlockKindImage = "image"
	// BlockKindVideo is a video block backed by the media pipeline.
	BlockKindVideo = "video"
	// BlockKindText is a text-only block with no media entry.
	BlockKindText = "text"
)

// boardPageSize is the fixed number of blocks per board page. The cursor is
// the only pagination input by design: no client-supplied page size means no
// resource-amplification knob on a read endpoint.
const boardPageSize = 6

// BoardData is the media-mosaic/v1 payload: one page of blocks plus the
// cursor that continues the walk.
type BoardData struct {
	// Blocks is this page of the board, newest first.
	Blocks []Block `json:"blocks"`
	// NextCursor continues pagination when more blocks remain; it is omitted
	// on the final page.
	NextCursor string `json:"nextCursor,omitempty"`
}

// Block is one mosaic tile: an image, a video, or a text card.
type Block struct {
	// ID is the stable block identifier; it doubles as the pagination cursor.
	ID string `json:"id"`
	// Kind is one of the BlockKind constants.
	Kind string `json:"kind"`
	// Media is present on image and video blocks.
	Media *Media `json:"media,omitempty"`
	// Text is present on text blocks and may caption media blocks.
	Text *Text `json:"text,omitempty"`
	// Tags label the block for future filtering; always present, may be empty.
	Tags []string `json:"tags"`
	// CreatedAt is the block's RFC 3339 UTC creation instant.
	CreatedAt string `json:"createdAt"`
	// Span hints how many mosaic lanes the block may occupy; 0 means 1.
	Span int `json:"span,omitempty"`
}

// Media describes one media asset with everything the UI needs to reserve
// space BEFORE bytes arrive: width, height, and a CSS-ready aspect ratio make
// zero layout shift a property of the data, not a rendering heuristic.
type Media struct {
	// Src is the full-quality asset URL in the digest-immutable class.
	Src string `json:"src"`
	// Poster is the still shown before a video plays; empty for images.
	Poster string `json:"poster,omitempty"`
	// Width and Height are the intrinsic pixel dimensions of Src.
	Width  int `json:"width"`
	Height int `json:"height"`
	// Aspect is "width/height" exactly as CSS aspect-ratio accepts it.
	Aspect string `json:"aspect"`
	// Alt is the accessibility description; required on every media entry.
	Alt string `json:"alt"`
	// Variants are pre-declared responsive renditions (srcset as data), so
	// the client never negotiates or probes for sizes.
	Variants []Variant `json:"variants"`
}

// Variant is one pre-declared rendition of a media asset.
type Variant struct {
	// Src is the rendition's URL in the digest-immutable class.
	Src string `json:"src"`
	// Width is the rendition's pixel width (the srcset "w" value).
	Width int `json:"width"`
	// Type is the rendition's MIME type.
	Type string `json:"type,omitempty"`
}

// Text is the written content of a block.
type Text struct {
	// Title is an optional heading.
	Title string `json:"title,omitempty"`
	// Body is the block's text.
	Body string `json:"body"`
}

// Review submission bounds, enforced by ValidateReviewSubmission and pinned
// by tests. Byte lengths, not runes: they are transport caps, not typography.
const (
	// maxReviewAuthorBytes caps the submitted author name.
	maxReviewAuthorBytes = 120
	// maxReviewTextBytes caps the submitted review text.
	maxReviewTextBytes = 2000
	// minRating and maxRating bound the 1-5 star scale.
	minRating = 1
	maxRating = 5
)

// ReviewSourceFirstParty labels reviews submitted directly to this site.
// External platform sources are a documented future design, not wired here.
const ReviewSourceFirstParty = "first-party"

// ReviewsData is the reviews/v1 payload: the server-computed aggregate plus
// the review list. The aggregate is always computed here — clients render it,
// they never derive it.
type ReviewsData struct {
	Aggregate Aggregate `json:"aggregate"`
	Reviews   []Review  `json:"reviews"`
}

// Aggregate summarizes the review set.
type Aggregate struct {
	// Count is the number of reviews.
	Count int `json:"count"`
	// Average is the mean rating rounded half up to one decimal. It is
	// derived from integer tenths so the value is deterministic; it is not a
	// money path.
	Average float64 `json:"average"`
	// Histogram counts reviews per rating: index i holds the count of
	// (i+1)-star reviews.
	Histogram [5]int `json:"histogram"`
}

// Review is one published review.
type Review struct {
	ID     string `json:"id"`
	Author string `json:"author"`
	// Rating is an integer 1-5.
	Rating int    `json:"rating"`
	Text   string `json:"text"`
	// Source is ReviewSourceFirstParty for direct submissions.
	Source    string `json:"source"`
	CreatedAt string `json:"createdAt"`
}

// ReviewSubmission is the POST /api/reviews request body. The contract ships
// now; persistence arrives with the platform storage layer, so a valid
// submission currently receives an honest "unavailable" envelope.
type ReviewSubmission struct {
	Author string `json:"author"`
	Rating int    `json:"rating"`
	Text   string `json:"text"`
}

// Estimate bounds, enforced by ComputeEstimate and pinned by tests. The caps
// also make the integer money math provably overflow-free: see the bound
// analysis in estimates.go.
const (
	// maxEstimateItems caps line items per estimate.
	maxEstimateItems = 100
	// maxDescriptionBytes caps one line item's description.
	maxDescriptionBytes = 200
	// maxNotesBytes caps the free-form notes field.
	maxNotesBytes = 2000
	// maxQty caps one line's quantity.
	maxQty = 100_000
	// maxUnitCents caps one line's unit price at one million dollars.
	maxUnitCents = 100_000_000
	// maxTaxRateBps caps the tax rate at 100% expressed in basis points.
	maxTaxRateBps = 10_000
	// estimateValidityDays is how long a computed estimate remains valid.
	estimateValidityDays = 30
)

// EstimateStatus is the estimate lifecycle enum. Preview always produces
// EstimateDraft; the later states arrive with persistence.
type EstimateStatus string

const (
	EstimateDraft    EstimateStatus = "draft"
	EstimateSent     EstimateStatus = "sent"
	EstimateAccepted EstimateStatus = "accepted"
)

// EstimateRequest is the POST /api/estimates/preview request body. All money
// arrives as integer cents and the tax rate as integer basis points: no float
// ever enters a money path, and the server's math is authoritative.
type EstimateRequest struct {
	// Currency is the ISO 4217 alphabetic code, three uppercase ASCII letters.
	Currency string `json:"currency"`
	// TaxRateBps is the tax rate in basis points (825 = 8.25%).
	TaxRateBps int64 `json:"taxRateBps"`
	// Notes is optional free text carried onto the estimate.
	Notes string `json:"notes,omitempty"`
	// Items are the line items; an empty estimate computes to zero totals.
	Items []LineItem `json:"items"`
}

// LineItem is one requested estimate line.
type LineItem struct {
	// Description names the work; required, at most maxDescriptionBytes.
	Description string `json:"description"`
	// Qty is the quantity, 0 through maxQty. Zero is a valid placeholder line.
	Qty int64 `json:"qty"`
	// UnitCents is the integer-cent unit price, 0 through maxUnitCents.
	UnitCents int64 `json:"unitCents"`
	// Taxable marks the line as subject to tax; omitted means non-taxable,
	// so taxation is always an explicit client statement.
	Taxable bool `json:"taxable,omitempty"`
}

// EstimateData is the estimates/v1 payload: the server-computed estimate.
type EstimateData struct {
	Currency string `json:"currency"`
	// Items echo the request lines with each line's computed amount, so the
	// UI renders server math instead of multiplying anything itself.
	Items []EstimateLine `json:"items"`
	// SubtotalCents is the sum of every line amount.
	SubtotalCents int64 `json:"subtotalCents"`
	// TaxRateBps echoes the applied rate.
	TaxRateBps int64 `json:"taxRateBps"`
	// TaxCents is the tax on the taxable base per the documented rounding.
	TaxCents int64 `json:"taxCents"`
	// TotalCents is SubtotalCents + TaxCents.
	TotalCents int64 `json:"totalCents"`
	// Notes echoes the request notes.
	Notes string `json:"notes,omitempty"`
	// ValidUntil is the RFC 3339 UTC instant the estimate expires.
	ValidUntil string `json:"validUntil"`
	// Status is always EstimateDraft for previews.
	Status EstimateStatus `json:"status"`
}

// EstimateLine is one computed estimate line.
type EstimateLine struct {
	Description string `json:"description"`
	Qty         int64  `json:"qty"`
	UnitCents   int64  `json:"unitCents"`
	Taxable     bool   `json:"taxable"`
	// AmountCents is Qty × UnitCents, computed server-side.
	AmountCents int64 `json:"amountCents"`
}
