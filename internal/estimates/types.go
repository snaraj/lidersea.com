// types.go collects the package's type declarations and package-level
// const/var blocks so the estimates/v1 data model can be surveyed in one
// place — deliberately the single home of the estimate's fields, so when the
// owner's real-world estimate examples arrive, evolving the model is one
// contained diff here. Validation and the money math stay in estimates.go.

package estimates

// Input caps, enforced by Compute and pinned by tests. The caps also make
// the integer money math provably overflow-free: see the bound analysis in
// estimates.go.
const (
	// maxItems caps line items per estimate.
	maxItems = 100
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
	// validityDays is how long a computed estimate remains valid.
	validityDays = 30
)

// Status is the estimate lifecycle enum. Preview always produces
// StatusDraft; the later states arrive with persistence.
type Status string

const (
	StatusDraft    Status = "draft"
	StatusSent     Status = "sent"
	StatusAccepted Status = "accepted"
)

// Request is an estimate computation request. All money arrives as integer
// cents and the tax rate as integer basis points: no float ever enters a
// money path, and the server's math is authoritative.
type Request struct {
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

// Estimate is the canonical computed estimate — format-neutral JSON. Every
// presentation (markdown, HTML, the future PDF) renders from this one
// shape, and renderers never recompute what it already carries.
type Estimate struct {
	Currency string `json:"currency"`
	// Items echo the request lines with each line's computed amount, so
	// consumers render server math instead of multiplying anything.
	Items []Line `json:"items"`
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
	// Status is always StatusDraft for previews.
	Status Status `json:"status"`
}

// Line is one computed estimate line.
type Line struct {
	Description string `json:"description"`
	Qty         int64  `json:"qty"`
	UnitCents   int64  `json:"unitCents"`
	Taxable     bool   `json:"taxable"`
	// AmountCents is Qty × UnitCents, computed server-side.
	AmountCents int64 `json:"amountCents"`
}
