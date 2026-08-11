// Package estimates is the estimates/v1 domain: a pure computation module
// turning line items into a canonical integer-cent estimate. It is pure —
// no HTTP, no I/O, no rendering — so the math is server-authoritative
// (client arithmetic is never trusted) and float-free: every money value is
// an int64 cent amount and the tax rate is integer basis points, so results
// are exact and identical on every platform. Presentation lives in the
// sibling render package; delivery in the delivery package.
//
// ROUNDING MODE (the single documented mode): tax is computed once on the
// summed taxable base, rounded half up to the nearest cent —
// tax = round_half_up(taxableBase × rateBps / 10000). Rounding once at the
// total, rather than per line, keeps the estimate equal to any system that
// recomputes it from the same base; half up is the conventional commercial
// direction. No other rounding occurs anywhere: line amounts are exact
// integer products.
//
// Persistence, numbering, and sending are future stages on the platform
// storage layer; Compute computes and returns, nothing more.
package estimates

import (
	"errors"
	"time"
)

// Validation errors: static, client-safe strings (never echoes of input),
// each naming the first violated rule.
var (
	errCurrencyInvalid = errors.New("currency must be a three-letter uppercase code")
	errTaxRateInvalid  = errors.New("taxRateBps must be an integer between 0 and 10000")
	errNotesTooLong    = errors.New("notes exceed the length cap")
	errTooManyItems    = errors.New("too many line items")
	errItemDescription = errors.New("every line item needs a description within the length cap")
	errItemQty         = errors.New("line item qty must be an integer between 0 and 100000")
	errItemUnitCents   = errors.New("line item unitCents must be an integer between 0 and 100000000")
)

// Compute validates a request and computes the canonical estimate at the
// given instant. The input caps double as the overflow proof for the int64
// math: one line amount is at most maxQty × maxUnitCents = 10^13 cents, the
// subtotal at most maxItems × 10^13 = 10^15, and the tax decomposition below
// never multiplies more than 10^11 × 10^4 — all far inside int64's 9.2×10^18
// range.
func Compute(req Request, now time.Time) (Estimate, error) {
	if !validCurrency(req.Currency) {
		return Estimate{}, errCurrencyInvalid
	}
	if req.TaxRateBps < 0 || req.TaxRateBps > maxTaxRateBps {
		return Estimate{}, errTaxRateInvalid
	}
	if len(req.Notes) > maxNotesBytes {
		return Estimate{}, errNotesTooLong
	}
	if len(req.Items) > maxItems {
		return Estimate{}, errTooManyItems
	}

	estimate := Estimate{
		Currency:   req.Currency,
		Items:      make([]Line, 0, len(req.Items)),
		TaxRateBps: req.TaxRateBps,
		Notes:      req.Notes,
		ValidUntil: now.UTC().AddDate(0, 0, validityDays).Format(time.RFC3339),
		Status:     StatusDraft,
	}

	var taxableBase int64
	for _, item := range req.Items {
		if item.Description == "" || len(item.Description) > maxDescriptionBytes {
			return Estimate{}, errItemDescription
		}
		if item.Qty < 0 || item.Qty > maxQty {
			return Estimate{}, errItemQty
		}
		if item.UnitCents < 0 || item.UnitCents > maxUnitCents {
			return Estimate{}, errItemUnitCents
		}
		amount := item.Qty * item.UnitCents
		estimate.Items = append(estimate.Items, Line{
			Description: item.Description,
			Qty:         item.Qty,
			UnitCents:   item.UnitCents,
			Taxable:     item.Taxable,
			AmountCents: amount,
		})
		estimate.SubtotalCents += amount
		if item.Taxable {
			taxableBase += amount
		}
	}

	estimate.TaxCents = taxHalfUp(taxableBase, req.TaxRateBps)
	estimate.TotalCents = estimate.SubtotalCents + estimate.TaxCents
	return estimate, nil
}

// taxHalfUp computes round_half_up(base × bps / 10000) without ever forming
// base × bps directly: the product is decomposed as
// (base/10000)×bps + ((base%10000)×bps + 5000)/10000, which is algebraically
// identical (the first term divides exactly) and keeps every intermediate
// below 10^15 even at the caps' extremes.
func taxHalfUp(base, bps int64) int64 {
	return (base/10_000)*bps + ((base%10_000)*bps+5_000)/10_000
}

// validCurrency accepts exactly three uppercase ASCII letters — the ISO 4217
// alphabetic shape — without maintaining a currency table the business does
// not need yet.
func validCurrency(code string) bool {
	if len(code) != 3 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < 'A' || code[i] > 'Z' {
			return false
		}
	}
	return true
}
