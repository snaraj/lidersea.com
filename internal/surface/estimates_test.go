// estimates_test exercises the estimates/v1 money math exhaustively: the
// documented single rounding mode at its boundaries, the input caps at their
// exact edges, the overflow-decomposed tax computation at the caps'
// extremes, and the derived fields (validity window, draft status). Every
// expected value is integer arithmetic written out by hand — no float
// appears anywhere in this file's money assertions.

package surface

import (
	"strings"
	"testing"
	"time"
)

// computeAt is the fixed instant every test computes at, so validUntil
// assertions are exact.
var computeAt = time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)

// item builds a taxable line.
func item(desc string, qty, unitCents int64) LineItem {
	return LineItem{Description: desc, Qty: qty, UnitCents: unitCents, Taxable: true}
}

// TestComputeEstimateMath drives the arithmetic table: subtotal accumulation,
// the taxable/non-taxable split, and the half-up rounding mode at exact
// boundaries in both directions.
func TestComputeEstimateMath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		items        []LineItem
		taxRateBps   int64
		wantSubtotal int64
		wantTax      int64
	}{
		{
			name:         "empty items compute to zero totals",
			items:        nil,
			taxRateBps:   825,
			wantSubtotal: 0,
			wantTax:      0,
		},
		{
			name:         "qty zero is a valid placeholder line",
			items:        []LineItem{item("hull wash", 0, 25_000)},
			taxRateBps:   825,
			wantSubtotal: 0,
			wantTax:      0,
		},
		{
			name:         "single taxable line, ordinary rate",
			items:        []LineItem{item("hull wash", 2, 25_000)},
			taxRateBps:   825, // 8.25% of $500.00 = $41.25 exactly
			wantSubtotal: 50_000,
			wantTax:      4_125,
		},
		{
			name: "non-taxable lines join the subtotal but not the base",
			items: []LineItem{
				item("detail", 1, 100_000),
				{Description: "dockage pass-through", Qty: 1, UnitCents: 40_000},
			},
			taxRateBps:   1_000, // 10% of $1000.00 only
			wantSubtotal: 140_000,
			wantTax:      10_000,
		},
		{
			name:         "exact half rounds up",
			items:        []LineItem{item("wax", 1, 50)}, // 50 × 100bps = 0.5 cents
			taxRateBps:   100,
			wantSubtotal: 50,
			wantTax:      1,
		},
		{
			name:         "just under half rounds down",
			items:        []LineItem{item("wax", 1, 49)}, // 0.49 cents
			taxRateBps:   100,
			wantSubtotal: 49,
			wantTax:      0,
		},
		{
			name:         "just over half rounds up",
			items:        []LineItem{item("wax", 1, 51)}, // 0.51 cents
			taxRateBps:   100,
			wantSubtotal: 51,
			wantTax:      1,
		},
		{
			name:         "rounding applies once on the summed base",
			items:        []LineItem{item("a", 1, 49), item("b", 1, 49)}, // base 98 → 0.98 → 1; per-line would be 0+0
			taxRateBps:   100,
			wantSubtotal: 98,
			wantTax:      1,
		},
		{
			name:         "zero rate",
			items:        []LineItem{item("detail", 3, 33_333)},
			taxRateBps:   0,
			wantSubtotal: 99_999,
			wantTax:      0,
		},
		{
			name:         "full 100% rate equals the taxable base",
			items:        []LineItem{item("detail", 1, 12_345)},
			taxRateBps:   10_000,
			wantSubtotal: 12_345,
			wantTax:      12_345,
		},
		{
			name:         "truncating fraction",
			items:        []LineItem{item("teak", 1, 333)}, // 333 × 825 = 274,725 → 27.4725 → 27
			taxRateBps:   825,
			wantSubtotal: 333,
			wantTax:      27,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data, err := ComputeEstimate(EstimateRequest{Currency: "USD", TaxRateBps: test.taxRateBps, Items: test.items}, computeAt)
			if err != nil {
				t.Fatalf("ComputeEstimate error = %v", err)
			}
			if data.SubtotalCents != test.wantSubtotal {
				t.Errorf("subtotal = %d, want %d", data.SubtotalCents, test.wantSubtotal)
			}
			if data.TaxCents != test.wantTax {
				t.Errorf("tax = %d, want %d", data.TaxCents, test.wantTax)
			}
			if want := test.wantSubtotal + test.wantTax; data.TotalCents != want {
				t.Errorf("total = %d, want %d", data.TotalCents, want)
			}
		})
	}
}

// TestComputeEstimateOverflowExtremes fills every cap simultaneously — one
// hundred maximal taxable lines at a 100% rate — and requires the exact
// analytic result, proving the decomposed tax math never overflows int64
// where a naive base×bps product would exceed 9.2×10^18.
func TestComputeEstimateOverflowExtremes(t *testing.T) {
	t.Parallel()
	items := make([]LineItem, maxEstimateItems)
	for i := range items {
		items[i] = item("maximal line", maxQty, maxUnitCents)
	}
	data, err := ComputeEstimate(EstimateRequest{Currency: "USD", TaxRateBps: maxTaxRateBps, Items: items}, computeAt)
	if err != nil {
		t.Fatalf("ComputeEstimate error = %v", err)
	}
	// 100 × 100000 × 100000000 = 10^15 cents; tax at 100% doubles it.
	const wantSubtotal = int64(1_000_000_000_000_000)
	if data.SubtotalCents != wantSubtotal || data.TaxCents != wantSubtotal || data.TotalCents != 2*wantSubtotal {
		t.Errorf("extremes = subtotal %d tax %d total %d, want %d %d %d",
			data.SubtotalCents, data.TaxCents, data.TotalCents, wantSubtotal, wantSubtotal, 2*wantSubtotal)
	}
}

// TestTaxHalfUpDecompositionMatchesDirectProduct cross-checks the
// decomposed formula against the naive (base×bps+5000)/10000 everywhere the
// naive form itself cannot overflow, including both sides of every rounding
// boundary near the decomposition's 10^4 seam.
func TestTaxHalfUpDecompositionMatchesDirectProduct(t *testing.T) {
	t.Parallel()
	bases := []int64{0, 1, 49, 50, 51, 9_999, 10_000, 10_001, 19_999, 333, 98, 123_456_789}
	rates := []int64{0, 1, 25, 100, 825, 5_000, 9_999, 10_000}
	for _, base := range bases {
		for _, rate := range rates {
			naive := (base*rate + 5_000) / 10_000
			if got := taxHalfUp(base, rate); got != naive {
				t.Errorf("taxHalfUp(%d, %d) = %d, want %d", base, rate, got, naive)
			}
		}
	}
}

// TestComputeEstimateValidation drives the request-validation table at each
// cap's exact boundary, and requires error text that never echoes input.
func TestComputeEstimateValidation(t *testing.T) {
	t.Parallel()
	valid := func() EstimateRequest {
		return EstimateRequest{Currency: "USD", TaxRateBps: 825, Items: []LineItem{item("detail", 1, 1_000)}}
	}
	tests := []struct {
		name    string
		mutate  func(*EstimateRequest)
		wantErr bool
	}{
		{name: "valid", mutate: func(r *EstimateRequest) {}},
		{name: "currency lowercase", mutate: func(r *EstimateRequest) { r.Currency = "usd" }, wantErr: true},
		{name: "currency short", mutate: func(r *EstimateRequest) { r.Currency = "US" }, wantErr: true},
		{name: "currency long", mutate: func(r *EstimateRequest) { r.Currency = "USDX" }, wantErr: true},
		{name: "currency empty", mutate: func(r *EstimateRequest) { r.Currency = "" }, wantErr: true},
		{name: "currency non-letter", mutate: func(r *EstimateRequest) { r.Currency = "U5D" }, wantErr: true},
		{name: "tax rate negative", mutate: func(r *EstimateRequest) { r.TaxRateBps = -1 }, wantErr: true},
		{name: "tax rate over cap", mutate: func(r *EstimateRequest) { r.TaxRateBps = 10_001 }, wantErr: true},
		{name: "notes at cap", mutate: func(r *EstimateRequest) { r.Notes = strings.Repeat("n", 2000) }},
		{name: "notes over cap", mutate: func(r *EstimateRequest) { r.Notes = strings.Repeat("n", 2001) }, wantErr: true},
		{name: "items at cap", mutate: func(r *EstimateRequest) {
			r.Items = make([]LineItem, 100)
			for i := range r.Items {
				r.Items[i] = item("line", 1, 1)
			}
		}},
		{name: "items over cap", mutate: func(r *EstimateRequest) {
			r.Items = make([]LineItem, 101)
			for i := range r.Items {
				r.Items[i] = item("line", 1, 1)
			}
		}, wantErr: true},
		{name: "description empty", mutate: func(r *EstimateRequest) { r.Items[0].Description = "" }, wantErr: true},
		{name: "description at cap", mutate: func(r *EstimateRequest) { r.Items[0].Description = strings.Repeat("d", 200) }},
		{name: "description over cap", mutate: func(r *EstimateRequest) { r.Items[0].Description = strings.Repeat("d", 201) }, wantErr: true},
		{name: "qty negative", mutate: func(r *EstimateRequest) { r.Items[0].Qty = -1 }, wantErr: true},
		{name: "qty at cap", mutate: func(r *EstimateRequest) { r.Items[0].Qty = 100_000 }},
		{name: "qty over cap", mutate: func(r *EstimateRequest) { r.Items[0].Qty = 100_001 }, wantErr: true},
		{name: "unitCents negative", mutate: func(r *EstimateRequest) { r.Items[0].UnitCents = -1 }, wantErr: true},
		{name: "unitCents at cap", mutate: func(r *EstimateRequest) { r.Items[0].UnitCents = 100_000_000 }},
		{name: "unitCents over cap", mutate: func(r *EstimateRequest) { r.Items[0].UnitCents = 100_000_001 }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			req := valid()
			test.mutate(&req)
			_, err := ComputeEstimate(req, computeAt)
			if (err != nil) != test.wantErr {
				t.Errorf("ComputeEstimate error = %v, wantErr %v", err, test.wantErr)
			}
			if err != nil && req.Notes != "" && strings.Contains(err.Error(), req.Notes) {
				t.Errorf("validation error %q echoes client input", err)
			}
		})
	}
}

// TestComputeEstimateDerivedFields pins the non-money outputs: the echoed
// line amounts, the 30-day UTC validity window, the draft status, and the
// carried notes and currency.
func TestComputeEstimateDerivedFields(t *testing.T) {
	t.Parallel()
	req := EstimateRequest{
		Currency:   "EUR",
		TaxRateBps: 2_000,
		Notes:      "haul-out included",
		Items: []LineItem{
			item("bottom paint", 2, 60_000),
			{Description: "zincs", Qty: 4, UnitCents: 2_500},
		},
	}
	data, err := ComputeEstimate(req, computeAt)
	if err != nil {
		t.Fatalf("ComputeEstimate error = %v", err)
	}
	if data.Currency != "EUR" || data.Notes != "haul-out included" || data.Status != EstimateDraft {
		t.Errorf("carried fields = %q %q %q", data.Currency, data.Notes, data.Status)
	}
	if data.TaxRateBps != 2_000 {
		t.Errorf("taxRateBps = %d, want 2000", data.TaxRateBps)
	}
	if data.ValidUntil != "2026-09-10T12:00:00Z" {
		t.Errorf("validUntil = %q, want computeAt + 30 days in UTC", data.ValidUntil)
	}
	if len(data.Items) != 2 {
		t.Fatalf("echoed %d lines, want 2", len(data.Items))
	}
	if data.Items[0].AmountCents != 120_000 || !data.Items[0].Taxable {
		t.Errorf("line 0 = %+v, want amount 120000 taxable", data.Items[0])
	}
	if data.Items[1].AmountCents != 10_000 || data.Items[1].Taxable {
		t.Errorf("line 1 = %+v, want amount 10000 non-taxable", data.Items[1])
	}
	if data.SubtotalCents != 130_000 || data.TaxCents != 24_000 || data.TotalCents != 154_000 {
		t.Errorf("totals = %d %d %d, want 130000 24000 154000",
			data.SubtotalCents, data.TaxCents, data.TotalCents)
	}
}

// TestEstimateStatusEnumIsPinned locks the lifecycle vocabulary as
// independent literals.
func TestEstimateStatusEnumIsPinned(t *testing.T) {
	t.Parallel()
	for want, got := range map[string]EstimateStatus{
		"draft":    EstimateDraft,
		"sent":     EstimateSent,
		"accepted": EstimateAccepted,
	} {
		if string(got) != want {
			t.Errorf("estimate status = %q, want %q", got, want)
		}
	}
}
