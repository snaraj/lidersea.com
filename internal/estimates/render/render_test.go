// Package render tests pin the renderer registry and both documents against
// byte-exact goldens: the registry is closed and fail-closed, every rendered
// money figure is the canonical estimate's verbatim cents (proven by
// rendering a deliberately inconsistent estimate), and client text cannot
// break document structure in either format.
package render

import (
	"strings"
	"testing"

	"github.com/snaraj/lidersea.com/internal/estimates"
)

// goldenEstimate is a hand-built canonical estimate exercising both
// escaping paths: a pipe in a description (markdown table integrity) and
// HTML-special characters in the notes.
func goldenEstimate() estimates.Estimate {
	return estimates.Estimate{
		Currency: "USD",
		Items: []estimates.Line{
			{Description: "Hull compound and polish", Qty: 2, UnitCents: 25_000, Taxable: true, AmountCents: 50_000},
			{Description: "Dockage | pass-through", Qty: 1, UnitCents: 40_000, AmountCents: 40_000},
		},
		SubtotalCents: 90_000,
		TaxRateBps:    825,
		TaxCents:      4_125,
		TotalCents:    94_125,
		Notes:         "Includes <one> season & warranty",
		ValidUntil:    "2026-09-10T12:00:00Z",
		Status:        estimates.StatusDraft,
	}
}

const goldenMarkdown = `# Estimate

- Status: draft
- Currency: USD
- Tax rate: 8.25%
- Valid until: 2026-09-10T12:00:00Z

| # | Description | Qty | Unit | Amount | Taxable |
| ---: | --- | ---: | ---: | ---: | :---: |
| 1 | Hull compound and polish | 2 | USD 250.00 | USD 500.00 | yes |
| 2 | Dockage \| pass-through | 1 | USD 400.00 | USD 400.00 | no |

| | |
| --- | ---: |
| Subtotal | USD 900.00 |
| Tax (8.25%) | USD 41.25 |
| **Total** | **USD 941.25** |

Includes <one> season & warranty
`

const goldenHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Estimate</title>
</head>
<body>
<main class="estimate">
<h1>Estimate</h1>
<dl class="estimate-facts">
<dt>Status</dt><dd>draft</dd>
<dt>Currency</dt><dd>USD</dd>
<dt>Tax rate</dt><dd>8.25%</dd>
<dt>Valid until</dt><dd>2026-09-10T12:00:00Z</dd>
</dl>
<table class="estimate-lines">
<thead>
<tr><th>#</th><th>Description</th><th>Qty</th><th>Unit</th><th>Amount</th><th>Taxable</th></tr>
</thead>
<tbody>
<tr><td>1</td><td>Hull compound and polish</td><td>2</td><td>USD 250.00</td><td>USD 500.00</td><td>yes</td></tr>
<tr><td>2</td><td>Dockage | pass-through</td><td>1</td><td>USD 400.00</td><td>USD 400.00</td><td>no</td></tr>
</tbody>
</table>
<table class="estimate-totals">
<tbody>
<tr><th>Subtotal</th><td>USD 900.00</td></tr>
<tr><th>Tax (8.25%)</th><td>USD 41.25</td></tr>
<tr><th>Total</th><td>USD 941.25</td></tr>
</tbody>
</table>
<p class="estimate-notes">Includes &lt;one&gt; season &amp; warranty</p>
</main>
</body>
</html>
`

// TestRegistryIsClosedAndFailClosed pins the format catalog: exactly
// markdown and html render; json is the canonical value, not a renderer;
// unknown names return false so callers must fail, never fall back.
func TestRegistryIsClosedAndFailClosed(t *testing.T) {
	t.Parallel()
	if got := Formats(); len(got) != 2 || got[0] != "html" || got[1] != "markdown" {
		t.Errorf("Formats() = %v, want [html markdown]", got)
	}
	for _, format := range []string{FormatMarkdown, FormatHTML} {
		renderer, ok := For(format)
		if !ok {
			t.Fatalf("For(%q) missing", format)
		}
		if renderer.Format() != format || renderer.ContentType() == "" {
			t.Errorf("renderer %q self-reports %q with content type %q", format, renderer.Format(), renderer.ContentType())
		}
	}
	for _, unknown := range []string{FormatJSON, "pdf", "PDF", "Markdown", "md", "", "docx"} {
		if _, ok := For(unknown); ok {
			t.Errorf("For(%q) resolved; unknown and canonical formats must fail closed", unknown)
		}
	}
}

// TestMarkdownGolden locks the markdown document byte for byte, including
// the escaped pipe that keeps a hostile description inside its table cell.
func TestMarkdownGolden(t *testing.T) {
	t.Parallel()
	renderer, _ := For(FormatMarkdown)
	got, err := renderer.Render(goldenEstimate())
	if err != nil {
		t.Fatalf("Render error = %v", err)
	}
	if string(got) != goldenMarkdown {
		t.Errorf("markdown drifted from golden:\n--- got ---\n%s\n--- want ---\n%s", got, goldenMarkdown)
	}
	if renderer.ContentType() != "text/markdown; charset=utf-8" {
		t.Errorf("markdown content type = %q", renderer.ContentType())
	}
}

// TestHTMLGolden locks the HTML document byte for byte, including entity
// escaping and the absence of scripts and inline styles (the site CSP must
// hold if the document is ever navigated to).
func TestHTMLGolden(t *testing.T) {
	t.Parallel()
	renderer, _ := For(FormatHTML)
	got, err := renderer.Render(goldenEstimate())
	if err != nil {
		t.Fatalf("Render error = %v", err)
	}
	if string(got) != goldenHTML {
		t.Errorf("html drifted from golden:\n--- got ---\n%s\n--- want ---\n%s", got, goldenHTML)
	}
	if renderer.ContentType() != "text/html; charset=utf-8" {
		t.Errorf("html content type = %q", renderer.ContentType())
	}
	document := string(got)
	for _, banned := range []string{"<script", "style=", "<style", "javascript:"} {
		if strings.Contains(document, banned) {
			t.Errorf("html document contains %q; it must stay script- and inline-style-free", banned)
		}
	}
}

// TestRenderersNeverRecompute renders a deliberately inconsistent estimate —
// totals that do NOT equal the sum of its lines — and requires both
// renderers to emit the canonical figures verbatim. A renderer that
// recomputed anything would "fix" the numbers and betray the single-source
// contract.
func TestRenderersNeverRecompute(t *testing.T) {
	t.Parallel()
	inconsistent := estimates.Estimate{
		Currency:      "USD",
		Items:         []estimates.Line{{Description: "line", Qty: 3, UnitCents: 100, Taxable: true, AmountCents: 77}},
		SubtotalCents: 111,
		TaxRateBps:    825,
		TaxCents:      222,
		TotalCents:    555,
		ValidUntil:    "2026-09-10T12:00:00Z",
		Status:        estimates.StatusDraft,
	}
	for _, format := range Formats() {
		renderer, _ := For(format)
		document, err := renderer.Render(inconsistent)
		if err != nil {
			t.Fatalf("%s Render error = %v", format, err)
		}
		for _, verbatim := range []string{"USD 0.77", "USD 1.11", "USD 2.22", "USD 5.55"} {
			if !strings.Contains(string(document), verbatim) {
				t.Errorf("%s rendering lacks the canonical figure %q; renderers must never recompute", format, verbatim)
			}
		}
		if strings.Contains(string(document), "USD 3.00") {
			t.Errorf("%s rendering contains a recomputed qty×unit product", format)
		}
	}
}

// TestMoneyAndPercentFormatting pins the shared integer formatting at its
// edges: zero, sub-cent padding, and the caps' extremes.
func TestMoneyAndPercentFormatting(t *testing.T) {
	t.Parallel()
	for cents, want := range map[int64]string{
		0:                     "USD 0.00",
		5:                     "USD 0.05",
		10:                    "USD 0.10",
		99:                    "USD 0.99",
		100:                   "USD 1.00",
		4_125:                 "USD 41.25",
		2_000_000_000_000_000: "USD 20000000000000.00",
	} {
		if got := money("USD", cents); got != want {
			t.Errorf("money(%d) = %q, want %q", cents, got, want)
		}
	}
	for bps, want := range map[int64]string{
		0:      "0.00%",
		5:      "0.05%",
		825:    "8.25%",
		1_000:  "10.00%",
		10_000: "100.00%",
	} {
		if got := percent(bps); got != want {
			t.Errorf("percent(%d) = %q, want %q", bps, got, want)
		}
	}
}
