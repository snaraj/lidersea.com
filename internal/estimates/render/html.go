// html.go renders the canonical estimate as a complete, semantic HTML
// document. It is deliberately unstyled and script-free: the site CSP
// (default-src 'self', no inline anything) must hold if this document is
// ever navigated to, and the UI's print stylesheet — the basis of the
// browser-native print-to-PDF path — owns presentation through the class
// hooks. Every text field passes through entity escaping; every figure is
// the computed estimate's verbatim cents.

package render

import (
	"html"
	"strconv"
	"strings"

	"github.com/snaraj/lidersea.com/internal/estimates"
)

// Format names the registry key.
func (htmlRenderer) Format() string { return FormatHTML }

// ContentType is the HTML media type.
func (htmlRenderer) ContentType() string { return "text/html; charset=utf-8" }

// Render produces the HTML document.
func (htmlRenderer) Render(estimate estimates.Estimate) ([]byte, error) {
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>Estimate</title>\n</head>\n<body>\n")
	b.WriteString("<main class=\"estimate\">\n<h1>Estimate</h1>\n")

	b.WriteString("<dl class=\"estimate-facts\">\n")
	b.WriteString("<dt>Status</dt><dd>" + esc(string(estimate.Status)) + "</dd>\n")
	b.WriteString("<dt>Currency</dt><dd>" + esc(estimate.Currency) + "</dd>\n")
	b.WriteString("<dt>Tax rate</dt><dd>" + percent(estimate.TaxRateBps) + "</dd>\n")
	b.WriteString("<dt>Valid until</dt><dd>" + esc(estimate.ValidUntil) + "</dd>\n")
	b.WriteString("</dl>\n")

	b.WriteString("<table class=\"estimate-lines\">\n<thead>\n")
	b.WriteString("<tr><th>#</th><th>Description</th><th>Qty</th><th>Unit</th><th>Amount</th><th>Taxable</th></tr>\n")
	b.WriteString("</thead>\n<tbody>\n")
	for i, line := range estimate.Items {
		taxable := "no"
		if line.Taxable {
			taxable = "yes"
		}
		b.WriteString("<tr><td>" + strconv.Itoa(i+1) +
			"</td><td>" + esc(line.Description) +
			"</td><td>" + strconv.FormatInt(line.Qty, 10) +
			"</td><td>" + esc(money(estimate.Currency, line.UnitCents)) +
			"</td><td>" + esc(money(estimate.Currency, line.AmountCents)) +
			"</td><td>" + taxable + "</td></tr>\n")
	}
	b.WriteString("</tbody>\n</table>\n")

	b.WriteString("<table class=\"estimate-totals\">\n<tbody>\n")
	b.WriteString("<tr><th>Subtotal</th><td>" + esc(money(estimate.Currency, estimate.SubtotalCents)) + "</td></tr>\n")
	b.WriteString("<tr><th>Tax (" + percent(estimate.TaxRateBps) + ")</th><td>" + esc(money(estimate.Currency, estimate.TaxCents)) + "</td></tr>\n")
	b.WriteString("<tr><th>Total</th><td>" + esc(money(estimate.Currency, estimate.TotalCents)) + "</td></tr>\n")
	b.WriteString("</tbody>\n</table>\n")

	if estimate.Notes != "" {
		b.WriteString("<p class=\"estimate-notes\">" + esc(estimate.Notes) + "</p>\n")
	}
	b.WriteString("</main>\n</body>\n</html>\n")
	return []byte(b.String()), nil
}
