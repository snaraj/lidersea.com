// markdown.go renders the canonical estimate as a markdown document: a
// heading, the estimate facts, a line-item table, and the totals — every
// figure taken verbatim from the computed estimate.

package render

import (
	"strconv"
	"strings"

	"github.com/snaraj/lidersea.com/internal/estimates"
)

func (markdownRenderer) Format() string { return FormatMarkdown }

func (markdownRenderer) ContentType() string { return "text/markdown; charset=utf-8" }

func (markdownRenderer) Render(estimate estimates.Estimate) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Estimate\n\n")
	b.WriteString("- Status: " + string(estimate.Status) + "\n")
	b.WriteString("- Currency: " + mdEscape(estimate.Currency) + "\n")
	b.WriteString("- Tax rate: " + percent(estimate.TaxRateBps) + "\n")
	b.WriteString("- Valid until: " + estimate.ValidUntil + "\n\n")

	b.WriteString("| # | Description | Qty | Unit | Amount | Taxable |\n")
	b.WriteString("| ---: | --- | ---: | ---: | ---: | :---: |\n")
	for i, line := range estimate.Items {
		taxable := "no"
		if line.Taxable {
			taxable = "yes"
		}
		b.WriteString("| " + strconv.Itoa(i+1) +
			" | " + mdEscape(line.Description) +
			" | " + strconv.FormatInt(line.Qty, 10) +
			" | " + money(estimate.Currency, line.UnitCents) +
			" | " + money(estimate.Currency, line.AmountCents) +
			" | " + taxable + " |\n")
	}

	b.WriteString("\n| | |\n| --- | ---: |\n")
	b.WriteString("| Subtotal | " + money(estimate.Currency, estimate.SubtotalCents) + " |\n")
	b.WriteString("| Tax (" + percent(estimate.TaxRateBps) + ") | " + money(estimate.Currency, estimate.TaxCents) + " |\n")
	b.WriteString("| **Total** | **" + money(estimate.Currency, estimate.TotalCents) + "** |\n")

	if estimate.Notes != "" {
		b.WriteString("\n" + mdEscape(estimate.Notes) + "\n")
	}
	return []byte(b.String()), nil
}

// mdEscape keeps client text from breaking document structure: pipes would
// splice table cells and newlines would splice rows, so both are neutralized.
// Markdown is not an execution context — structural integrity is the whole
// concern here; the HTML renderer is where entity escaping matters.
func mdEscape(text string) string {
	text = strings.ReplaceAll(text, "|", `\|`)
	text = strings.ReplaceAll(text, "\r", "")
	return strings.ReplaceAll(text, "\n", " ")
}
