// Package render maps the canonical computed estimate to presentation
// formats through a closed registry: markdown and HTML today, both pure Go,
// both rendering the domain package's already-computed integer cents without
// ever recomputing money. The registry is how "convert between formats"
// stays free forever: every format renders from the same canonical value.
package render

import (
	"slices"
	"strconv"
)

// For returns the registered renderer for a format name. Unknown formats
// return false — callers fail closed instead of falling back to a guess.
func For(format string) (Renderer, bool) {
	renderer, ok := registry[format]
	return renderer, ok
}

// Formats lists the registered render formats, sorted, for diagnostics and
// tests. FormatJSON is not listed: it is the canonical value, not a
// rendering.
func Formats() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// money renders integer cents as "<CUR> <units>.<cc>" with pure integer
// math — the one money-presentation rule shared by every renderer. Domain
// validation guarantees non-negative cents; the currency code is the
// caller-visible unit because a symbol table is presentation the business
// does not need yet.
func money(currency string, cents int64) string {
	return currency + " " + strconv.FormatInt(cents/100, 10) + "." + pad2(cents%100)
}

// percent renders basis points as "<n>.<nn>%" with pure integer math.
func percent(bps int64) string {
	return strconv.FormatInt(bps/100, 10) + "." + pad2(bps%100) + "%"
}

// pad2 zero-pads a 0-99 value to two digits.
func pad2(n int64) string {
	if n < 10 {
		return "0" + strconv.FormatInt(n, 10)
	}
	return strconv.FormatInt(n, 10)
}
