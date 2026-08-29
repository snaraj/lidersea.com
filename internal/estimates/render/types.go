// types.go collects the package's type declarations and package-level
// const/var blocks so the rendering contract can be surveyed in one place.
// Registry lookup and shared formatting stay in render.go; each renderer's
// logic stays in its own file (markdown.go, html.go).

package render

import "github.com/snaraj/lidersea.com/internal/estimates"

// Format names. FormatJSON is the canonical estimate itself — served by the
// envelope path, never a Renderer — while the others name registry entries.
const (
	// FormatJSON is the canonical format-neutral estimate (the default).
	FormatJSON = "json"
	// FormatMarkdown renders a markdown document.
	FormatMarkdown = "markdown"
	// FormatHTML renders a print-ready semantic HTML document.
	FormatHTML = "html"
)

// Renderer maps the canonical computed estimate to one presentation format.
// Renderers present, never compute: every money figure they emit comes from
// the estimate's already-computed integer cents, so a rendering can never
// disagree with the canonical JSON. Conversion between formats is free by
// construction — render the canonical estimate into the target.
type Renderer interface {
	// Format is the registry key and the ?format= parameter value.
	Format() string
	// ContentType is the exact Content-Type served with the rendering.
	ContentType() string
	// Render produces the document bytes for one computed estimate.
	Render(estimate estimates.Estimate) ([]byte, error)
}

// markdownRenderer renders FormatMarkdown; logic in markdown.go.
type markdownRenderer struct{}

// htmlRenderer renders FormatHTML; logic in html.go.
type htmlRenderer struct{}

// registry is the closed set of available renderers. PDF deliberately has no
// entry: the intended v1 is the browser's own print-to-PDF over the HTML
// rendering above, and TRUE server-side PDF generation requires a library —
// an owner dependency decision (requirement 9: the Go module stays
// standard-library only), not incremental drift. Its slot in this registry
// is reserved for that decision.
var registry = map[string]Renderer{
	FormatMarkdown: markdownRenderer{},
	FormatHTML:     htmlRenderer{},
}
