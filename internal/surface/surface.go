// Package surface defines lidersea.com's surface vocabulary: the surface/v1
// envelope every JSON endpoint speaks and the registry of the surfaces this
// site serves. It is deliberately thin — a contract package, not a logic
// package: each surface's data and rules live in that surface's own domain
// package (internal/board, internal/reviews, internal/estimates), and the
// server layer composes domain payloads into envelopes at its routes.
package surface

import "time"

// NewEnvelope wraps a surface payload in the site's one response shape. The
// caller supplies the generation instant explicitly: embedded samples pass
// their domain's fixed publication instant (keeping response bytes and ETags
// stable), while computed responses pass their real generation time.
func NewEnvelope(d Descriptor, status Status, generatedAt time.Time, data any) Envelope {
	return Envelope{
		Schema:      Schema,
		ID:          d.ID,
		Kind:        d.Kind,
		Title:       d.Title,
		GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
		Status:      status,
		Data:        data,
	}
}
