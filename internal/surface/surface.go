// Package surface defines lidersea.com's surface catalog: the surface/v1
// envelope every JSON endpoint speaks, the registry of the surfaces this
// site serves, and each surface's pure data logic. The package is transport-
// free — it produces values, never HTTP — so every contract here is testable
// as plain functions and the server package owns all routing and headers.
package surface

import "time"

// NewEnvelope wraps a surface payload in the site's one response shape. The
// caller supplies the generation instant explicitly: embedded samples pass
// their fixed publication instant (keeping response bytes and ETags stable),
// while computed responses pass their real generation time.
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

// SamplePublishedAt exposes the fixed publication instant of the embedded
// sample payloads, so the server builds envelopes carrying exactly the
// samples' generation time.
func SamplePublishedAt() time.Time {
	return samplePublishedAt
}
