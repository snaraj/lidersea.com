// Package delivery defines the estimate delivery contract — and, today,
// deliberately nothing that can send. Emailing an estimate needs a
// transport, and every candidate transport (SMTP, a provider API) is
// origin-side egress governed by requirements 1 and 11 (zero spend, no
// external services, no personal data at rest) and by the platform's egress
// design, which does not exist yet. So this package ships the interface and
// one implementation: an honest refusal.
//
// NO transport code, NO egress, NO recipient storage lives here or should be
// added here ad hoc. When the platform egress design lands, a real
// implementation arrives behind its own default-off gate and its own HTTP
// route with the same carve-out discipline as the other write paths — until
// then, no route accepts recipient addresses at all, because collecting a
// recipient the origin cannot serve would be theater with someone's email
// address.
package delivery

import "github.com/snaraj/lidersea.com/internal/estimates"

// Deliver refuses honestly: no transport is configured, and the result says
// exactly that instead of pretending the estimate went anywhere.
func (Unconfigured) Deliver(estimates.Estimate, string) Result {
	return Result{Delivered: false, Reason: NotConfiguredReason}
}
