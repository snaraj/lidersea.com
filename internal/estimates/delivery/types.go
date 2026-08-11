// types.go collects the package's type declarations and package-level
// const/var blocks so the delivery contract can be surveyed in one place.
// The unconfigured implementation's behavior stays in delivery.go.

package delivery

import "github.com/snaraj/lidersea.com/internal/estimates"

// NotConfiguredReason is the honest answer of the delivery contract until a
// transport exists.
const NotConfiguredReason = "estimate delivery is not configured"

// Delivery sends a computed estimate to a recipient. This is the contract
// the owner's "email an estimate" capability lands behind; implementations
// carry the transport, and callers carry the gate discipline (default off,
// one narrow route, honest refusals — the same pattern as every other write
// carve-out).
type Delivery interface {
	// Deliver attempts to send the estimate and reports the honest outcome.
	// It never fabricates success: an implementation without a working
	// transport answers Delivered: false with its reason.
	Deliver(estimate estimates.Estimate, recipient string) Result
}

// Result is one delivery attempt's honest outcome.
type Result struct {
	// Delivered reports whether the estimate actually went out.
	Delivered bool `json:"delivered"`
	// Reason explains a false Delivered; empty on success.
	Reason string `json:"reason,omitempty"`
}

// Unconfigured is the only implementation until the platform egress design
// lands: it refuses every delivery, honestly.
type Unconfigured struct{}
