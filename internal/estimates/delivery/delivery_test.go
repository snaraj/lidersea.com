// Package delivery tests pin the contract's only current truth: with no
// transport configured, every delivery attempt is refused honestly — never
// an error, never a fabricated success.
package delivery

import (
	"testing"

	"github.com/snaraj/lidersea.com/internal/estimates"
)

// The unconfigured refusal must satisfy the delivery contract itself, so a
// future real transport is a drop-in replacement, not a redesign.
var _ Delivery = Unconfigured{}

// TestUnconfiguredDeliveryRefusesHonestly requires the not-configured state
// to say exactly what it is for any estimate and recipient: not delivered,
// with the documented reason.
func TestUnconfiguredDeliveryRefusesHonestly(t *testing.T) {
	t.Parallel()
	estimate := estimates.Estimate{Currency: "USD", TotalCents: 12_345, Status: estimates.StatusDraft}
	for _, recipient := range []string{"client@example.invalid", ""} {
		result := Unconfigured{}.Deliver(estimate, recipient)
		if result.Delivered {
			t.Fatalf("Deliver(recipient %q) fabricated success", recipient)
		}
		if result.Reason != NotConfiguredReason {
			t.Errorf("Deliver reason = %q, want %q", result.Reason, NotConfiguredReason)
		}
	}
}
