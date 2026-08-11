// config.go parses the handler's optional-capability configuration from the
// environment, fail-closed: unset means off, "true" means on, and anything
// else — including any partially-specified media set — is a startup error.
// No environment variable can ever weaken a security control; these gates
// only add narrowly-scoped capabilities whose default is absence.

package server

import (
	"errors"

	"github.com/snaraj/lidersea.com/internal/media"
)

// ConfigFromEnv assembles the complete surface configuration from the
// environment lookup run() already injects, so tests drive every gate
// combination without touching process globals.
func ConfigFromEnv(lookup func(string) string) (Config, error) {
	mediaCfg, err := media.ConfigFromEnv(lookup)
	if err != nil {
		return Config{}, err
	}
	reviewsWrite, err := featureGate(lookup, "REVIEWS_WRITE_ENABLED")
	if err != nil {
		return Config{}, err
	}
	estimates, err := featureGate(lookup, "ESTIMATES_ENABLED")
	if err != nil {
		return Config{}, err
	}
	return Config{
		Media:               mediaCfg,
		ReviewsWriteEnabled: reviewsWrite,
		EstimatesEnabled:    estimates,
	}, nil
}

// featureGate parses one boolean capability gate strictly: absent and
// "false" are off, "true" is on, and any other value is a configuration
// error surfaced at startup — a typo must crash the pod, never silently
// resolve to either state.
func featureGate(lookup func(string) string, name string) (bool, error) {
	switch lookup(name) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errors.New(name + ` must be "true" or "false"`)
	}
}
