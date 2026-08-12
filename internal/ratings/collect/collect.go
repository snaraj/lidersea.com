// Package collect is the ratings surface's optional, gated producer: it can
// refresh the embedded ratings snapshot from each platform's own feed URL.
//
// It ships OFF. The zero-value configuration collects nothing, the shipped
// snapshot carries no feed URLs at all, and the cluster this site runs in
// denies egress by default — so enabling the gate is an explicit operator
// decision on three independent axes, not a flag flip. That is deliberate:
// at the time this package was written no supported rating platform offered
// a rating read without an account credential, so the mechanism exists as a
// reviewed, tested contract for a future authenticated ingest rather than
// as a capability with something to fetch today.
//
// Everything about a pass is snapshot-first and fail-soft. The current
// snapshot is the input; a platform whose feed cannot be read, is too
// large, redirects, answers the wrong type, or produces a value that fails
// snapshot validation KEEPS THE VALUE IT ALREADY HAD. No failure mode in
// this package can blank a published rating or shrink the strip.
//
// The safety properties are fixed in code and reachable from no
// configuration and no data file: https only, the ratings package's
// per-platform host allowlist re-checked at call time, redirects refused
// outright, a hard body cap, a JSON content-type requirement, a strict
// decode, bounded connect/handshake/request timeouts, and a final pass of
// the whole result through the same validation the shipped data file must
// satisfy.
package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/snaraj/lidersea.com/internal/ratings"
)

// ConfigFromEnv parses the collector's environment fail-closed: the
// capability is enabled only by the complete, valid variable set, and every
// partial or malformed set is a startup error rather than a silently
// half-configured background worker. Absence of all three variables is the
// one valid disabled state (an explicit "false" is accepted as its
// spelling).
func ConfigFromEnv(lookup func(string) string) (Config, error) {
	enabled := lookup(envEnabled)
	interval := lookup(envInterval)
	timeout := lookup(envTimeout)

	switch enabled {
	case "", "false":
		if interval != "" || timeout != "" {
			return Config{}, errors.New("ratings collector configuration is all-or-nothing: " +
				envInterval + " and " + envTimeout + " require " + envEnabled + "=true")
		}
		return Config{}, nil
	case "true":
		if interval == "" || timeout == "" {
			return Config{}, errors.New(envEnabled + "=true requires both " + envInterval + " and " + envTimeout)
		}
		parsedInterval, err := parseDuration(interval, MinInterval, MaxInterval)
		if err != nil {
			return Config{}, errors.New(envInterval + " must be a duration between " +
				MinInterval.String() + " and " + MaxInterval.String())
		}
		parsedTimeout, err := parseDuration(timeout, MinTimeout, MaxTimeout)
		if err != nil {
			return Config{}, errors.New(envTimeout + " must be a duration between " +
				MinTimeout.String() + " and " + MaxTimeout.String())
		}
		return Config{Enabled: true, Interval: parsedInterval, Timeout: parsedTimeout}, nil
	default:
		return Config{}, errors.New(envEnabled + ` must be "true" or "false"`)
	}
}

// New builds the production collector: a client that refuses redirects,
// bounds every phase of a request, and keeps a small connection pool. There
// is no constructor parameter that could relax any of it.
func New(cfg Config) *Collector {
	return newCollector(cfg, &http.Transport{
		DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConns,
		ForceAttemptHTTP2:   true,
	})
}

// Run drives collection passes until ctx is cancelled: one pass at start so
// a restart does not wait a whole window, then one per configured interval.
// It returns on cancellation, which is how the process's own shutdown path
// stops it. Calling it with a disabled configuration is a no-op, so the
// caller never has to branch.
func Run(ctx context.Context, cfg Config, store *ratings.Store) {
	if !cfg.Enabled {
		return
	}
	collector := New(cfg)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		store.Replace(collector.Collect(ctx, store.Load(), time.Now().UTC()))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Collect performs one pass over current and returns the snapshot to serve
// next. It never returns an error: a pass is a best-effort refresh of data
// the site already has, so every failure resolves to keeping what is
// already published. The pass as a whole is re-validated through the
// ratings package's own Build, and a result that fails is discarded whole
// in favour of current — a collected snapshot can never be laxer than an
// authored one.
func (c *Collector) Collect(ctx context.Context, current ratings.Data, now time.Time) ratings.Data {
	file := current.File()
	refreshed := 0
	for index, platform := range file.Platforms {
		if platform.FeedURL == "" {
			continue
		}
		reading, err := c.read(ctx, platform.ID, platform.FeedURL)
		if err != nil {
			slog.Warn("ratings feed not collected", "platform", platform.ID, "error", err)
			continue
		}
		file.Platforms[index].State = ratings.StatePublished
		file.Platforms[index].RatingTenths = reading.RatingTenths
		file.Platforms[index].ReviewCount = reading.ReviewCount
		file.Platforms[index].CapturedAt = reading.CapturedAt
		refreshed++
	}
	if refreshed == 0 {
		return current
	}
	file.PublishedAt = now.UTC().Format(time.RFC3339)
	collected, err := ratings.Build(file)
	if err != nil {
		slog.Warn("collected ratings snapshot rejected", "error", errors.Join(ErrRejectedSnapshot, err))
		return current
	}
	return collected
}

// read fetches and decodes one platform's feed. Every refusal is a static
// error naming the rule; none of them carries response bytes, because a
// third party's body must never reach this origin's logs.
func (c *Collector) read(ctx context.Context, platformID, feedURL string) (Reading, error) {
	parsed, err := url.Parse(feedURL)
	if err != nil {
		return Reading{}, ErrFeedUnreadable
	}
	if parsed.Scheme != "https" {
		return Reading{}, ErrSchemeNotAllowed
	}
	// The allowlist is re-checked here, at the moment of the call, even
	// though snapshot validation already rejected anything else: a check
	// that only runs at authoring time protects only authored data.
	if !ratings.AllowedHost(platformID, parsed.Host) {
		return Reading{}, ErrHostNotAllowed
	}

	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, feedURL, nil)
	if err != nil {
		return Reading{}, ErrFeedUnreadable
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirectRefused) {
			return Reading{}, ErrRedirectRefused
		}
		return Reading{}, ErrFeedUnreadable
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Reading{}, ErrFeedStatus
	}
	if mediaType, _, _ := strings.Cut(response.Header.Get("Content-Type"), ";"); strings.TrimSpace(mediaType) != "application/json" {
		return Reading{}, ErrFeedContentType
	}
	// One byte past the cap is a refusal rather than a truncation, so an
	// oversized feed is reported as what it is.
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxFeedBytes+1))
	if err != nil {
		return Reading{}, ErrFeedUnreadable
	}
	if len(body) > MaxFeedBytes {
		return Reading{}, ErrFeedTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var reading Reading
	if err := decoder.Decode(&reading); err != nil || decoder.More() {
		return Reading{}, ErrFeedUnreadable
	}
	return reading, nil
}

// newCollector assembles a collector over an explicit transport. It is
// unexported so no caller outside this package's own suite can substitute
// one: production construction goes through New, which supplies the
// hardened transport above.
func newCollector(cfg Config, transport http.RoundTripper) *Collector {
	return &Collector{
		client: &http.Client{
			Transport: transport,
			// Refusing redirects is the point: a redirect is the standard way
			// out of a host allowlist, and following one would mean trusting a
			// destination nobody reviewed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirectRefused },
			Timeout:       cfg.Timeout,
		},
		timeout: cfg.Timeout,
	}
}

// parseDuration parses a Go duration and requires it inside an inclusive
// range. Out-of-range is an error, never a clamp: silently correcting an
// operator's value hides the misconfiguration instead of surfacing it.
func parseDuration(value string, low, high time.Duration) (time.Duration, error) {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if parsed < low || parsed > high {
		return 0, errors.New("duration out of range")
	}
	return parsed, nil
}
