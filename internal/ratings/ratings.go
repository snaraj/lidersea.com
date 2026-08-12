// Package ratings is the ratings/v1 domain: the strip of third-party
// rating platforms the site links out to, the owner-editable snapshot that
// carries their captured values, and the validation that makes a
// half-filled snapshot impossible to serve.
//
// It is pure — no HTTP, no I/O beyond the embedded file, no envelope
// knowledge — so the server layer composes it and every rule here is
// testable as plain functions. The optional, gated collector that can
// refresh the snapshot lives in the collect subpackage; nothing here
// reaches the network.
//
// # Honesty rules
//
// A platform either publishes a captured rating or it does not. There is
// no partially-populated state: a pending platform must carry no rating,
// no review count, and no capture instant, so a data file cannot present
// an invented number as a business fact. When nothing is published the
// summary omits its average entirely rather than reporting a zero, which
// a reader would see as a rating of zero rather than as an absence.
//
// # Updating the snapshot
//
// platforms.json is the owner's file. To publish a platform's rating:
//
//  1. Read the rating and review count from the platform's own public
//     profile page.
//  2. Set that platform's "profileUrl" to the public profile URL. It must
//     be an https URL whose host is on that platform's allowlist in
//     types.go — a data file can never introduce a new outbound
//     destination, because that is a code decision.
//  3. Set "ratingTenths" to the rating times ten (4.9 becomes 49),
//     "reviewCount" to the review count, "capturedAt" to the UTC instant
//     you read them, and "state" to "published".
//  4. Bump the file's top-level "publishedAt" to the same instant.
//  5. Run the Go suite. Every rule above is enforced by Snapshot, which
//     the server calls during construction: a malformed snapshot fails
//     startup rather than reaching a visitor.
//
// A platform may carry a "profileUrl" while still "pending" — a listed
// profile with no rating captured yet is a legitimate state and renders as
// a link without a number.
package ratings

import (
	"bytes"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Snapshot decodes and validates the embedded data file. The server calls
// it during construction, so a snapshot that breaks any rule stops the
// process before Kubernetes routes traffic to it.
func Snapshot() (Data, error) {
	return Decode(snapshotJSON)
}

// Decode parses one snapshot document and returns the served payload. It is
// exported so a test — or a future collector ingest — validates exactly the
// bytes the server would, through the same door.
func Decode(document []byte) (Data, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	// Unknown fields are a rejected snapshot, never ignored input: a typo in
	// a field name would otherwise silently drop the value it was meant to
	// set and publish the default instead.
	decoder.DisallowUnknownFields()
	var file File
	if err := decoder.Decode(&file); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Data{}, ErrSnapshotUnknownKeys
		}
		return Data{}, ErrSnapshotUnreadable
	}
	if decoder.More() {
		return Data{}, ErrSnapshotUnreadable
	}
	return Build(file)
}

// AllowedHost reports whether host is an approved outbound destination for
// the named platform. It is the single gate both the profile links and the
// gated collector pass through, so no data file and no environment setting
// can widen the set of hosts this site talks to or sends a visitor to.
func AllowedHost(platformID, host string) bool {
	hosts, registered := allowedHosts[platformID]
	return registered && slices.Contains(hosts, host)
}

// RegisteredPlatform reports whether the platform id has an allowlist at
// all. A snapshot naming an unregistered platform is rejected: it would
// have no approved destination and could never be published.
func RegisteredPlatform(platformID string) bool {
	_, registered := allowedHosts[platformID]
	return registered
}

// Freshness reports how the snapshot should be presented. maxAge is the
// refresh window the operator configured for the gated collector; zero
// means no refresh contract exists — the shipped snapshot is the shipped
// truth and cannot be "late".
func (d Data) Freshness(now time.Time, maxAge time.Duration) Freshness {
	if d.Summary.Published == 0 {
		return FreshnessNoRatings
	}
	if maxAge <= 0 {
		return FreshnessCurrent
	}
	for _, platform := range d.Platforms {
		if platform.State != StatePublished {
			continue
		}
		// Parsing cannot fail here: every published capture instant was
		// validated on the way in.
		captured, _ := time.Parse(time.RFC3339, platform.CapturedAt)
		if now.Sub(captured) <= maxAge {
			return FreshnessCurrent
		}
	}
	return FreshnessAged
}

// File returns the authored form of a served snapshot, so a caller that
// wants to change one value — the gated collector is the only one — can
// re-authorise the whole document through Build rather than mutating the
// served payload in place.
func (d Data) File() File {
	file := File{PublishedAt: d.PublishedAt, Platforms: make([]FilePlatform, 0, len(d.Platforms))}
	for _, platform := range d.Platforms {
		file.Platforms = append(file.Platforms, FilePlatform{
			ID:           platform.ID,
			Name:         platform.Name,
			State:        platform.State,
			ProfileURL:   platform.ProfileURL,
			FeedURL:      platform.FeedURL,
			RatingTenths: int(platform.Rating*10 + 0.5),
			ReviewCount:  platform.ReviewCount,
			CapturedAt:   platform.CapturedAt,
		})
	}
	return file
}

// NewStore holds an already-validated snapshot for serving.
func NewStore(data Data) *Store {
	store := &Store{}
	store.Replace(data)
	return store
}

// Load returns the snapshot currently being served.
func (s *Store) Load() Data {
	return *s.current.Load()
}

// Replace publishes a new snapshot to every subsequent request at once.
// Only the gated collector calls it; with the collector off, the snapshot
// the process started with is the snapshot it serves for its whole life.
func (s *Store) Replace(data Data) {
	s.current.Store(&data)
}

// Build validates an authored file and derives the served payload from it.
// Every rule is checked before anything is derived, so a rejected snapshot
// never produces a partially-computed summary. It is exported so the gated
// collector's output passes through EXACTLY the validation the shipped file
// does — a collected snapshot can never be laxer than an authored one.
func Build(file File) (Data, error) {
	if len(file.Platforms) == 0 {
		return Data{}, ErrNoPlatforms
	}
	if len(file.Platforms) > MaxPlatforms {
		return Data{}, ErrTooManyPlatforms
	}
	if err := validateInstant(file.PublishedAt); err != nil {
		return Data{}, ErrPublishedAtInstant
	}

	data := Data{PublishedAt: file.PublishedAt, Platforms: make([]Platform, 0, len(file.Platforms))}
	seen := make(map[string]bool, len(file.Platforms))
	weightedTenths, reviews := 0, 0
	for _, authored := range file.Platforms {
		platform, err := validatePlatform(authored, seen)
		if err != nil {
			return Data{}, err
		}
		seen[authored.ID] = true
		if authored.State == StatePublished {
			data.Summary.Published++
			reviews += authored.ReviewCount
			weightedTenths += authored.RatingTenths * authored.ReviewCount
		} else {
			data.Summary.Pending++
		}
		data.Platforms = append(data.Platforms, platform)
	}

	data.Summary.Scale = Scale
	data.Summary.Reviews = reviews
	if reviews > 0 {
		// Weighted by review count, derived in integer tenths and rounded
		// half up, so the value is deterministic on every platform. Ratings
		// are not money; the integer discipline here is for determinism.
		data.Summary.Average = float64((weightedTenths+reviews/2)/reviews) / 10
	}
	return data, nil
}

// validatePlatform enforces every per-platform rule and returns the served
// entry. The published and pending shapes are checked as WHOLE shapes, not
// field by field, which is what makes a half-filled entry unrepresentable.
func validatePlatform(authored FilePlatform, seen map[string]bool) (Platform, error) {
	if !platformIDPattern.MatchString(authored.ID) {
		return Platform{}, ErrPlatformID
	}
	if seen[authored.ID] {
		return Platform{}, ErrDuplicatePlatform
	}
	if !RegisteredPlatform(authored.ID) {
		return Platform{}, ErrUnknownPlatform
	}
	if authored.Name == "" || len(authored.Name) > MaxNameBytes {
		return Platform{}, ErrPlatformName
	}
	if authored.ProfileURL != "" {
		if err := validateOutboundURL(authored.ID, authored.ProfileURL); err != nil {
			return Platform{}, err
		}
	}
	if authored.FeedURL != "" {
		if err := validateOutboundURL(authored.ID, authored.FeedURL); err != nil {
			return Platform{}, err
		}
	}

	platform := Platform{
		ID:         authored.ID,
		Name:       authored.Name,
		State:      authored.State,
		ProfileURL: authored.ProfileURL,
		FeedURL:    authored.FeedURL,
	}
	switch authored.State {
	case StatePublished:
		if authored.ProfileURL == "" {
			return Platform{}, ErrPublishedNeedsURL
		}
		if authored.RatingTenths < MinRatingTenths || authored.RatingTenths > MaxRatingTenths {
			return Platform{}, ErrRatingOutOfRange
		}
		if authored.ReviewCount < 1 || authored.ReviewCount > MaxReviewCount {
			return Platform{}, ErrReviewCountRange
		}
		if err := validateInstant(authored.CapturedAt); err != nil {
			return Platform{}, err
		}
		platform.Rating = float64(authored.RatingTenths) / 10
		platform.ReviewCount = authored.ReviewCount
		platform.CapturedAt = authored.CapturedAt
	case StatePending:
		if authored.RatingTenths != 0 || authored.ReviewCount != 0 || authored.CapturedAt != "" {
			return Platform{}, ErrPendingHasRating
		}
	default:
		return Platform{}, ErrPlatformState
	}
	return platform, nil
}

// validateOutboundURL is the one door every URL this site emits or reads
// passes through: absolute https, an allowlisted host for that platform, no
// credentials, no fragment, no unprintable bytes, and a bounded length.
func validateOutboundURL(platformID, raw string) error {
	if len(raw) > MaxURLBytes {
		return ErrURLLength
	}
	if strings.TrimFunc(raw, func(r rune) bool { return r > 0x20 && r < 0x7f }) != "" {
		return ErrURLShape
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ErrURLShape
	}
	if parsed.Scheme != "https" {
		return ErrURLScheme
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return ErrURLShape
	}
	if !AllowedHost(platformID, parsed.Host) {
		return ErrURLHost
	}
	return nil
}

// validateInstant requires an RFC 3339 instant expressed in UTC. A local
// offset would make two snapshots incomparable and would leak the editor's
// timezone into a public repository.
func validateInstant(value string) error {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || !strings.HasSuffix(value, "Z") {
		return ErrCaptureInstant
	}
	return nil
}
