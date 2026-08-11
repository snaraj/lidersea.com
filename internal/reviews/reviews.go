// Package reviews is the reviews/v1 domain: embedded sample reviews, the
// server-computed aggregate, and submission validation for the gated write
// path. It is pure — no HTTP, no I/O, no envelope knowledge — so the server
// layer composes it into responses and every rule here is testable as plain
// functions. First-party persistence arrives with the platform storage
// layer; external review platforms are a documented config-driven fetch
// design, not wired here.
package reviews

import (
	"errors"
	"strings"
	"time"
)

// Submission validation errors. They are static strings — never echoes of
// client input — so handlers can return them verbatim without reflecting
// attacker-controlled bytes.
var (
	errRatingOutOfRange = errors.New("rating must be an integer between 1 and 5")
	errAuthorRequired   = errors.New("author is required")
	errAuthorTooLong    = errors.New("author exceeds the length cap")
	errTextRequired     = errors.New("text is required")
	errTextTooLong      = errors.New("text exceeds the length cap")
)

// PublishedAt is the generation instant of the sample snapshot, exposed so
// the composing layer can stamp envelopes with exactly the data's
// provenance.
func PublishedAt() time.Time {
	return samplePublishedAt
}

// Snapshot returns the reviews/v1 payload: the embedded sample list with its
// aggregate computed server-side.
func Snapshot() Data {
	reviews := sampleReviews()
	return Data{Aggregate: aggregate(reviews), Reviews: reviews}
}

// aggregate computes count, histogram, and the mean rating. The mean is
// derived in integer tenths — (sum×10 + count/2) / count, rounding half up —
// then rendered as a one-decimal number, so the value is deterministic on
// every platform. Ratings are not money; the integer discipline here is for
// determinism, not cents.
func aggregate(reviews []Review) Aggregate {
	a := Aggregate{Count: len(reviews)}
	if a.Count == 0 {
		return a
	}
	sum := 0
	for _, review := range reviews {
		sum += review.Rating
		a.Histogram[review.Rating-1]++
	}
	tenths := (sum*10 + a.Count/2) / a.Count
	a.Average = float64(tenths) / 10
	return a
}

// ValidateSubmission enforces the write contract: an integer 1-5 rating and
// non-empty, capped author and text. It returns a static, client-safe error
// naming the first violated rule.
func ValidateSubmission(s Submission) error {
	if s.Rating < minRating || s.Rating > maxRating {
		return errRatingOutOfRange
	}
	if strings.TrimSpace(s.Author) == "" {
		return errAuthorRequired
	}
	if len(s.Author) > maxAuthorBytes {
		return errAuthorTooLong
	}
	if strings.TrimSpace(s.Text) == "" {
		return errTextRequired
	}
	if len(s.Text) > maxTextBytes {
		return errTextTooLong
	}
	return nil
}

// sampleReviews builds the embedded sample list, newest first. Authors are
// deliberately generic placeholders — requirement 11 keeps personal data out
// of this repository — and will be replaced by real submissions once
// persistence exists.
func sampleReviews() []Review {
	return []Review{
		{
			ID: "rev-006", Author: "Charter owner, 62' flybridge", Rating: 5,
			Text:      "The hull came back looking better than the day we took delivery. Meticulous from waterline to radar arch.",
			Source:    SourceFirstParty,
			CreatedAt: "2026-08-03T17:20:00Z",
		},
		{
			ID: "rev-005", Author: "Sailing yacht owner", Rating: 5,
			Text:      "Teak brightwork was stripped and refinished on schedule. Communication was clear at every step.",
			Source:    SourceFirstParty,
			CreatedAt: "2026-07-26T09:10:00Z",
		},
		{
			ID: "rev-004", Author: "Marina neighbor", Rating: 4,
			Text:      "Booked a seasonal wash-down program after watching them work a slip over. Consistent, careful crew.",
			Source:    SourceFirstParty,
			CreatedAt: "2026-07-15T14:45:00Z",
		},
		{
			ID: "rev-003", Author: "Sportfisher owner", Rating: 5,
			Text:      "Ceramic coating on the topsides has held through a full charter season. Water still sheets off.",
			Source:    SourceFirstParty,
			CreatedAt: "2026-07-02T11:30:00Z",
		},
		{
			ID: "rev-002", Author: "Trawler owner", Rating: 4,
			Text:      "Interior detail was thorough — galley, heads, and bilges all addressed. Scheduling took one extra call.",
			Source:    SourceFirstParty,
			CreatedAt: "2026-06-20T16:00:00Z",
		},
		{
			ID: "rev-001", Author: "First-time client", Rating: 5,
			Text:      "Estimate matched the final invoice to the dollar, and the running gear polish was immaculate.",
			Source:    SourceFirstParty,
			CreatedAt: "2026-06-08T10:05:00Z",
		},
	}
}
