// types.go collects the package's type declarations and package-level
// const/var blocks so the reviews/v1 data model can be surveyed in one
// place. Aggregation, validation, and sample construction stay in
// reviews.go.

package reviews

import "time"

// Submission bounds, enforced by ValidateSubmission and pinned by tests.
// Byte lengths, not runes: they are transport caps, not typography.
const (
	// maxAuthorBytes caps the submitted author name.
	maxAuthorBytes = 120
	// maxTextBytes caps the submitted review text.
	maxTextBytes = 2000
	// minRating and maxRating bound the 1-5 star scale.
	minRating = 1
	maxRating = 5
)

// SourceFirstParty labels reviews submitted directly to this site. External
// review platforms are a documented config-driven fetch design, not wired
// here.
const SourceFirstParty = "first-party"

// samplePublishedAt is the fixed publication instant of the embedded sample
// reviews, keeping sample payloads byte-identical across requests, replicas,
// and restarts so their digest ETags stay stable. Real submissions, once
// persistence exists, will carry their real timestamps.
var samplePublishedAt = time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC)

// Data is the reviews/v1 payload: the server-computed aggregate plus the
// review list. The aggregate is always computed here — clients render it,
// they never derive it.
type Data struct {
	Aggregate Aggregate `json:"aggregate"`
	Reviews   []Review  `json:"reviews"`
}

// Aggregate summarizes the review set.
type Aggregate struct {
	// Count is the number of reviews.
	Count int `json:"count"`
	// Average is the mean rating rounded half up to one decimal. It is
	// derived from integer tenths so the value is deterministic; it is not a
	// money path.
	Average float64 `json:"average"`
	// Histogram counts reviews per rating: index i holds the count of
	// (i+1)-star reviews.
	Histogram [5]int `json:"histogram"`
}

// Review is one published review.
type Review struct {
	ID     string `json:"id"`
	Author string `json:"author"`
	// Rating is an integer 1-5.
	Rating int    `json:"rating"`
	Text   string `json:"text"`
	// Source is SourceFirstParty for direct submissions.
	Source    string `json:"source"`
	CreatedAt string `json:"createdAt"`
}

// Submission is a first-party review submission. The contract ships now;
// persistence arrives with the platform storage layer, so a valid
// submission currently receives an honest "unavailable" answer.
type Submission struct {
	Author string `json:"author"`
	Rating int    `json:"rating"`
	Text   string `json:"text"`
}
