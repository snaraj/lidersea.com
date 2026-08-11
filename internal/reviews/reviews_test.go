// Package reviews tests pin the reviews/v1 domain: sample well-formedness,
// the server-computed aggregate's integer-tenths math, and the strict
// submission validation guarding the gated write path.
package reviews

import (
	"strings"
	"testing"
	"time"
)

// TestSnapshotAggregateIsServerMath recomputes the aggregate from the served
// list independently and requires exact agreement: histogram totals, count,
// and the half-up integer-tenths mean. Clients render these numbers; this
// test is why they never need to derive them.
func TestSnapshotAggregateIsServerMath(t *testing.T) {
	t.Parallel()
	data := Snapshot()
	if len(data.Reviews) == 0 {
		t.Fatal("sample snapshot has no reviews")
	}
	if data.Aggregate.Count != len(data.Reviews) {
		t.Errorf("aggregate count = %d, want %d", data.Aggregate.Count, len(data.Reviews))
	}
	sum, histogramTotal := 0, 0
	var histogram [5]int
	for _, review := range data.Reviews {
		sum += review.Rating
		histogram[review.Rating-1]++
	}
	for _, n := range data.Aggregate.Histogram {
		histogramTotal += n
	}
	if histogramTotal != data.Aggregate.Count {
		t.Errorf("histogram sums to %d, want %d", histogramTotal, data.Aggregate.Count)
	}
	if histogram != data.Aggregate.Histogram {
		t.Errorf("histogram = %v, want %v", data.Aggregate.Histogram, histogram)
	}
	tenths := (sum*10 + len(data.Reviews)/2) / len(data.Reviews)
	if want := float64(tenths) / 10; data.Aggregate.Average != want {
		t.Errorf("average = %v, want %v (integer tenths, half up)", data.Aggregate.Average, want)
	}
}

// TestAggregateEdges covers the empty set (an honest zero aggregate, no
// division) and hand-checked rounding cases.
func TestAggregateEdges(t *testing.T) {
	t.Parallel()
	empty := aggregate(nil)
	if empty.Count != 0 || empty.Average != 0 || empty.Histogram != [5]int{} {
		t.Errorf("aggregate(nil) = %+v, want zeros", empty)
	}
	// Ratings 5 and 4: mean 4.5 exactly; tenths math must not truncate it.
	two := aggregate([]Review{{Rating: 5}, {Rating: 4}})
	if two.Average != 4.5 {
		t.Errorf("aggregate mean = %v, want 4.5", two.Average)
	}
	// Ratings 5, 5, 4: mean 4.666… rounds half up to 4.7.
	three := aggregate([]Review{{Rating: 5}, {Rating: 5}, {Rating: 4}})
	if three.Average != 4.7 {
		t.Errorf("aggregate mean = %v, want 4.7", three.Average)
	}
}

// TestPublishedAtIsFixedUTC pins the sample-data property the cache identity
// depends on: a constant UTC instant.
func TestPublishedAtIsFixedUTC(t *testing.T) {
	t.Parallel()
	first, second := PublishedAt(), PublishedAt()
	if !first.Equal(second) || first.Location() != time.UTC || first.IsZero() {
		t.Errorf("PublishedAt = %v then %v, want one fixed UTC instant", first, second)
	}
}

// TestSampleReviewsAreWellFormed requires every sample review to satisfy the
// contract shape: ids, in-range integer ratings, first-party source,
// parseable timestamps, and text within the submission caps (samples must
// obey the same bounds the write path enforces).
func TestSampleReviewsAreWellFormed(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, review := range sampleReviews() {
		if review.ID == "" || seen[review.ID] {
			t.Errorf("review id %q missing or duplicated", review.ID)
		}
		seen[review.ID] = true
		if review.Rating < 1 || review.Rating > 5 {
			t.Errorf("%s: rating %d out of range", review.ID, review.Rating)
		}
		if review.Source != SourceFirstParty {
			t.Errorf("%s: source = %q, want %q", review.ID, review.Source, SourceFirstParty)
		}
		if _, err := time.Parse(time.RFC3339, review.CreatedAt); err != nil {
			t.Errorf("%s: createdAt %q is not RFC 3339", review.ID, review.CreatedAt)
		}
		if err := ValidateSubmission(Submission{Author: review.Author, Rating: review.Rating, Text: review.Text}); err != nil {
			t.Errorf("%s: sample violates the submission contract: %v", review.ID, err)
		}
	}
}

// TestValidateSubmission drives the whole validation table: the 1-5 integer
// rating bounds, required fields, whitespace-only rejection, and the
// byte-length caps at their exact boundaries.
func TestValidateSubmission(t *testing.T) {
	t.Parallel()
	valid := Submission{Author: "Charter owner", Rating: 5, Text: "Excellent work."}
	tests := []struct {
		name    string
		mutate  func(*Submission)
		wantErr bool
	}{
		{name: "valid", mutate: func(s *Submission) {}},
		{name: "rating low", mutate: func(s *Submission) { s.Rating = 0 }, wantErr: true},
		{name: "rating high", mutate: func(s *Submission) { s.Rating = 6 }, wantErr: true},
		{name: "rating negative", mutate: func(s *Submission) { s.Rating = -1 }, wantErr: true},
		{name: "rating boundary one", mutate: func(s *Submission) { s.Rating = 1 }},
		{name: "author empty", mutate: func(s *Submission) { s.Author = "" }, wantErr: true},
		{name: "author whitespace", mutate: func(s *Submission) { s.Author = "   " }, wantErr: true},
		{name: "author at cap", mutate: func(s *Submission) { s.Author = strings.Repeat("a", 120) }},
		{name: "author over cap", mutate: func(s *Submission) { s.Author = strings.Repeat("a", 121) }, wantErr: true},
		{name: "text empty", mutate: func(s *Submission) { s.Text = "" }, wantErr: true},
		{name: "text whitespace", mutate: func(s *Submission) { s.Text = " \n\t" }, wantErr: true},
		{name: "text at cap", mutate: func(s *Submission) { s.Text = strings.Repeat("b", 2000) }},
		{name: "text over cap", mutate: func(s *Submission) { s.Text = strings.Repeat("b", 2001) }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			submission := valid
			test.mutate(&submission)
			err := ValidateSubmission(submission)
			if (err != nil) != test.wantErr {
				t.Errorf("ValidateSubmission(%+v) error = %v, wantErr %v", submission, err, test.wantErr)
			}
			if err != nil && submission.Author != "" && strings.Contains(err.Error(), submission.Author) {
				t.Errorf("validation error %q echoes client input", err)
			}
		})
	}
}
