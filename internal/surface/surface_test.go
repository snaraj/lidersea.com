// Package surface tests pin the envelope vocabulary and the registry's
// internal consistency. Contract strings are asserted as independent
// literals on purpose — importing the constants back would make every
// assertion a tautology.
package surface

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestEnvelopeVocabularyIsPinned locks the exact wire strings of the
// envelope contract the UI builds against: the schema version, the status
// values, and each registered surface's kind. A change here is a conscious
// contract revision, never drift.
func TestEnvelopeVocabularyIsPinned(t *testing.T) {
	t.Parallel()
	if Schema != "surface/v1" {
		t.Errorf("Schema = %q, want surface/v1", Schema)
	}
	for want, got := range map[string]Status{
		"ok":          StatusOK,
		"stale":       StatusStale,
		"unavailable": StatusUnavailable,
	} {
		if string(got) != want {
			t.Errorf("status constant = %q, want %q", got, want)
		}
	}
	for id, want := range map[string]string{
		"board":     "media-mosaic/v1",
		"reviews":   "reviews/v1",
		"estimates": "estimates/v1",
	} {
		found := false
		for _, d := range Registry {
			if d.ID == id {
				found = true
				if d.Kind != want {
					t.Errorf("surface %s kind = %q, want %q", id, d.Kind, want)
				}
			}
		}
		if !found {
			t.Errorf("registry is missing surface %q", id)
		}
	}
}

// TestRegistryIsInternallyConsistent requires every registered surface to be
// complete and collision-free: explicit /api/ routes, unique IDs and routes,
// non-empty titles and kinds.
func TestRegistryIsInternallyConsistent(t *testing.T) {
	t.Parallel()
	ids := map[string]bool{}
	routes := map[string]bool{}
	for _, d := range Registry {
		if d.ID == "" || d.Kind == "" || d.Title == "" {
			t.Errorf("descriptor %+v has an empty field", d)
		}
		if !strings.HasPrefix(d.Route, "/api/") {
			t.Errorf("surface %s route %q is not under /api/", d.ID, d.Route)
		}
		if ids[d.ID] {
			t.Errorf("duplicate surface id %q", d.ID)
		}
		if routes[d.Route] {
			t.Errorf("duplicate surface route %q", d.Route)
		}
		ids[d.ID] = true
		routes[d.Route] = true
	}
}

// TestNewEnvelopeCarriesTheDescriptor verifies field mapping and the UTC
// RFC 3339 rendering of the generation instant, including the JSON key
// casing the UI will consume.
func TestNewEnvelopeCarriesTheDescriptor(t *testing.T) {
	t.Parallel()
	generated := time.Date(2026, time.August, 11, 15, 4, 5, 0, time.FixedZone("east", 3*3600))
	env := NewEnvelope(Board, StatusOK, generated, "payload")
	if env.Schema != "surface/v1" || env.ID != "board" || env.Kind != "media-mosaic/v1" {
		t.Errorf("envelope identity = %q %q %q", env.Schema, env.ID, env.Kind)
	}
	if env.Title == "" || env.Status != StatusOK || env.Data != "payload" {
		t.Errorf("envelope content = %+v", env)
	}
	if env.GeneratedAt != "2026-08-11T12:04:05Z" {
		t.Errorf("GeneratedAt = %q, want the UTC RFC 3339 instant", env.GeneratedAt)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	for _, key := range []string{`"schema"`, `"id"`, `"kind"`, `"title"`, `"generatedAt"`, `"status"`, `"data"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("envelope JSON lacks key %s: %s", key, raw)
		}
	}
}

// TestSamplePublishedAtIsFixedUTC pins the sample-payload property the cache
// identity depends on: a constant UTC instant, so sample envelopes marshal
// to identical bytes on every request, replica, and restart.
func TestSamplePublishedAtIsFixedUTC(t *testing.T) {
	t.Parallel()
	first, second := SamplePublishedAt(), SamplePublishedAt()
	if !first.Equal(second) || first.Location() != time.UTC {
		t.Errorf("SamplePublishedAt = %v then %v, want one fixed UTC instant", first, second)
	}
	if first.IsZero() {
		t.Error("SamplePublishedAt is the zero time")
	}
}
