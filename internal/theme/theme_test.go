// Package theme's suite proves the two properties the mechanism rests on:
// no value outside the catalog can ever be written into a served document,
// and a stamp changes exactly one attribute and not one other byte.
package theme

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// shell is a minimal but complete document with the single root element a
// real build emits, used wherever a test needs a stampable input.
const shell = `<!doctype html><html lang="en"><body><main>hello</main></body></html>`

// TestParseAcceptsOnlyCatalogValues sweeps the cookie value contract. Every
// row that is not an exact catalog spelling must resolve to Default with
// false, because the cookie is visitor-controlled input and Parse is the
// only door between it and a document.
func TestParseAcceptsOnlyCatalogValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		value  string
		want   Theme
		wantOK bool
	}{
		{name: "system", value: "system", want: System, wantOK: true},
		{name: "light", value: "light", want: Light, wantOK: true},
		{name: "dark", value: "dark", want: Dark, wantOK: true},
		{name: "absent", value: "", want: Default},
		{name: "capitalised", value: "Dark", want: Default},
		{name: "uppercase", value: "DARK", want: Default},
		{name: "leading space", value: " dark", want: Default},
		{name: "trailing space", value: "dark ", want: Default},
		{name: "unknown word", value: "sepia", want: Default},
		{name: "attribute injection", value: `dark" onload="alert(1)`, want: Default},
		{name: "tag injection", value: "dark><script>", want: Default},
		{name: "oversized", value: strings.Repeat("d", MaxCookieValueBytes+1), want: Default},
		{name: "at the size cap", value: strings.Repeat("d", MaxCookieValueBytes), want: Default},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := Parse(test.value)
			if got != test.want || ok != test.wantOK {
				t.Fatalf("Parse(%q) = (%q, %t), want (%q, %t)", test.value, got, ok, test.want, test.wantOK)
			}
			if !Known(got) {
				t.Fatalf("Parse(%q) returned %q, which is not a catalog member", test.value, got)
			}
		})
	}
}

// TestCatalogIsTheClosedSetOfThemes pins the catalog's own consistency: the
// default is a member, the two explicit reading themes are present, and no
// entry repeats.
func TestCatalogIsTheClosedSetOfThemes(t *testing.T) {
	t.Parallel()
	seen := make(map[Theme]bool, len(Catalog))
	for _, candidate := range Catalog {
		if seen[candidate] {
			t.Errorf("catalog repeats %q", candidate)
		}
		seen[candidate] = true
	}
	for _, required := range []Theme{Default, Light, Dark} {
		if !seen[required] {
			t.Errorf("catalog is missing %q", required)
		}
	}
	if Known("sepia") {
		t.Error(`Known("sepia") = true, want false`)
	}
}

// TestStampWritesTheAttributeAndNothingElse proves the stamp is surgical:
// the served document differs from the build output by exactly the inserted
// attribute, and the input slice is never mutated.
func TestStampWritesTheAttributeAndNothingElse(t *testing.T) {
	t.Parallel()
	for _, candidate := range Catalog {
		t.Run(string(candidate), func(t *testing.T) {
			t.Parallel()
			document := []byte(shell)
			stamped, err := Stamp(document, candidate)
			if err != nil {
				t.Fatalf("Stamp(%q) error = %v", candidate, err)
			}
			attribute := ` ` + Attribute + `="` + string(candidate) + `"`
			if count := bytes.Count(stamped, []byte(Attribute)); count != 1 {
				t.Fatalf("stamped document carries %d theme attributes, want 1", count)
			}
			if !bytes.Contains(stamped, []byte(`<html`+attribute+` lang="en">`)) {
				t.Fatalf("attribute is not on the root element: %s", stamped)
			}
			if restored := bytes.Replace(stamped, []byte(attribute), nil, 1); !bytes.Equal(restored, document) {
				t.Fatalf("stamp changed bytes beyond the attribute:\n got %s\nwant %s", restored, document)
			}
			if string(document) != shell {
				t.Fatalf("Stamp mutated its argument: %s", document)
			}
		})
	}
}

// TestStampFailsClosed sweeps every shape that must stop a rollout rather
// than reach a visitor. Each is a broken bundle, not a request-time state.
func TestStampFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		document string
		theme    Theme
		want     error
	}{
		{name: "theme outside the catalog", document: shell, theme: "sepia", want: ErrUnknownTheme},
		{name: "empty theme", document: shell, theme: "", want: ErrUnknownTheme},
		{name: "no document", document: "", theme: Dark, want: ErrNoRootElement},
		{
			name:     "fragment without a root element",
			document: "<!doctype html><main data-static-fallback>hello</main>",
			theme:    Dark,
			want:     ErrNoRootElement,
		},
		{
			name:     "element that merely starts with the same letters",
			document: "<!doctype html><htmlish>hello</htmlish>",
			theme:    Dark,
			want:     ErrNoRootElement,
		},
		{
			name:     "two root elements",
			document: `<html lang="en"></html><html lang="fr"></html>`,
			theme:    Dark,
			want:     ErrNoRootElement,
		},
		{
			name:     "unterminated root element",
			document: "<!doctype html><html lang=",
			theme:    Dark,
			want:     ErrRootElementUnterminated,
		},
		{
			name:     "already stamped",
			document: `<!doctype html><html ` + Attribute + `="dark" lang="en"></html>`,
			theme:    Light,
			want:     ErrAlreadyStamped,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stamped, err := Stamp([]byte(test.document), test.theme)
			if !errors.Is(err, test.want) {
				t.Fatalf("Stamp error = %v, want %v", err, test.want)
			}
			if stamped != nil {
				t.Fatalf("a failed stamp returned %d bytes, want none", len(stamped))
			}
		})
	}
}

// TestVariantsCoverTheCatalog proves the precompute the server depends on:
// one document per theme, each distinct, each correctly stamped.
func TestVariantsCoverTheCatalog(t *testing.T) {
	t.Parallel()
	variants, err := Variants([]byte(shell))
	if err != nil {
		t.Fatalf("Variants() error = %v", err)
	}
	if len(variants) != len(Catalog) {
		t.Fatalf("Variants() produced %d documents, want %d", len(variants), len(Catalog))
	}
	seen := make(map[string]Theme, len(variants))
	for _, candidate := range Catalog {
		document, present := variants[candidate]
		if !present {
			t.Fatalf("Variants() has no document for %q", candidate)
		}
		if !bytes.Contains(document, []byte(Attribute+`="`+string(candidate)+`"`)) {
			t.Errorf("%q document is not stamped with its own theme: %s", candidate, document)
		}
		if earlier, collides := seen[string(document)]; collides {
			t.Errorf("%q and %q produced identical documents", earlier, candidate)
		}
		seen[string(document)] = candidate
	}
}

// TestVariantsPropagateStampFailure keeps the precompute fail-closed: a
// shell that cannot be stamped yields no partial variant map for a caller
// to serve from.
func TestVariantsPropagateStampFailure(t *testing.T) {
	t.Parallel()
	variants, err := Variants([]byte("<!doctype html><main>no root element</main>"))
	if !errors.Is(err, ErrNoRootElement) {
		t.Fatalf("Variants() error = %v, want %v", err, ErrNoRootElement)
	}
	if variants != nil {
		t.Fatalf("Variants() returned %d documents on failure, want none", len(variants))
	}
}
