// Package board tests pin the media-mosaic/v1 domain: block
// well-formedness, the zero-CLS media metadata, the digest-immutable URL
// class of every sample address, and the cursor walk's completeness.
package board

import (
	"errors"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// immutableMediaURL is the digest-immutable URL class asserted independently
// of the media package, so board data and pipeline stay in agreement without
// either importing the other's constant.
var immutableMediaURL = regexp.MustCompile(`^/media/immutable/[0-9a-f]{64}/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// TestPaginationWalksEveryBlockExactlyOnce follows cursors from the first
// page to exhaustion and requires full, duplicate-free, order-preserving
// coverage with the fixed page size on every non-final page.
func TestPaginationWalksEveryBlockExactlyOnce(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	var order []string
	cursor := ""
	pages := 0
	for {
		page, err := Page(cursor)
		if err != nil {
			t.Fatalf("Page(%q) error = %v", cursor, err)
		}
		pages++
		if pages > 10 {
			t.Fatal("cursor walk did not terminate")
		}
		if page.NextCursor != "" && len(page.Blocks) != pageSize {
			t.Errorf("non-final page has %d blocks, want %d", len(page.Blocks), pageSize)
		}
		for _, block := range page.Blocks {
			if seen[block.ID] {
				t.Errorf("block %q served twice", block.ID)
			}
			seen[block.ID] = true
			order = append(order, block.ID)
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor != page.Blocks[len(page.Blocks)-1].ID {
			t.Errorf("nextCursor = %q, want the page's final block id", page.NextCursor)
		}
		cursor = page.NextCursor
	}
	if pages < 2 {
		t.Errorf("sample board paginates in %d page(s); need at least 2 to prove the cursor", pages)
	}
	if len(order) != len(sampleBoard()) {
		t.Errorf("walk visited %d blocks, want %d", len(order), len(sampleBoard()))
	}
	for i, block := range sampleBoard() {
		if order[i] != block.ID {
			t.Fatalf("walk order[%d] = %q, want %q", i, order[i], block.ID)
		}
	}
}

// TestCursorEdges covers the cursor's failure and boundary behavior: an
// unknown cursor is a client error, and the final block's cursor yields an
// empty terminal page rather than an error.
func TestCursorEdges(t *testing.T) {
	t.Parallel()
	if _, err := Page("no-such-block"); !errors.Is(err, ErrUnknownCursor) {
		t.Errorf("Page(unknown) error = %v, want ErrUnknownCursor", err)
	}
	blocks := sampleBoard()
	last, err := Page(blocks[len(blocks)-1].ID)
	if err != nil {
		t.Fatalf("Page(final id) error = %v", err)
	}
	if len(last.Blocks) != 0 || last.NextCursor != "" {
		t.Errorf("page after the final block = %+v, want empty and terminal", last)
	}
}

// TestPublishedAtIsFixedUTC pins the sample-data property the cache identity
// depends on: a constant UTC instant, so sample payloads marshal to
// identical bytes on every request, replica, and restart.
func TestPublishedAtIsFixedUTC(t *testing.T) {
	t.Parallel()
	first, second := PublishedAt(), PublishedAt()
	if !first.Equal(second) || first.Location() != time.UTC || first.IsZero() {
		t.Errorf("PublishedAt = %v then %v, want one fixed UTC instant", first, second)
	}
}

// TestBlocksAreWellFormed requires every sample block to satisfy the
// media-mosaic/v1 contract a consumer would reserve layout from: valid
// kinds, media
// exactly on media kinds, intrinsic dimensions with a CSS-ready aspect,
// accessibility text, declared variants, posters on video, parseable
// timestamps, and non-nil tags.
func TestBlocksAreWellFormed(t *testing.T) {
	t.Parallel()
	kinds := map[string]int{}
	for _, block := range sampleBoard() {
		kinds[block.Kind]++
		if block.ID == "" {
			t.Fatal("block with empty id")
		}
		if block.Tags == nil {
			t.Errorf("%s: tags must be present (may be empty), got nil", block.ID)
		}
		if _, err := time.Parse(time.RFC3339, block.CreatedAt); err != nil {
			t.Errorf("%s: createdAt %q is not RFC 3339", block.ID, block.CreatedAt)
		}

		switch block.Kind {
		case KindImage, KindVideo:
			m := block.Media
			if m == nil {
				t.Errorf("%s: %s block without media", block.ID, block.Kind)
				continue
			}
			if m.Width <= 0 || m.Height <= 0 {
				t.Errorf("%s: dimensions %dx%d must be positive for space reservation", block.ID, m.Width, m.Height)
			}
			if wantAspect := strconv.Itoa(m.Width) + "/" + strconv.Itoa(m.Height); m.Aspect != wantAspect {
				t.Errorf("%s: aspect = %q, want %q (CSS aspect-ratio form)", block.ID, m.Aspect, wantAspect)
			}
			if m.Alt == "" {
				t.Errorf("%s: media without alt text", block.ID)
			}
			if !immutableMediaURL.MatchString(m.Src) {
				t.Errorf("%s: src %q is outside the digest-immutable URL class", block.ID, m.Src)
			}
			if len(m.Variants) == 0 {
				t.Errorf("%s: media without pre-declared variants", block.ID)
			}
			for _, v := range m.Variants {
				if !immutableMediaURL.MatchString(v.Src) || v.Width <= 0 || v.Type == "" {
					t.Errorf("%s: malformed variant %+v", block.ID, v)
				}
			}
			if block.Kind == KindVideo {
				if m.Poster == "" || !immutableMediaURL.MatchString(m.Poster) {
					t.Errorf("%s: video poster %q missing or outside the URL class", block.ID, m.Poster)
				}
			} else if m.Poster != "" {
				t.Errorf("%s: image block carries a poster", block.ID)
			}
		case KindText:
			if block.Media != nil {
				t.Errorf("%s: text block carries media", block.ID)
			}
			if block.Text == nil || block.Text.Body == "" {
				t.Errorf("%s: text block without body", block.ID)
			}
		default:
			t.Errorf("%s: unknown kind %q", block.ID, block.Kind)
		}
	}
	for _, kind := range []string{KindImage, KindVideo, KindText} {
		if kinds[kind] == 0 {
			t.Errorf("sample board demonstrates no %q block", kind)
		}
	}
}
