// types.go collects the package's type declarations and package-level
// const/var blocks so the media-mosaic/v1 data model can be surveyed in one
// place. Pagination and sample construction stay in board.go.

package board

import "time"

// Block kinds for the media-mosaic/v1 payload.
const (
	// KindImage is a photo block backed by the media pipeline.
	KindImage = "image"
	// KindVideo is a video block backed by the media pipeline.
	KindVideo = "video"
	// KindText is a text-only block with no media entry.
	KindText = "text"
)

// pageSize is the fixed number of blocks per board page. The cursor is the
// only pagination input by design: no client-supplied page size means no
// resource-amplification knob on a read endpoint.
const pageSize = 6

// samplePublishedAt is the fixed publication instant of the embedded sample
// board. A fixed instant — rather than time.Now — keeps sample payloads
// byte-identical across requests, replicas, and restarts, which keeps their
// digest ETags stable and 304 revalidation honest. Real content, when the
// platform storage layer lands, will carry its real publication time.
var samplePublishedAt = time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC)

// Data is the media-mosaic/v1 payload: one page of blocks plus the cursor
// that continues the walk.
type Data struct {
	// Blocks is this page of the board, newest first.
	Blocks []Block `json:"blocks"`
	// NextCursor continues pagination when more blocks remain; it is omitted
	// on the final page.
	NextCursor string `json:"nextCursor,omitempty"`
}

// Block is one mosaic tile: an image, a video, or a text card.
type Block struct {
	// ID is the stable block identifier; it doubles as the pagination cursor.
	ID string `json:"id"`
	// Kind is one of the Kind constants.
	Kind string `json:"kind"`
	// Media is present on image and video blocks.
	Media *Media `json:"media,omitempty"`
	// Text is present on text blocks and may caption media blocks.
	Text *Text `json:"text,omitempty"`
	// Tags label the block for future filtering; always present, may be empty.
	Tags []string `json:"tags"`
	// CreatedAt is the block's RFC 3339 UTC creation instant.
	CreatedAt string `json:"createdAt"`
	// Span hints how many mosaic lanes the block may occupy; 0 means 1.
	Span int `json:"span,omitempty"`
}

// Media describes one media asset with everything the UI needs to reserve
// space BEFORE bytes arrive: width, height, and a CSS-ready aspect ratio
// make zero layout shift a property of the data, not a rendering heuristic.
type Media struct {
	// Src is the full-quality asset URL in the digest-immutable class.
	Src string `json:"src"`
	// Poster is the still shown before a video plays; empty for images.
	Poster string `json:"poster,omitempty"`
	// Width and Height are the intrinsic pixel dimensions of Src.
	Width  int `json:"width"`
	Height int `json:"height"`
	// Aspect is "width/height" exactly as CSS aspect-ratio accepts it.
	Aspect string `json:"aspect"`
	// Alt is the accessibility description; required on every media entry.
	Alt string `json:"alt"`
	// Variants are pre-declared responsive renditions (srcset as data), so
	// the client never negotiates or probes for sizes.
	Variants []Variant `json:"variants"`
}

// Variant is one pre-declared rendition of a media asset.
type Variant struct {
	// Src is the rendition's URL in the digest-immutable class.
	Src string `json:"src"`
	// Width is the rendition's pixel width (the srcset "w" value).
	Width int `json:"width"`
	// Type is the rendition's MIME type.
	Type string `json:"type,omitempty"`
}

// Text is the written content of a block.
type Text struct {
	// Title is an optional heading.
	Title string `json:"title,omitempty"`
	// Body is the block's text.
	Body string `json:"body"`
}
