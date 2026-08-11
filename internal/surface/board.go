// board.go implements the media-mosaic/v1 surface: the embedded sample board
// and its cursor pagination. The sample ships first so the UI can build
// against the real contract; real content arrives when the platform storage
// layer lands and a publishing flow writes digest-addressed files under the
// media root (the chart's media volume is documented, deliberately unwired,
// until that storage design is decided).

package surface

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// ErrUnknownCursor reports a pagination cursor that names no block. It is a
// client error: cursors are only ever issued by a previous page.
var ErrUnknownCursor = errors.New("unknown board cursor")

// BoardPage returns one page of the board. An empty cursor starts from the
// newest block; otherwise the page starts after the block the cursor names.
// The page size is fixed server-side (boardPageSize) so pagination has no
// client-tunable cost knob.
func BoardPage(cursor string) (BoardData, error) {
	blocks := sampleBoard()
	start := 0
	if cursor != "" {
		start = -1
		for i, block := range blocks {
			if block.ID == cursor {
				start = i + 1
				break
			}
		}
		if start < 0 {
			return BoardData{}, ErrUnknownCursor
		}
	}

	end := min(start+boardPageSize, len(blocks))
	page := BoardData{Blocks: blocks[start:end]}
	if end < len(blocks) {
		page.NextCursor = blocks[end-1].ID
	}
	return page, nil
}

// sampleDigest derives a placeholder address in the digest-immutable URL
// class from a sample identifier. The digest is honest about being a sample:
// it is the SHA-256 of a named sentinel, not of media bytes, because the
// binary deliberately embeds no media (heavy media never enters git, the
// bundle, or the image). These URLs answer 404 until the platform storage
// layer publishes real digest-addressed content — the UI reserves space from
// width/height/aspect either way, so absence costs no layout shift.
func sampleDigest(id string) string {
	sum := sha256.Sum256([]byte("lidersea-sample:" + id))
	return hex.EncodeToString(sum[:])
}

// sampleMedia assembles one sample media entry with pre-declared responsive
// variants, giving the UI real srcset data to render.
func sampleMedia(id, name, mediaType string, width, height int, alt string, variantWidths ...int) *Media {
	m := &Media{
		Src:    "/media/immutable/" + sampleDigest(id) + "/" + name,
		Width:  width,
		Height: height,
		Aspect: strconv.Itoa(width) + "/" + strconv.Itoa(height),
		Alt:    alt,
	}
	for _, w := range variantWidths {
		variantID := fmt.Sprintf("%s-%d", id, w)
		m.Variants = append(m.Variants, Variant{
			Src:   "/media/immutable/" + sampleDigest(variantID) + "/" + fmt.Sprintf("%d-%s", w, name),
			Width: w,
			Type:  mediaType,
		})
	}
	return m
}

// sampleBoard builds the embedded sample board, newest first. It is a
// function rather than a package-level var so callers always receive a fresh
// value no shared caller can mutate.
func sampleBoard() []Block {
	hull := sampleMedia("hull-restoration", "hull-restoration.avif", "image/avif",
		1600, 1067, "Freshly compounded navy hull at the dock", 640, 1024, 1600)
	walkthrough := sampleMedia("detailing-walkthrough", "detailing-walkthrough.mp4", "video/mp4",
		1920, 1080, "Deck detailing walkthrough, bow to stern", 1280, 1920)
	walkthrough.Poster = "/media/immutable/" + sampleDigest("detailing-walkthrough-poster") + "/detailing-walkthrough-poster.avif"
	teak := sampleMedia("teak-brightwork", "teak-brightwork.avif", "image/avif",
		1600, 2000, "Oiled teak brightwork after refinishing", 640, 1024, 1600)
	helm := sampleMedia("helm-refit", "helm-refit.avif", "image/avif",
		1600, 1067, "Refitted helm station with restored upholstery", 640, 1024, 1600)
	ceramic := sampleMedia("ceramic-coating", "ceramic-coating.mp4", "video/mp4",
		1920, 1080, "Applying ceramic coating along the waterline", 1280, 1920)
	ceramic.Poster = "/media/immutable/" + sampleDigest("ceramic-coating-poster") + "/ceramic-coating-poster.avif"
	interior := sampleMedia("interior-detail", "interior-detail.avif", "image/avif",
		1600, 1200, "Detailed salon interior in natural light", 640, 1024, 1600)
	propeller := sampleMedia("propeller-polish", "propeller-polish.avif", "image/avif",
		1600, 1600, "Mirror-polished propeller before relaunch", 640, 1024, 1600)

	return []Block{
		{
			ID: "hull-restoration", Kind: BlockKindImage, Media: hull,
			Text:      &Text{Title: "Hull restoration", Body: "Oxidation removal, compound, and a full polish."},
			Tags:      []string{"hull", "polish"},
			CreatedAt: "2026-08-09T14:00:00Z",
			Span:      2,
		},
		{
			ID: "detailing-walkthrough", Kind: BlockKindVideo, Media: walkthrough,
			Tags:      []string{"detailing", "walkthrough"},
			CreatedAt: "2026-08-07T10:30:00Z",
		},
		{
			ID: "craft-note", Kind: BlockKindText,
			Text:      &Text{Title: "Why detail matters", Body: "Salt is relentless. A sealed, detailed finish is the difference between weathering a season and wearing it."},
			Tags:      []string{"notes"},
			CreatedAt: "2026-08-05T09:00:00Z",
		},
		{
			ID: "teak-brightwork", Kind: BlockKindImage, Media: teak,
			Text:      &Text{Title: "Teak brightwork", Body: "Stripped, sanded, and oiled to grain."},
			Tags:      []string{"teak", "brightwork"},
			CreatedAt: "2026-08-02T16:45:00Z",
		},
		{
			ID: "helm-refit", Kind: BlockKindImage, Media: helm,
			Tags:      []string{"refit", "interior"},
			CreatedAt: "2026-07-28T12:00:00Z",
		},
		{
			ID: "ceramic-coating", Kind: BlockKindVideo, Media: ceramic,
			Text:      &Text{Title: "Ceramic coating", Body: "Waterline to rail in one continuous pass."},
			Tags:      []string{"coating"},
			CreatedAt: "2026-07-21T11:15:00Z",
		},
		{
			ID: "service-note", Kind: BlockKindText,
			Text:      &Text{Title: "Seasonal programs", Body: "Monthly wash-downs, quarterly details, and haul-out prep on a standing schedule."},
			Tags:      []string{"notes", "programs"},
			CreatedAt: "2026-07-14T08:00:00Z",
		},
		{
			ID: "interior-detail", Kind: BlockKindImage, Media: interior,
			Tags:      []string{"interior", "detailing"},
			CreatedAt: "2026-07-06T15:20:00Z",
		},
		{
			ID: "propeller-polish", Kind: BlockKindImage, Media: propeller,
			Text:      &Text{Title: "Running gear", Body: "Propspeed-ready polish on shafts and props."},
			Tags:      []string{"running-gear"},
			CreatedAt: "2026-06-30T13:05:00Z",
		},
		{
			ID: "mooring-note", Kind: BlockKindText,
			Text:      &Text{Body: "Now booking end-of-season detailing slots."},
			Tags:      []string{},
			CreatedAt: "2026-06-24T09:40:00Z",
		},
	}
}
