// types.go collects the package's type declarations and package-level
// const/var blocks so the media pipeline's data model can be surveyed in one
// place. Configuration parsing and the serving logic stay in media.go.

package media

import "os"

// URLPathPrefix is the digest-immutable URL class this pipeline serves:
// /media/immutable/<sha256-hex>/<name>. The digest names the content, so a
// changed file is always published under a new URL and a year-long immutable
// cache lifetime is safe by construction.
const URLPathPrefix = "/media/immutable/"

// digestHexLen is the length of a lowercase hex SHA-256 digest.
const digestHexLen = 64

// maxConcurrentCeiling bounds MEDIA_MAX_CONCURRENT. The origin is small
// single-board hardware; hundreds of concurrent media streams is a
// misconfiguration, not a capacity plan.
const maxConcurrentCeiling = 256

// bytesRangePrefix is the only range unit net/http honours. The admission
// cap matches it exactly the way http.ServeContent's own parser does, so the
// cap and the delegate can never disagree about what is a byte-range set.
const bytesRangePrefix = "bytes="

// maxRangeSetSize caps how many ranges one request may name, refused at
// admission before a concurrency slot or a file descriptor is taken. A
// player seeking video asks for one range; the multipart contract test asks
// for two; nothing legitimate asks for more, so four is headroom rather than
// a limit real traffic meets.
//
// The cap exists because multipart/byteranges answers EVERY named range with
// its own boundary line, Content-Type, and Content-Range — about 129 bytes
// of generated framing for the handful of bytes that name the range — so the
// response grows with the range count while the request barely does.
// Measured against this package's own delegate over the 4 KiB video fixture:
// 1024 one-byte ranges answer an 8,025-byte Range header with 131,990
// response bytes (16x), and every one of those bytes is written while
// holding a concurrency slot on small single-board hardware. Capping the SET
// SIZE removes the multiplier and leaves Range algebra entirely to net/http.
const maxRangeSetSize = 4

// rangeSetTooLargeMessage is the 416 body for a refused oversized set. It is
// deliberately distinct from net/http's own Range errors so the responsible
// layer is legible in a response — and assertable in a test — without
// pinning the delegate's wording.
const rangeSetTooLargeMessage = "range set too large"

// contentTypes is the fail-closed extension allowlist. It exists because the
// production container is distroless: there is no /etc/mime.types, and Go's
// built-in table lacks the video types, so mime.TypeByExtension would serve
// video with no Content-Type. Only these extensions are served at all —
// an unknown extension is an opaque 404, never an octet-stream guess.
// SVG is deliberately absent: it is a scripting-capable document format, not
// a photograph, and does not belong in the media pipeline.
var contentTypes = map[string]string{
	".avif": "image/avif",
	".webp": "image/webp",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
	".mp4":  "video/mp4",
	".webm": "video/webm",
	".vtt":  "text/vtt; charset=utf-8",
}

// Config is the media pipeline's runtime configuration, parsed fail-closed
// by ConfigFromEnv. The zero value is the production default: disabled.
// Enabling the pipeline is an explicit operator action that adds a read-only
// serving capability; no security control is ever disabled by any setting.
type Config struct {
	// Enabled reports whether the pipeline serves at all.
	Enabled bool
	// Root is the directory holding digest-addressed content:
	// Root/<sha256>/<name>. Today this is a development path; in production
	// it will be the platform storage layer's volume once that design lands
	// (the chart deliberately mounts nothing yet).
	Root string
	// MaxConcurrent bounds simultaneous media responses.
	MaxConcurrent int
}

// Handler serves the digest-immutable URL class from a rooted filesystem
// with bounded concurrency.
type Handler struct {
	// root confines every open to the media root. os.Root is kernel-enforced
	// containment: symlinks and traversal cannot escape it, which is a
	// stronger guarantee than any path string validation alone.
	root *os.Root
	// slots is the concurrency semaphore; one token per in-flight response.
	slots chan struct{}
}
