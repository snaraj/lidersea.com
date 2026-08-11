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
