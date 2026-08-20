// Package media is lidersea.com's media pipeline: it serves the
// digest-immutable URL class /media/immutable/<sha256>/<name> from an
// env-gated directory with explicit HTTP Range support (video seeking),
// correct media content types, immutable cache headers, and bounded
// concurrency.
//
// The pipeline does zero request-path content work: the URL's digest IS the
// asset's identity (its ETag) and the publishing flow — not the server —
// guarantees that a file under Root/<sha256>/ has that digest. Verifying
// gigabytes of video per request would trade the performance requirement for
// a property the publisher already provides.
//
// Range algebra (206 slicing, Content-Range, multipart/byteranges, 416,
// If-Range) is delegated to net/http's audited http.ServeContent — the same
// decision the asset path made ("net/http's bounded reader, not a second ad
// hoc implementation") — while this handler owns what net/http cannot know:
// the digest identity, the immutable cache class, the media type allowlist,
// the concurrency bound, and how many ranges one request may name.
//
// That last one is an admission cap (maxRangeSetSize), refused with 416
// BEFORE a concurrency slot or a file descriptor is taken: multipart
// answers emit per-part framing for every range named, so an oversized set
// is amplification the delegate has no way to decline. The cap counts set
// members and nothing else — which bytes a range covers, whether it
// overlaps, and whether it is satisfiable all stay http.ServeContent's, so
// nothing this package does can widen what is served. The Range matrix is
// pinned by explicit tests.
package media

import (
	"errors"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// ConfigFromEnv parses the MEDIA_* environment fail-closed: the pipeline is
// enabled only by the complete, valid variable set, and every partial or
// malformed set is a startup error rather than a silently half-configured
// server. Absence of all three variables is the one valid "disabled" state
// (MEDIA_ENABLED=false alone is accepted as its explicit spelling).
func ConfigFromEnv(lookup func(string) string) (Config, error) {
	enabled := lookup("MEDIA_ENABLED")
	root := lookup("MEDIA_ROOT")
	maxConcurrent := lookup("MEDIA_MAX_CONCURRENT")

	switch enabled {
	case "", "false":
		if root != "" || maxConcurrent != "" {
			return Config{}, errors.New("media configuration is all-or-nothing: MEDIA_ROOT and MEDIA_MAX_CONCURRENT require MEDIA_ENABLED=true")
		}
		return Config{}, nil
	case "true":
		if root == "" || maxConcurrent == "" {
			return Config{}, errors.New("MEDIA_ENABLED=true requires both MEDIA_ROOT and MEDIA_MAX_CONCURRENT")
		}
		n, err := strconv.Atoi(maxConcurrent)
		if err != nil || n < 1 || n > maxConcurrentCeiling {
			return Config{}, errors.New("MEDIA_MAX_CONCURRENT must be an integer between 1 and " + strconv.Itoa(maxConcurrentCeiling))
		}
		return Config{Enabled: true, Root: root, MaxConcurrent: n}, nil
	default:
		return Config{}, errors.New(`MEDIA_ENABLED must be "true" or "false"`)
	}
}

// NewHandler opens the media root and prepares the concurrency bound. A
// missing or unopenable root is a construction error — the process fails
// before readiness rather than 404ing every asset while claiming health.
func NewHandler(cfg Config) (*Handler, error) {
	root, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return nil, errors.New("media root is not an openable directory: MEDIA_ROOT must exist before the server starts")
	}
	return &Handler{root: root, slots: make(chan struct{}, cfg.MaxConcurrent)}, nil
}

// ServeHTTP serves one digest-immutable asset. Every rejection — malformed
// digest, unlisted extension, absent file, non-file — is the same opaque 404
// so probes learn nothing about the media root's contents.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The read-only method contract matches the origin's sitewide guard: the
	// media class is immutable by definition, so nothing but GET and HEAD can
	// ever be meaningful here.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	digest, name, ok := parsePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Range-set admission, ahead of every slot and every file descriptor: a
	// request that names more ranges than any player ever seeks is refused
	// here, so amplification costs the origin one short 416 rather than a
	// concurrency slot held for a multipart write. Ordering is the whole
	// point — a cap after the acquire would still let a hostile client
	// occupy the semaphore — and it is pinned by its own test.
	if rangeSetTooLarge(r.Header.Get("Range")) {
		http.Error(w, rangeSetTooLargeMessage, http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// Bounded concurrency: acquire a slot for the whole response or say so
	// honestly. A saturated origin answering 503 with Retry-After keeps video
	// players backing off instead of piling onto small hardware.
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	file, err := h.root.Open(digest + "/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}

	// The digest is the immutable identity: it is the strong ETag (free — no
	// request-path hashing), and it licenses the year-long immutable cache
	// class because changed content always publishes under a new digest.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set("Content-Type", contentTypes[path.Ext(name)])
	// A zero modtime suppresses Last-Modified: file copy times differ across
	// replicas and say nothing about content identity — the digest ETag is
	// the only validator, so If-Range and If-None-Match stay deterministic.
	http.ServeContent(w, r, name, time.Time{}, file)
}

// parsePath validates /media/immutable/<sha256>/<name> strictly: a 64-char
// lowercase hex digest, then exactly one clean name segment bearing an
// allowlisted media extension. Anything else is unservable by construction —
// the rooted open confines reads anyway (defense in depth), but requests
// that are not the URL class simply do not name a resource.
func parsePath(requestPath string) (digest, name string, ok bool) {
	rest, found := strings.CutPrefix(requestPath, URLPathPrefix)
	if !found {
		return "", "", false
	}
	digest, name, found = strings.Cut(rest, "/")
	if !found || !validDigest(digest) || !validName(name) {
		return "", "", false
	}
	if _, listed := contentTypes[path.Ext(name)]; !listed {
		return "", "", false
	}
	return digest, name, true
}

// validDigest accepts exactly 64 lowercase hex characters.
func validDigest(digest string) bool {
	if len(digest) != digestHexLen {
		return false
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// rangeSetTooLarge reports whether a Range header names more members than
// maxRangeSetSize. It counts comma-separated members of a bytes= set and
// judges nothing else: an absent header, a non-bytes unit, or any other
// spelling returns false and reaches http.ServeContent exactly as before,
// which keeps every Range decision except set size in the delegate. Counting
// is deliberately cheaper than parsing — the cap only ever refuses more than
// stdlib would, never fewer, so an over-count cannot widen what is served.
func rangeSetTooLarge(header string) bool {
	set, isBytes := strings.CutPrefix(header, bytesRangePrefix)
	if !isBytes {
		return false
	}
	return strings.Count(set, ",")+1 > maxRangeSetSize
}

// validName accepts one path segment of safe filename bytes that does not
// start with a dot: no separators, no traversal, no hidden files.
func validName(name string) bool {
	if name == "" || name[0] == '.' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}
