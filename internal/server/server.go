// Package server exposes the production HTTP handler for lidersea.com. It
// serves only the embedded frontend and Kubernetes health probes, keeping the
// application stateless and suitable for replicated, pull-based deployments.
package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/snaraj/lidersea.com/internal/media"
	"github.com/snaraj/lidersea.com/internal/ratings"
	"github.com/snaraj/lidersea.com/internal/theme"
)

// New constructs the complete lidersea.com HTTP handler from built frontend
// assets with the default configuration: every write gate off and the media
// pipeline disabled — the strictly read-only origin.
func New(assets fs.FS) (http.Handler, error) {
	return NewSite(assets, Config{})
}

// NewSite constructs the complete lidersea.com HTTP handler for an explicit
// configuration. Construction validates index.html up front and precomputes
// its themed variants, wires Kubernetes probe endpoints, the surface API,
// and (when configured) the media pipeline, and applies the one
// non-configurable security-header policy to every response in every mode.
func NewSite(assets fs.FS, cfg Config) (http.Handler, error) {
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded index: %w", err)
	}
	// One shell per theme, stamped once, here. A shell that cannot carry the
	// theme attribute is a broken bundle: it would serve every visitor an
	// unthemed document, so it fails construction alongside a missing
	// entrypoint rather than degrading silently in front of visitors.
	shells, err := theme.Variants(index)
	if err != nil {
		return nil, fmt.Errorf("stamp themed shells: %w", err)
	}
	// The ratings snapshot is decoded and validated here, once: an
	// owner-edited data file that breaks any rule fails startup rather than
	// putting a half-filled entry in front of a visitor, and no request ever
	// pays to parse it.
	store := cfg.Ratings
	if store == nil {
		snapshot, err := ratings.Snapshot()
		if err != nil {
			return nil, fmt.Errorf("load ratings snapshot: %w", err)
		}
		store = ratings.NewStore(snapshot)
	}
	h := &handler{assets: assets, shells: shells}
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", health)
	mux.HandleFunc("/readyz", health)
	mux.Handle("/api/", &apiHandler{cfg: cfg, ratings: store})
	if cfg.Media.Enabled {
		// Disabled (the default), the media URL class falls through to the
		// static handler's opaque 404s: an absent pipeline is
		// indistinguishable from absent content.
		mediaHandler, err := media.NewHandler(cfg.Media)
		if err != nil {
			return nil, err
		}
		mux.Handle(media.URLPathPrefix, mediaHandler)
	}
	mux.Handle("/", h)
	return securityHeaders(redirectForwardedHTTP(rejectAmbiguousPath(mux))), nil
}

// health provides the shared liveness and readiness response. The service has
// no database or other runtime dependency, so both probes intentionally use the
// same cheap, side-effect-free check.
func health(w http.ResponseWriter, r *http.Request) {
	if !allowReadMethod(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("ok\n"))
	}
}

// ServeHTTP maps a clean URL path to a built frontend file. Unknown paths return
// 404 instead of falling back to index.html because this site has no client-side
// router and silently rewriting mistakes would hide broken asset references.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !allowReadMethod(w, r) {
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		// The shell is the one response that depends on a request cookie, so
		// it is the one response that declares it. Without this, a shared
		// cache could hand one visitor's themed document to another; with it,
		// each themed variant keeps its own digest ETag and its own cache
		// entry. Assets and surfaces read no cookie and declare no variance.
		w.Header().Set("Vary", "Cookie")
		// index.html points at content-addressed assets and must be revalidated on
		// every navigation so a rollout is visible without a stale shell page.
		// "no-cache" keeps that guarantee — a revalidation is still mandatory —
		// while allowing the edge and browser to STORE the shell, so an unchanged
		// site answers a navigation with a small 304 instead of shipping the whole
		// document from the origin again. "no-store" would forbid storage outright
		// and make every navigation a full origin round trip for no safety gain:
		// this document is public, holds no visitor data, and its ETag is a digest.
		serveBytes(w, r, "index.html", h.shell(r), "no-cache")
		return
	}
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	// dist/.gitkeep exists only so a clean checkout can compile before the
	// frontend build. It is build metadata, not public site content.
	if name == ".gitkeep" {
		http.NotFound(w, r)
		return
	}
	info, err := fs.Stat(h.assets, name)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(h.assets, name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	cacheControl := "no-cache"
	if strings.HasPrefix(name, "assets/") {
		// Vite filenames contain a content hash, making a year-long immutable
		// cache safe: changed bytes are always published under a new URL.
		cacheControl = "public, max-age=31536000, immutable"
	}
	serveBytes(w, r, name, data, cacheControl)
}

// shell returns the precomputed document for the theme this request asks
// for. Selection is a lookup and nothing more: the cookie is parsed by the
// theme domain into a closed catalog value, and the bytes were stamped at
// construction, so no visitor byte is ever written into a document and no
// request pays for the transformation. Absent, malformed, oversized, and
// unknown cookie values all resolve to the default theme, which follows the
// visitor's own operating-system preference through the stylesheet.
func (h *handler) shell(r *http.Request) []byte {
	selected := theme.Default
	if cookie, err := r.Cookie(theme.CookieName); err == nil {
		selected, _ = theme.Parse(cookie.Value)
	}
	return h.shells[selected]
}

// allowReadMethod enforces the read-only contract shared by site and probe
// routes. Rejecting mutation methods closes an unnecessary attack surface.
func allowReadMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// rejectAmbiguousPath runs before ServeMux so it returns a terminal 404 instead
// of redirecting traversal or duplicate-separator input to a different route.
// Canonical paths make the edge, Go router, and rooted filesystem agree on the
// exact resource a visitor requested.
func rejectAmbiguousPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Path, "\\\x00") || path.Clean(r.URL.Path) != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveBytes applies cache metadata and delegates byte-range, conditional, and
// HEAD behavior to net/http. Its digest-based strong ETag remains stable across
// replicas and restarts, so every pod presents the same cache identity.
func serveBytes(w http.ResponseWriter, r *http.Request, name string, data []byte, cacheControl string) {
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("ETag", etag)
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// securityHeaders enforces the browser-security baseline at the origin as
// defense in depth if an edge rule is later changed. Six of the seven headers
// it sets were observed byte-identical on a public response; the
// Strict-Transport-Security value was not. HSTS is therefore the one member
// of this baseline whose visitor-facing value is demonstrably not the one
// minted here, and what follows records the OUTCOMES that were measured
// rather than a mechanism this origin cannot see.
//
// Measured 2026-08-22 (issues #95, #96): a public request over the proxied
// path is answered with exactly one Strict-Transport-Security header, reading
// max-age=31536000; includeSubDomains, and carrying no preload directive. The
// edge is the visitor-facing HSTS owner — the promise browsers are actually
// told, and the scope it covers, are settled there and not here. The value
// minted below, max-age=31536000 without includeSubDomains, is not what that
// public response carried. WHY it is not cannot be decided from outside, and
// this comment deliberately picks neither answer: a promise the origin never
// minted, because that leg was not declared TLS, and a promise that did not
// arrive intact are indistinguishable in a public response, and both would
// produce exactly the bytes that were measured.
//
// The origin mints its own regardless, on purpose: it is the promise an
// origin-direct client would receive if the edge were ever bypassed, which is
// the whole reason defense in depth keeps it. Both layers now state the same
// 31536000-second lifetime, so includeSubDomains is the only difference left
// between them. Neither layer closes the first-contact gap — HSTS binds a
// browser only once a secure response has told it (RFC 6797 §14.6), never the
// request that carries the telling — which is why redirectForwardedHTTP below
// is a separate control rather than a restatement of this one.
//
// The header rides only requests the edge declares as TLS — an HSTS pin
// teaches a browser to refuse plain HTTP for a year, so it must never answer
// a leg that demonstrated no such transport, and probe or port-forward
// traffic that never crossed the edge declares nothing and correctly earns
// nothing.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Header.Get(forwardedProtoHeader) == forwardedProtoHTTPS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// redirectForwardedHTTP answers every request the edge declares as plain
// HTTP with a permanent redirect to the identical URL over TLS — origin-side
// defense in depth behind the edge's own HTTPS enforcement, closing the
// window where a plain http:// navigation would otherwise receive content.
// The host comes from the request's Host header (the edge binds it to the
// site hostname) and RequestURI carries the escaped path and query byte for
// byte. Only the exact lowercase declaration bounces (see
// forwardedProtoHTTP); http.Redirect keeps HEAD and POST bodiless and gives
// GET the standard hyperlink stub. Running inside securityHeaders and ahead
// of all routing, the bounce carries the baseline policy — minus the HSTS
// promise the plain leg has not earned — and covers every path, probes and
// opaque 404s included, before any content or method decision is made.
func redirectForwardedHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(forwardedProtoHeader) == forwardedProtoHTTP {
			// 308, not 301: a permanent redirect that preserves the method and
			// body. This origin is not GET/HEAD-only — the gated reviews and
			// estimates carve-outs accept POST — and the bounce runs ahead of
			// routing, so a POST arriving over the plain leg is redirected here;
			// a 301 would rewrite it to GET and silently drop the body, while
			// 308 replays the POST to the TLS URL intact. The edge redirects
			// plain HTTP itself and stays the primary control: a public
			// plain-HTTP request was measured answered 301 (issue #96), which
			// is the edge's code and not this one. This 308 answers only a
			// request that reached the origin still declared plain, so the two
			// codes differing is expected rather than drift.
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}
