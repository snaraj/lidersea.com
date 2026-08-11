// surfaces.go serves the surface catalog under /api/ by COMPOSING the domain
// packages: internal/board, internal/reviews, and internal/estimates (with
// its render subpackage) produce every payload; this file owns only the HTTP
// boundary — routing, method contracts, gates, decoding, and cache identity.
// Routing is explicit: exactly the registry's routes exist, every unknown
// /api/ path is an opaque 404, and the sitewide read-only contract holds
// everywhere except the two documented, individually-gated write carve-outs
// (POST /api/reviews and POST /api/estimates/preview), which are off by
// default and admit POST on their one route only. The security-header
// policy — including the CSP's form-action 'none' — is identical in every
// mode: the UI submits gated writes with fetch(), which default-src 'self'
// already governs, so opening a gate never touches a header.

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/snaraj/lidersea.com/internal/board"
	"github.com/snaraj/lidersea.com/internal/estimates"
	"github.com/snaraj/lidersea.com/internal/estimates/render"
	"github.com/snaraj/lidersea.com/internal/reviews"
	"github.com/snaraj/lidersea.com/internal/surface"
)

// ServeHTTP dispatches to the registry's explicit routes. There is no
// pattern matching and no fallthrough into the static site: /api/ is surface
// territory, and an unregistered path there names nothing.
func (a *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case surface.Board.Route:
		a.serveBoard(w, r)
	case surface.Reviews.Route:
		a.serveReviews(w, r)
	case surface.Estimates.Route:
		a.serveEstimatePreview(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveBoard answers GET /api/board: one cursor-paginated page of the
// media-mosaic/v1 sample board under the surface envelope. The page size is
// fixed in the domain; the cursor is the only client input and an unknown
// one is a client error, because cursors are only ever issued by a prior
// page.
func (a *apiHandler) serveBoard(w http.ResponseWriter, r *http.Request) {
	if !allowReadMethod(w, r) {
		return
	}
	page, err := board.Page(r.URL.Query().Get("cursor"))
	if err != nil {
		http.Error(w, "unknown board cursor", http.StatusBadRequest)
		return
	}
	serveSurfaceJSON(w, r, surface.NewEnvelope(surface.Board, surface.StatusOK, board.PublishedAt(), page))
}

// serveReviews answers /api/reviews. Reads are always available. The write
// path is the documented carve-out: with REVIEWS_WRITE_ENABLED unset (the
// default) this route enforces the sitewide GET/HEAD-only contract
// unchanged; with the gate explicitly on, POST is admitted on this one route
// with strict validation and honest storage-unavailable semantics.
func (a *apiHandler) serveReviews(w http.ResponseWriter, r *http.Request) {
	if a.cfg.ReviewsWriteEnabled {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead, http.MethodPost) {
			return
		}
		if r.Method == http.MethodPost {
			a.submitReview(w, r)
			return
		}
	} else if !allowReadMethod(w, r) {
		return
	}
	env := surface.NewEnvelope(surface.Reviews, surface.StatusOK, reviews.PublishedAt(), reviews.Snapshot())
	serveSurfaceJSON(w, r, env)
}

// submitReview validates a gated review submission and answers with the
// truth: the contract is live but no persistence exists until the platform
// storage layer lands, so a valid submission receives 503 with an
// unavailable envelope instead of a fabricated acceptance.
func (a *apiHandler) submitReview(w http.ResponseWriter, r *http.Request) {
	var submission reviews.Submission
	if !decodeJSONBody(w, r, maxReviewRequestBytes, &submission) {
		return
	}
	if err := reviews.ValidateSubmission(submission); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	env := surface.NewEnvelope(surface.Reviews, surface.StatusUnavailable, time.Now(),
		reviewWriteUnavailable{Reason: reviewStorageUnavailableReason})
	writeSurfaceJSON(w, http.StatusServiceUnavailable, env)
}

// serveEstimatePreview answers POST /api/estimates/preview when
// ESTIMATES_ENABLED is explicitly on. Off (the default), the route does not
// exist: an opaque 404 for every method, indistinguishable from any unknown
// /api/ path, so the disabled surface is invisible rather than discoverable.
//
// ?format= selects the response document: the canonical enveloped JSON by
// default, or a registered rendering (markdown, html) of the same computed
// estimate. Unknown formats fail closed with 400 — never a silent fallback —
// and the format is validated BEFORE the body is read, so a bad parameter
// costs nothing.
func (a *apiHandler) serveEstimatePreview(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.EstimatesEnabled {
		http.NotFound(w, r)
		return
	}
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = render.FormatJSON
	}
	var renderer render.Renderer
	if format != render.FormatJSON {
		var known bool
		if renderer, known = render.For(format); !known {
			http.Error(w, "unknown estimate format", http.StatusBadRequest)
			return
		}
	}
	var req estimates.Request
	if !decodeJSONBody(w, r, maxEstimateRequestBytes, &req) {
		return
	}
	now := time.Now()
	estimate, err := estimates.Compute(req, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if renderer == nil {
		writeSurfaceJSON(w, http.StatusOK, surface.NewEnvelope(surface.Estimates, surface.StatusOK, now, estimate))
		return
	}
	document, err := renderer.Render(estimate)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", renderer.ContentType())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}

// allowMethods is the carve-out companion to allowReadMethod: the identical
// rejection shape (405, Allow header, opaque body) for the two gated routes
// whose allowed set differs from the sitewide read-only default. It never
// replaces allowReadMethod anywhere else.
func allowMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// serveSurfaceJSON serves a read envelope with the same cache identity
// discipline as serveBytes: a digest strong ETag over the exact payload
// bytes and the no-cache revalidation class, delegating conditional and HEAD
// behavior to net/http. Sample-backed envelopes carry their domain's fixed
// publication instant, so their bytes — and therefore their ETags — are
// stable and 304 revalidation works end to end.
func serveSurfaceJSON(w http.ResponseWriter, r *http.Request, env surface.Envelope) {
	payload, err := json.Marshal(env)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(payload)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(payload))
}

// writeSurfaceJSON writes a computed (write-path) envelope. These responses
// are never cacheable: they answer a specific submission, not a resource.
func writeSurfaceJSON(w http.ResponseWriter, status int, env surface.Envelope) {
	payload, err := json.Marshal(env)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// decodeJSONBody enforces the write-path request discipline shared by both
// gated routes: a declared application/json content type, a hard byte cap, no
// unknown fields, and exactly one JSON value. Failures answer with terse
// static messages that never echo request bytes.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	if decoder.More() {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}
