// surfaces_gated_test is the EXPLICIT enabled-mode suite: it proves each
// write carve-out does exactly what its gate grants — POST on its one route,
// strict validation, honest storage semantics — and provably nothing else:
// byte-identical security headers and CSP, unchanged method contracts on
// every other route, and gates that never leak into each other. The default-
// build contract suites (surfaces_test.go here, plus the untouched
// TestNoRequestMethodCanEverMutate) stay the authority for gate-off
// behavior; this file exists so the carve-outs are pinned separately instead
// of by edits to those contracts.

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaraj/lidersea.com/internal/media"
	"github.com/snaraj/lidersea.com/internal/surface"
	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// gatedHandler builds the production handler with an explicit configuration.
func gatedHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	siteHandler, err := NewSite(testsupport.FrontendFS(), cfg)
	if err != nil {
		t.Fatalf("NewSite() error = %v", err)
	}
	return siteHandler
}

// postJSON sends one POST with the given body and content type.
func postJSON(t *testing.T, siteHandler http.Handler, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	response := httptest.NewRecorder()
	siteHandler.ServeHTTP(response, request)
	return response
}

// assertBaselineHeaders requires the byte-exact sitewide policy — the CSP
// with form-action 'none' included — on a carve-out response: opening a gate
// must never move a single header byte.
func assertBaselineHeaders(t *testing.T, context string, response *httptest.ResponseRecorder) {
	t.Helper()
	if got := response.Header().Get("Content-Security-Policy"); got != testsupport.SiteContentSecurityPolicy {
		t.Errorf("%s: CSP = %q, want the byte-identical site policy", context, got)
	}
	for header, want := range map[string]string{
		"Strict-Transport-Security": "max-age=31536000",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s: %s = %q, want %q", context, header, got, want)
		}
	}
}

// TestReviewsWriteCarveOut drives the enabled review write path end to end:
// a valid submission is answered honestly with a 503 unavailable envelope
// (no persistence exists yet), reads keep working, the method contract
// admits exactly GET/HEAD/POST, and every response still carries the
// untouched security baseline.
func TestReviewsWriteCarveOut(t *testing.T) {
	t.Parallel()
	siteHandler := gatedHandler(t, Config{ReviewsWriteEnabled: true})

	valid := postJSON(t, siteHandler, surface.Reviews.Route, "application/json",
		`{"author":"Charter owner","rating":5,"text":"Immaculate work."}`)
	if valid.Code != http.StatusServiceUnavailable {
		t.Fatalf("valid submission = %d, want an honest 503", valid.Code)
	}
	assertBaselineHeaders(t, "valid submission", valid)
	if got := valid.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("write response Cache-Control = %q, want no-store", got)
	}
	var env struct {
		Schema string `json:"schema"`
		ID     string `json:"id"`
		Status string `json:"status"`
		Data   struct {
			Reason string `json:"reason"`
		} `json:"data"`
	}
	if err := json.Unmarshal(valid.Body.Bytes(), &env); err != nil {
		t.Fatalf("write response is not an envelope: %v", err)
	}
	if env.Schema != "surface/v1" || env.ID != "reviews" || env.Status != "unavailable" {
		t.Errorf("write envelope = %+v, want an unavailable reviews envelope", env)
	}
	if !strings.Contains(env.Data.Reason, "not configured") {
		t.Errorf("reason = %q, want the honest storage explanation", env.Data.Reason)
	}

	read := httptest.NewRecorder()
	siteHandler.ServeHTTP(read, httptest.NewRequest(http.MethodGet, surface.Reviews.Route, nil))
	if read.Code != http.StatusOK {
		t.Errorf("GET with the gate open = %d, want 200", read.Code)
	}

	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(method, surface.Reviews.Route, nil))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD, POST" {
			t.Errorf("%s = %d Allow=%q, want 405 GET, HEAD, POST", method, response.Code, response.Header().Get("Allow"))
		}
		assertBaselineHeaders(t, method, response)
	}
}

// TestReviewsWriteValidationMatrix drives the strict submission validation
// over HTTP: every malformed body class answers 400/413/415 with a terse
// static message, and no rejection ever echoes request bytes.
func TestReviewsWriteValidationMatrix(t *testing.T) {
	t.Parallel()
	siteHandler := gatedHandler(t, Config{ReviewsWriteEnabled: true})
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "rating zero", contentType: "application/json", body: `{"author":"a","rating":0,"text":"t"}`, wantStatus: http.StatusBadRequest},
		{name: "rating six", contentType: "application/json", body: `{"author":"a","rating":6,"text":"t"}`, wantStatus: http.StatusBadRequest},
		{name: "rating fractional", contentType: "application/json", body: `{"author":"a","rating":4.5,"text":"t"}`, wantStatus: http.StatusBadRequest},
		{name: "rating string", contentType: "application/json", body: `{"author":"a","rating":"5","text":"t"}`, wantStatus: http.StatusBadRequest},
		{name: "rating missing", contentType: "application/json", body: `{"author":"a","text":"t"}`, wantStatus: http.StatusBadRequest},
		{name: "author missing", contentType: "application/json", body: `{"rating":5,"text":"t"}`, wantStatus: http.StatusBadRequest},
		{name: "author too long", contentType: "application/json", body: `{"author":"` + strings.Repeat("a", 121) + `","rating":5,"text":"t"}`, wantStatus: http.StatusBadRequest},
		{name: "text missing", contentType: "application/json", body: `{"author":"a","rating":5}`, wantStatus: http.StatusBadRequest},
		{name: "text too long", contentType: "application/json", body: `{"author":"a","rating":5,"text":"` + strings.Repeat("t", 2001) + `"}`, wantStatus: http.StatusBadRequest},
		{name: "unknown field", contentType: "application/json", body: `{"author":"a","rating":5,"text":"t","admin":true}`, wantStatus: http.StatusBadRequest},
		{name: "trailing value", contentType: "application/json", body: `{"author":"a","rating":5,"text":"t"}{}`, wantStatus: http.StatusBadRequest},
		{name: "not json", contentType: "application/json", body: `rating=5`, wantStatus: http.StatusBadRequest},
		{name: "empty body", contentType: "application/json", body: ``, wantStatus: http.StatusBadRequest},
		{name: "wrong content type", contentType: "text/plain", body: `{"author":"a","rating":5,"text":"t"}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "missing content type", contentType: "", body: `{"author":"a","rating":5,"text":"t"}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "oversized body", contentType: "application/json", body: `{"author":"a","rating":5,"text":"` + strings.Repeat("x", maxReviewRequestBytes) + `"}`, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := postJSON(t, siteHandler, surface.Reviews.Route, test.contentType, test.body)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", response.Code, test.wantStatus, response.Body.String())
			}
			assertBaselineHeaders(t, test.name, response)
			if strings.Contains(response.Body.String(), "admin") || strings.Contains(response.Body.String(), "rating=5") {
				t.Errorf("rejection echoes request bytes: %q", response.Body.String())
			}
		})
	}
}

// TestReviewsGateDoesNotLeak proves the carve-out's scope is exactly one
// route: with only the reviews gate open, the board keeps its sitewide 405,
// the estimates route stays an invisible 404, and the media class stays
// dark.
func TestReviewsGateDoesNotLeak(t *testing.T) {
	t.Parallel()
	siteHandler := gatedHandler(t, Config{ReviewsWriteEnabled: true})
	board := postJSON(t, siteHandler, surface.Board.Route, "application/json", `{}`)
	if board.Code != http.StatusMethodNotAllowed || board.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST board with reviews gate open = %d Allow=%q, want the sitewide 405", board.Code, board.Header().Get("Allow"))
	}
	estimates := postJSON(t, siteHandler, surface.Estimates.Route, "application/json", `{}`)
	if estimates.Code != http.StatusNotFound {
		t.Errorf("estimates with reviews gate open = %d, want 404", estimates.Code)
	}
	mediaProbe := httptest.NewRecorder()
	siteHandler.ServeHTTP(mediaProbe, httptest.NewRequest(http.MethodGet, "/media/immutable/"+strings.Repeat("c", 64)+"/x.mp4", nil))
	if mediaProbe.Code != http.StatusNotFound {
		t.Errorf("media with reviews gate open = %d, want 404", mediaProbe.Code)
	}
}

// TestEstimatesCarveOut drives the enabled preview route: POST computes the
// enveloped estimate with exact integer-cent totals, the method contract is
// POST-only, rejects are strict, and the baseline headers never move.
func TestEstimatesCarveOut(t *testing.T) {
	t.Parallel()
	siteHandler := gatedHandler(t, Config{EstimatesEnabled: true})

	valid := postJSON(t, siteHandler, surface.Estimates.Route, "application/json",
		`{"currency":"USD","taxRateBps":825,"items":[`+
			`{"description":"Hull compound and polish","qty":2,"unitCents":25000,"taxable":true},`+
			`{"description":"Dockage pass-through","qty":1,"unitCents":40000}]}`)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid preview = %d, body %q", valid.Code, valid.Body.String())
	}
	assertBaselineHeaders(t, "valid preview", valid)
	if got := valid.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("preview Cache-Control = %q, want no-store", got)
	}
	var env struct {
		Schema string `json:"schema"`
		ID     string `json:"id"`
		Kind   string `json:"kind"`
		Status string `json:"status"`
		Data   struct {
			SubtotalCents int64  `json:"subtotalCents"`
			TaxCents      int64  `json:"taxCents"`
			TotalCents    int64  `json:"totalCents"`
			Status        string `json:"status"`
			ValidUntil    string `json:"validUntil"`
			Items         []struct {
				AmountCents int64 `json:"amountCents"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(valid.Body.Bytes(), &env); err != nil {
		t.Fatalf("preview response is not an envelope: %v", err)
	}
	if env.Schema != "surface/v1" || env.ID != "estimates" || env.Kind != "estimates/v1" || env.Status != "ok" {
		t.Errorf("preview envelope identity = %+v", env)
	}
	// $500.00 taxable at 8.25% = $41.25 tax; $400.00 non-taxable joins only
	// the subtotal: 90000 + 4125 = 94125.
	if env.Data.SubtotalCents != 90_000 || env.Data.TaxCents != 4_125 || env.Data.TotalCents != 94_125 {
		t.Errorf("totals = %d %d %d, want 90000 4125 94125",
			env.Data.SubtotalCents, env.Data.TaxCents, env.Data.TotalCents)
	}
	if len(env.Data.Items) != 2 || env.Data.Items[0].AmountCents != 50_000 || env.Data.Items[1].AmountCents != 40_000 {
		t.Errorf("echoed lines = %+v, want server-computed amounts 50000 and 40000", env.Data.Items)
	}
	if env.Data.Status != "draft" || env.Data.ValidUntil == "" {
		t.Errorf("preview lifecycle = %q until %q, want a dated draft", env.Data.Status, env.Data.ValidUntil)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(method, surface.Estimates.Route, nil))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "POST" {
			t.Errorf("%s preview = %d Allow=%q, want 405 POST", method, response.Code, response.Header().Get("Allow"))
		}
		assertBaselineHeaders(t, method, response)
	}

	for name, body := range map[string]string{
		"invalid currency": `{"currency":"dollars","taxRateBps":0,"items":[]}`,
		"negative rate":    `{"currency":"USD","taxRateBps":-1,"items":[]}`,
		"unknown field":    `{"currency":"USD","taxRateBps":0,"items":[],"discount":true}`,
		"float unitCents":  `{"currency":"USD","taxRateBps":0,"items":[{"description":"d","qty":1,"unitCents":10.5}]}`,
	} {
		response := postJSON(t, siteHandler, surface.Estimates.Route, "application/json", body)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, response.Code)
		}
	}
	oversized := postJSON(t, siteHandler, surface.Estimates.Route, "application/json",
		`{"currency":"USD","taxRateBps":0,"notes":"`+strings.Repeat("n", maxEstimateRequestBytes)+`","items":[]}`)
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized preview = %d, want 413", oversized.Code)
	}

	// The estimates gate opens nothing else: reviews keeps its read-only
	// default while only this gate is on.
	reviews := postJSON(t, siteHandler, surface.Reviews.Route, "application/json", `{"author":"a","rating":5,"text":"t"}`)
	if reviews.Code != http.StatusMethodNotAllowed || reviews.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST reviews with only estimates open = %d Allow=%q, want the sitewide 405", reviews.Code, reviews.Header().Get("Allow"))
	}
}

// TestEstimateFormatSelection drives the renderer registry through the
// preview route: the canonical JSON default, both registered renderings of
// the same computed money, fail-closed rejection of unknown formats (never a
// fallback), and format validation preceding any body work.
func TestEstimateFormatSelection(t *testing.T) {
	t.Parallel()
	siteHandler := gatedHandler(t, Config{EstimatesEnabled: true})
	body := `{"currency":"USD","taxRateBps":825,"items":[` +
		`{"description":"Hull compound and polish","qty":2,"unitCents":25000,"taxable":true}]}`

	markdown := postJSON(t, siteHandler, surface.Estimates.Route+"?format=markdown", "application/json", body)
	if markdown.Code != http.StatusOK {
		t.Fatalf("markdown preview = %d, body %q", markdown.Code, markdown.Body.String())
	}
	assertBaselineHeaders(t, "markdown rendering", markdown)
	if got := markdown.Header().Get("Content-Type"); got != "text/markdown; charset=utf-8" {
		t.Errorf("markdown Content-Type = %q", got)
	}
	if got := markdown.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("markdown Cache-Control = %q, want no-store", got)
	}
	for _, figure := range []string{"# Estimate", "USD 500.00", "USD 41.25", "USD 541.25"} {
		if !strings.Contains(markdown.Body.String(), figure) {
			t.Errorf("markdown rendering lacks %q", figure)
		}
	}

	htmlDoc := postJSON(t, siteHandler, surface.Estimates.Route+"?format=html", "application/json", body)
	if htmlDoc.Code != http.StatusOK {
		t.Fatalf("html preview = %d", htmlDoc.Code)
	}
	assertBaselineHeaders(t, "html rendering", htmlDoc)
	if got := htmlDoc.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("html Content-Type = %q", got)
	}
	for _, figure := range []string{"<h1>Estimate</h1>", "USD 500.00", "USD 41.25", "USD 541.25"} {
		if !strings.Contains(htmlDoc.Body.String(), figure) {
			t.Errorf("html rendering lacks %q", figure)
		}
	}

	// ?format=json is the explicit spelling of the default envelope.
	asJSON := postJSON(t, siteHandler, surface.Estimates.Route+"?format=json", "application/json", body)
	if asJSON.Code != http.StatusOK || asJSON.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("json format = %d %q, want the canonical envelope", asJSON.Code, asJSON.Header().Get("Content-Type"))
	}
	var env struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(asJSON.Body.Bytes(), &env); err != nil || env.Schema != "surface/v1" {
		t.Errorf("json format did not produce an envelope (schema %q, err %v)", env.Schema, err)
	}

	// Unknown formats fail closed — 400, no fallback rendering — and the
	// format is validated before the body, so even a valid body renders
	// nothing under a bad format and a garbage body changes nothing.
	for _, tail := range []string{"?format=pdf", "?format=Markdown", "?format=docx", "?format=%20"} {
		rejected := postJSON(t, siteHandler, surface.Estimates.Route+tail, "application/json", body)
		if rejected.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", tail, rejected.Code)
		}
	}
	precedence := postJSON(t, siteHandler, surface.Estimates.Route+"?format=pdf", "application/json", "not json at all")
	if precedence.Code != http.StatusBadRequest || !strings.Contains(precedence.Body.String(), "unknown estimate format") {
		t.Errorf("format precedence = %d %q, want the format rejection before any body work", precedence.Code, precedence.Body.String())
	}
}

// TestMediaPipelineWiredThroughNewSite proves the enabled pipeline serves
// through the full production handler — security wrapper, ambiguity guard,
// immutable identity — and that construction fails closed on a bad root.
// The deep Range/conditional/concurrency matrix lives in internal/media.
func TestMediaPipelineWiredThroughNewSite(t *testing.T) {
	t.Parallel()
	fixtures := testsupport.MediaFixtures()
	root := testsupport.WriteMediaRoot(t, fixtures)
	siteHandler := gatedHandler(t, Config{Media: media.Config{Enabled: true, Root: root, MaxConcurrent: 4}})

	video := fixtures[1]
	response := httptest.NewRecorder()
	siteHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, video.URL(), nil))
	if response.Code != http.StatusOK || response.Body.Len() != len(video.Bytes) {
		t.Fatalf("wired media GET = %d with %d bytes, want the full fixture", response.Code, response.Body.Len())
	}
	assertBaselineHeaders(t, "media", response)
	if got := response.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("wired media Cache-Control = %q", got)
	}
	if got := response.Header().Get("ETag"); got != `"`+video.Digest+`"` {
		t.Errorf("wired media ETag = %q, want the quoted digest", got)
	}

	ranged := httptest.NewRequest(http.MethodGet, video.URL(), nil)
	ranged.Header.Set("Range", "bytes=100-199")
	partial := httptest.NewRecorder()
	siteHandler.ServeHTTP(partial, ranged)
	if partial.Code != http.StatusPartialContent || partial.Body.String() != string(video.Bytes[100:200]) {
		t.Errorf("wired media range = %d with %d bytes, want the exact 206 slice", partial.Code, partial.Body.Len())
	}

	// Traversal shapes die in the ambiguity guard before the pipeline runs.
	hostile := httptest.NewRecorder()
	hostileRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	hostileRequest.URL.Path = "/media/immutable/" + video.Digest + "/../" + video.Name
	siteHandler.ServeHTTP(hostile, hostileRequest)
	if hostile.Code != http.StatusNotFound {
		t.Errorf("traversal through the wired pipeline = %d, want 404", hostile.Code)
	}

	if _, err := NewSite(testsupport.FrontendFS(), Config{Media: media.Config{Enabled: true, Root: "/nonexistent/lidersea-media", MaxConcurrent: 2}}); err == nil {
		t.Error("NewSite() accepted a missing media root; construction must fail closed")
	}
}

// TestConfigFromEnvGateTable drives the composed configuration parser: gate
// spellings, media pass-through, and the fail-closed rejection of typos.
func TestConfigFromEnvGateTable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr bool
	}{
		{name: "zero environment is the strict default", env: map[string]string{}, want: Config{}},
		{name: "explicit false everywhere", env: map[string]string{"REVIEWS_WRITE_ENABLED": "false", "ESTIMATES_ENABLED": "false", "MEDIA_ENABLED": "false"}, want: Config{}},
		{name: "reviews gate on", env: map[string]string{"REVIEWS_WRITE_ENABLED": "true"}, want: Config{ReviewsWriteEnabled: true}},
		{name: "estimates gate on", env: map[string]string{"ESTIMATES_ENABLED": "true"}, want: Config{EstimatesEnabled: true}},
		{
			name: "media set passes through",
			env:  map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "8"},
			want: Config{Media: media.Config{Enabled: true, Root: "/srv/media", MaxConcurrent: 8}},
		},
		{name: "reviews typo fails startup", env: map[string]string{"REVIEWS_WRITE_ENABLED": "yes"}, wantErr: true},
		{name: "estimates typo fails startup", env: map[string]string{"ESTIMATES_ENABLED": "1"}, wantErr: true},
		{name: "partial media fails startup", env: map[string]string{"MEDIA_ROOT": "/srv/media"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ConfigFromEnv(func(key string) string { return test.env[key] })
			if (err != nil) != test.wantErr {
				t.Fatalf("ConfigFromEnv error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("ConfigFromEnv = %+v, want %+v", got, test.want)
			}
		})
	}
}
