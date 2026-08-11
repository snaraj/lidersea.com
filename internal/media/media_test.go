// Package media tests pin the pipeline's whole contract: fail-closed
// configuration parsing, the digest-immutable URL class's strict shape, the
// explicit Range behavior matrix (start/middle/suffix/open/multipart/
// malformed/unsatisfiable), conditional requests over the digest ETag,
// bounded concurrency, and the opaque-404 policy for everything unservable.
package media

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// testHandler builds a Handler over a fixture media root.
func testHandler(t *testing.T, maxConcurrent int) (*Handler, []testsupport.MediaFixture) {
	t.Helper()
	fixtures := testsupport.MediaFixtures()
	root := testsupport.WriteMediaRoot(t, fixtures)
	h, err := NewHandler(Config{Enabled: true, Root: root, MaxConcurrent: maxConcurrent})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return h, fixtures
}

// get performs one request against the handler. The target is assigned to
// URL.Path directly — the same discipline as the server fault suite —
// because several hostile targets are deliberately not parseable request
// URLs, and the handler routes on URL.Path alone.
func get(t *testing.T, h *Handler, method, target string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "/", nil)
	request.URL.Path = target
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

// TestConfigFromEnvIsFailClosed drives every configuration shape: the two
// valid disabled spellings, the one valid enabled set, and every partial or
// malformed combination as a startup error.
func TestConfigFromEnvIsFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr bool
	}{
		{name: "absent set disables", env: map[string]string{}, want: Config{}},
		{name: "explicit false disables", env: map[string]string{"MEDIA_ENABLED": "false"}, want: Config{}},
		{
			name: "complete valid set enables",
			env:  map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "8"},
			want: Config{Enabled: true, Root: "/srv/media", MaxConcurrent: 8},
		},
		{name: "root without enabled", env: map[string]string{"MEDIA_ROOT": "/srv/media"}, wantErr: true},
		{name: "concurrency without enabled", env: map[string]string{"MEDIA_MAX_CONCURRENT": "8"}, wantErr: true},
		{name: "false with root", env: map[string]string{"MEDIA_ENABLED": "false", "MEDIA_ROOT": "/srv/media"}, wantErr: true},
		{name: "enabled without root", env: map[string]string{"MEDIA_ENABLED": "true", "MEDIA_MAX_CONCURRENT": "8"}, wantErr: true},
		{name: "enabled without concurrency", env: map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media"}, wantErr: true},
		{name: "enabled alone", env: map[string]string{"MEDIA_ENABLED": "true"}, wantErr: true},
		{name: "boolean typo", env: map[string]string{"MEDIA_ENABLED": "yes"}, wantErr: true},
		{name: "concurrency not a number", env: map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "many"}, wantErr: true},
		{name: "concurrency zero", env: map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "0"}, wantErr: true},
		{name: "concurrency negative", env: map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "-1"}, wantErr: true},
		{name: "concurrency over ceiling", env: map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "257"}, wantErr: true},
		{name: "concurrency at ceiling", env: map[string]string{"MEDIA_ENABLED": "true", "MEDIA_ROOT": "/srv/media", "MEDIA_MAX_CONCURRENT": "256"},
			want: Config{Enabled: true, Root: "/srv/media", MaxConcurrent: 256}},
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

// TestNewHandlerRequiresAnExistingRoot keeps readiness fail-closed: a
// missing media root fails construction before the process can claim health.
func TestNewHandlerRequiresAnExistingRoot(t *testing.T) {
	t.Parallel()
	if _, err := NewHandler(Config{Enabled: true, Root: "/nonexistent/lidersea-media", MaxConcurrent: 2}); err == nil {
		t.Fatal("NewHandler() accepted a missing root")
	}
}

// TestFullResponsesCarryTheImmutableIdentity pins the 200 contract for both
// fixtures: exact bytes, the allowlisted Content-Type, the digest strong
// ETag, the immutable cache class, and advertised range support — plus the
// HEAD twin with identical headers and no body.
func TestFullResponsesCarryTheImmutableIdentity(t *testing.T) {
	t.Parallel()
	h, fixtures := testHandler(t, 4)
	for _, fixture := range fixtures {
		response := get(t, h, http.MethodGet, fixture.URL(), nil)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", fixture.URL(), response.Code)
		}
		if got := response.Body.String(); got != string(fixture.Bytes) {
			t.Errorf("%s: body mismatch (%d bytes, want %d)", fixture.Name, len(got), len(fixture.Bytes))
		}
		if got := response.Header().Get("Content-Type"); got != fixture.ContentType {
			t.Errorf("%s: Content-Type = %q, want %q", fixture.Name, got, fixture.ContentType)
		}
		if got := response.Header().Get("ETag"); got != `"`+fixture.Digest+`"` {
			t.Errorf("%s: ETag = %q, want the quoted digest", fixture.Name, got)
		}
		if got := response.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("%s: Cache-Control = %q", fixture.Name, got)
		}
		if got := response.Header().Get("Accept-Ranges"); got != "bytes" {
			t.Errorf("%s: Accept-Ranges = %q, want bytes", fixture.Name, got)
		}
		if response.Header().Get("Last-Modified") != "" {
			t.Errorf("%s: Last-Modified present; the digest is the only validator", fixture.Name)
		}

		head := get(t, h, http.MethodHead, fixture.URL(), nil)
		if head.Code != http.StatusOK || head.Body.Len() != 0 {
			t.Errorf("HEAD %s = %d with %d body bytes", fixture.Name, head.Code, head.Body.Len())
		}
		for _, name := range []string{"Content-Type", "ETag", "Cache-Control"} {
			if head.Header().Get(name) != response.Header().Get(name) {
				t.Errorf("HEAD %s: %s does not match GET", fixture.Name, name)
			}
		}
	}
}

// TestRangeBehaviorMatrix is the explicit video-seeking contract: every
// class of Range request against the 4096-byte video fixture, with exact
// status, Content-Range, and body-slice assertions.
//
// The handler under test is deliberately sized AFTER the matrix, to
// len(tests): the subtests run in parallel and each in-flight response
// correctly holds one concurrency slot, so a semaphore smaller than the
// matrix would make the handler shed legitimate requests with 503 — correct
// product behavior, nondeterministic test. This matrix exercises Range
// algebra only; admission control under overload has its own deliberate,
// deterministic test (TestBoundedConcurrencySheds), so shedding coverage is
// not lost by admitting every subtest here.
func TestRangeBehaviorMatrix(t *testing.T) {
	t.Parallel()
	video := testsupport.MediaFixtures()[1]
	size := len(video.Bytes)

	tests := []struct {
		name        string
		rangeHeader string
		wantStatus  int
		wantRange   string // expected Content-Range
		wantBody    []byte // nil means assert on status/headers only
	}{
		{
			name:        "start slice",
			rangeHeader: "bytes=0-99",
			wantStatus:  http.StatusPartialContent,
			wantRange:   fmt.Sprintf("bytes 0-99/%d", size),
			wantBody:    video.Bytes[0:100],
		},
		{
			name:        "middle slice",
			rangeHeader: "bytes=1000-1999",
			wantStatus:  http.StatusPartialContent,
			wantRange:   fmt.Sprintf("bytes 1000-1999/%d", size),
			wantBody:    video.Bytes[1000:2000],
		},
		{
			name:        "open-ended tail",
			rangeHeader: fmt.Sprintf("bytes=%d-", size-256),
			wantStatus:  http.StatusPartialContent,
			wantRange:   fmt.Sprintf("bytes %d-%d/%d", size-256, size-1, size),
			wantBody:    video.Bytes[size-256:],
		},
		{
			name:        "suffix length",
			rangeHeader: "bytes=-128",
			wantStatus:  http.StatusPartialContent,
			wantRange:   fmt.Sprintf("bytes %d-%d/%d", size-128, size-1, size),
			wantBody:    video.Bytes[size-128:],
		},
		{
			name:        "final byte",
			rangeHeader: fmt.Sprintf("bytes=%d-%d", size-1, size-1),
			wantStatus:  http.StatusPartialContent,
			wantRange:   fmt.Sprintf("bytes %d-%d/%d", size-1, size-1, size),
			wantBody:    video.Bytes[size-1:],
		},
		{
			name:        "end clamped to size",
			rangeHeader: fmt.Sprintf("bytes=4000-%d", size+5000),
			wantStatus:  http.StatusPartialContent,
			wantRange:   fmt.Sprintf("bytes 4000-%d/%d", size-1, size),
			wantBody:    video.Bytes[4000:],
		},
		{
			// RFC 9110 lets a server ignore or reject an invalid Range;
			// net/http uniformly rejects anything that is not a valid bytes
			// range with 416 and no Content-Range. Pinning the delegate's
			// real choice keeps this matrix an honest contract.
			name:        "malformed range is rejected",
			rangeHeader: "bytes=abc",
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:        "non-bytes unit is rejected",
			rangeHeader: "seconds=0-10",
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:        "unsatisfiable range",
			rangeHeader: fmt.Sprintf("bytes=%d-", size+1),
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
			wantRange:   fmt.Sprintf("bytes */%d", size),
		},
	}
	// One slot per parallel subtest: every request must be admitted, never
	// shed — see the function comment. testsupport fixtures are
	// deterministic, so this handler serves byte-identical content at the
	// same digest URL as the fixture captured above.
	h, _ := testHandler(t, len(tests))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": test.rangeHeader})
			if response.Code != test.wantStatus {
				t.Fatalf("Range %q status = %d, want %d", test.rangeHeader, response.Code, test.wantStatus)
			}
			if got := response.Header().Get("Content-Range"); got != test.wantRange {
				t.Errorf("Range %q Content-Range = %q, want %q", test.rangeHeader, got, test.wantRange)
			}
			if test.wantBody != nil && response.Body.String() != string(test.wantBody) {
				t.Errorf("Range %q returned %d bytes, want the exact %d-byte slice",
					test.rangeHeader, response.Body.Len(), len(test.wantBody))
			}
			if test.wantStatus == http.StatusPartialContent {
				if got := response.Header().Get("Content-Type"); got != video.ContentType {
					t.Errorf("Range %q Content-Type = %q, want %q", test.rangeHeader, got, video.ContentType)
				}
				if got := response.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
					t.Errorf("Range %q lost the immutable cache class: %q", test.rangeHeader, got)
				}
			}
		})
	}
}

// TestMultipartRangeResponse pins the multi-slice form: two ranges answer
// 206 as multipart/byteranges with each part carrying its own Content-Range
// and exact bytes.
func TestMultipartRangeResponse(t *testing.T) {
	t.Parallel()
	h, fixtures := testHandler(t, 4)
	video := fixtures[1]
	response := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": "bytes=0-9,100-109"})
	if response.Code != http.StatusPartialContent {
		t.Fatalf("multipart range status = %d", response.Code)
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "multipart/byteranges") {
		t.Fatalf("multipart Content-Type = %q", got)
	}
	body := response.Body.String()
	for _, part := range []string{
		fmt.Sprintf("Content-Range: bytes 0-9/%d", len(video.Bytes)),
		fmt.Sprintf("Content-Range: bytes 100-109/%d", len(video.Bytes)),
		string(video.Bytes[0:10]),
		string(video.Bytes[100:110]),
	} {
		if !strings.Contains(body, part) {
			t.Errorf("multipart body lacks %q", part)
		}
	}
}

// TestConditionalRequestsUseTheDigest verifies the digest ETag is a working
// validator: If-None-Match revalidates to 304, a matching If-Range keeps the
// 206 slice, and a stale If-Range falls back to the full 200 so a seeking
// player never splices bytes from two different assets.
func TestConditionalRequestsUseTheDigest(t *testing.T) {
	t.Parallel()
	h, fixtures := testHandler(t, 4)
	video := fixtures[1]
	etag := `"` + video.Digest + `"`

	notModified := get(t, h, http.MethodGet, video.URL(), map[string]string{"If-None-Match": etag})
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Errorf("If-None-Match = %d with %d bytes, want empty 304", notModified.Code, notModified.Body.Len())
	}

	matched := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": "bytes=0-9", "If-Range": etag})
	if matched.Code != http.StatusPartialContent {
		t.Errorf("matching If-Range = %d, want 206", matched.Code)
	}

	stale := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": "bytes=0-9", "If-Range": `"` + strings.Repeat("0", 64) + `"`})
	if stale.Code != http.StatusOK || stale.Body.Len() != len(video.Bytes) {
		t.Errorf("stale If-Range = %d with %d bytes, want the full 200", stale.Code, stale.Body.Len())
	}
}

// TestBoundedConcurrencySheds fills every slot and requires the next request
// to be shed with an honest, uncacheable 503 carrying Retry-After — then
// requires full service once slots free.
func TestBoundedConcurrencySheds(t *testing.T) {
	t.Parallel()
	h, fixtures := testHandler(t, 2)
	image := fixtures[0]

	h.slots <- struct{}{}
	h.slots <- struct{}{}
	shed := get(t, h, http.MethodGet, image.URL(), nil)
	if shed.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated status = %d, want 503", shed.Code)
	}
	if shed.Header().Get("Retry-After") != "1" || shed.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("saturated headers = Retry-After %q, Cache-Control %q",
			shed.Header().Get("Retry-After"), shed.Header().Get("Cache-Control"))
	}

	<-h.slots
	<-h.slots
	served := get(t, h, http.MethodGet, image.URL(), nil)
	if served.Code != http.StatusOK {
		t.Errorf("post-drain status = %d, want 200", served.Code)
	}
	if len(h.slots) != 0 {
		t.Errorf("%d slots still held after serving; the handler leaked its token", len(h.slots))
	}
}

// TestMutatingMethodsAreRejected extends the origin's read-only contract to
// the media class: every mutating method answers 405 with the exact Allow
// set and never a success.
func TestMutatingMethodsAreRejected(t *testing.T) {
	t.Parallel()
	h, fixtures := testHandler(t, 4)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		response := get(t, h, method, fixtures[0].URL(), nil)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s = %d Allow=%q, want 405 GET, HEAD", method, response.Code, response.Header().Get("Allow"))
		}
	}
}

// TestUnservablePathsAreOpaque404s drives every rejection class — wrong
// prefix, malformed digests, unsafe or unlisted names, absent content, and
// directories — and requires the identical opaque 404 so probing the media
// root teaches an attacker nothing.
func TestUnservablePathsAreOpaque404s(t *testing.T) {
	t.Parallel()
	fixtures := testsupport.MediaFixtures()
	digest := fixtures[0].Digest
	targets := map[string]string{
		"missing name":         "/media/immutable/" + digest,
		"trailing slash only":  "/media/immutable/" + digest + "/",
		"digest too short":     "/media/immutable/" + digest[:63] + "/file.avif",
		"digest uppercase":     "/media/immutable/" + strings.ToUpper(digest) + "/file.avif",
		"digest non-hex":       "/media/immutable/" + strings.Repeat("z", 64) + "/file.avif",
		"unknown digest":       "/media/immutable/" + strings.Repeat("0", 64) + "/file.avif",
		"wrong name":           "/media/immutable/" + digest + "/other.avif",
		"unlisted extension":   "/media/immutable/" + digest + "/file.exe",
		"no extension":         "/media/immutable/" + digest + "/file",
		"svg is not media":     "/media/immutable/" + digest + "/image.svg",
		"dotfile name":         "/media/immutable/" + digest + "/.hidden.avif",
		"nested path":          "/media/immutable/" + digest + "/a/b.avif",
		"unsafe bytes in name": "/media/immutable/" + digest + "/a b.avif",
		"digest as name":       "/media/immutable/" + digest + "/" + digest,
	}
	// One slot per parallel subtest, for the same reason as the Range
	// matrix: several targets ("unknown digest", "wrong name") are valid URL
	// shapes that correctly reach the slot acquire before their 404, so a
	// semaphore smaller than the table could shed them with 503 instead.
	// Overload behavior itself is pinned by TestBoundedConcurrencySheds.
	h, _ := testHandler(t, len(targets))
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			response := get(t, h, http.MethodGet, target, nil)
			if response.Code != http.StatusNotFound {
				t.Fatalf("GET %s = %d, want 404", target, response.Code)
			}
			if got := strings.TrimSpace(response.Body.String()); got != "404 page not found" {
				t.Errorf("GET %s body = %q; it must stay the opaque default", target, got)
			}
		})
	}
}

// TestDirectoryContentIsNotAFile covers the non-regular-file branch: a
// digest directory containing a directory named like a media file must stay
// an opaque 404, not a traversal or a listing.
func TestDirectoryContentIsNotAFile(t *testing.T) {
	t.Parallel()
	fixtures := testsupport.MediaFixtures()
	root := testsupport.WriteMediaRoot(t, fixtures)
	h, err := NewHandler(Config{Enabled: true, Root: root, MaxConcurrent: 2})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	dirTarget := "/media/immutable/" + fixtures[0].Digest + "/" + fixtures[0].Name
	// Recreate the served path as a directory in a fresh root.
	root2 := t.TempDir()
	h2, err := NewHandler(Config{Enabled: true, Root: root2, MaxConcurrent: 2})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root2, fixtures[0].Digest, fixtures[0].Name), 0o755); err != nil {
		t.Fatalf("build directory fixture: %v", err)
	}
	response := get(t, h2, http.MethodGet, dirTarget, nil)
	if response.Code != http.StatusNotFound {
		t.Errorf("directory-as-file = %d, want 404", response.Code)
	}
	// The healthy handler still serves the real file, proving the 404 above
	// is the directory branch, not a broken fixture.
	healthy := get(t, h, http.MethodGet, dirTarget, nil)
	if healthy.Code != http.StatusOK {
		t.Errorf("healthy root = %d, want 200", healthy.Code)
	}
}
