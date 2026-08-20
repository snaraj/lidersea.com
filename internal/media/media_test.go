// Package media tests pin the pipeline's whole contract: fail-closed
// configuration parsing, the digest-immutable URL class's strict shape, the
// explicit Range behavior matrix (start/middle/suffix/open/multipart/
// malformed/unsatisfiable), the range-set admission cap and its position
// ahead of both the concurrency slot and the file open, conditional requests
// over the digest ETag, bounded concurrency, and the opaque-404 policy for
// everything unservable.
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

// oneByteRangeSet builds a Range header naming n distinct one-byte ranges —
// the amplification shape, because it is the cheapest request per range a
// client can write.
func oneByteRangeSet(n int) string {
	specs := make([]string, n)
	for i := range specs {
		specs[i] = fmt.Sprintf("%d-%d", i, i)
	}
	return "bytes=" + strings.Join(specs, ",")
}

// refusedByTheCap reports whether THIS package answered 416, as opposed to
// http.ServeContent's own Range refusal. The two are deliberately different
// bodies, so every row below states which layer must have decided — a cap
// that quietly swallowed the delegate's cases would pass a status-only
// assertion while destroying the Range contract.
func refusedByTheCap(response *httptest.ResponseRecorder) bool {
	return strings.TrimSpace(response.Body.String()) == rangeSetTooLargeMessage
}

// TestRangeSetSizeIsCappedAtAdmission is the admission contract for the
// number of ranges one request may name. Sets at or under maxRangeSetSize
// serve exactly as before; sets over it are refused 416 by this package;
// and anything that is not a bytes= set — a foreign unit, a different
// capitalisation, leading whitespace — is not the cap's business at all and
// must still be decided by http.ServeContent, which is what keeps the Range
// algebra in the audited delegate (requirement 9, no fork or vendoring).
//
// The delegate rejects every non-`bytes=` spelling outright, so matching the
// prefix exactly the way it does leaves no set the delegate would expand but
// the cap would not have counted.
func TestRangeSetSizeIsCappedAtAdmission(t *testing.T) {
	t.Parallel()
	video := testsupport.MediaFixtures()[1]
	size := len(video.Bytes)

	tests := []struct {
		name           string
		rangeHeader    string // "" sends no Range header at all
		wantStatus     int
		wantMultipart  bool
		wantCapRefusal bool
		wantParts      []string // Content-Range lines every multipart part must carry
	}{
		{
			name:       "no range header is untouched",
			wantStatus: http.StatusOK,
		},
		{
			name:        "one range is untouched",
			rangeHeader: "bytes=0-9",
			wantStatus:  http.StatusPartialContent,
		},
		{
			name:          "two ranges keep the multipart contract",
			rangeHeader:   "bytes=0-9,100-109",
			wantStatus:    http.StatusPartialContent,
			wantMultipart: true,
			wantParts: []string{
				fmt.Sprintf("Content-Range: bytes 0-9/%d", size),
				fmt.Sprintf("Content-Range: bytes 100-109/%d", size),
			},
		},
		{
			name:          "exactly the cap is served",
			rangeHeader:   "bytes=0-9,100-109,200-209,300-309",
			wantStatus:    http.StatusPartialContent,
			wantMultipart: true,
			wantParts: []string{
				fmt.Sprintf("Content-Range: bytes 0-9/%d", size),
				fmt.Sprintf("Content-Range: bytes 100-109/%d", size),
				fmt.Sprintf("Content-Range: bytes 200-209/%d", size),
				fmt.Sprintf("Content-Range: bytes 300-309/%d", size),
			},
		},
		{
			name:           "one over the cap is refused",
			rangeHeader:    "bytes=0-9,100-109,200-209,300-309,400-409",
			wantStatus:     http.StatusRequestedRangeNotSatisfiable,
			wantCapRefusal: true,
		},
		{
			name:           "far over the cap is refused",
			rangeHeader:    oneByteRangeSet(64),
			wantStatus:     http.StatusRequestedRangeNotSatisfiable,
			wantCapRefusal: true,
		},
		{
			// net/http skips empty members, so this set would otherwise serve
			// as a single range. The cap counts members instead of parsing
			// them, which is deliberately the stricter reading: padding a
			// header with separators is not something a player does, and
			// counting cannot be made to under-count by a spelling trick.
			name:           "separator padding counts toward the cap",
			rangeHeader:    "bytes=0-9,,,,,",
			wantStatus:     http.StatusRequestedRangeNotSatisfiable,
			wantCapRefusal: true,
		},
		{
			name:        "a malformed bytes set under the cap still reaches the delegate",
			rangeHeader: "bytes=abc,def",
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:        "a foreign unit is never counted, however many members",
			rangeHeader: "seconds=" + strings.TrimPrefix(oneByteRangeSet(32), "bytes="),
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:        "a mis-capitalised unit is never counted",
			rangeHeader: "Bytes=" + strings.TrimPrefix(oneByteRangeSet(32), "bytes="),
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:        "a space-prefixed unit is never counted",
			rangeHeader: " " + oneByteRangeSet(32),
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
		},
	}
	// One slot per parallel subtest, for the same reason as the Range matrix:
	// admitted rows hold a slot for their whole response, so a smaller
	// semaphore would shed legitimate rows nondeterministically. Shedding
	// itself is pinned by TestBoundedConcurrencySheds, and the cap's position
	// ahead of the slot by TestRangeSetCapPrecedesSlotAndFileWork.
	h, _ := testHandler(t, len(tests))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var header map[string]string
			if test.rangeHeader != "" {
				header = map[string]string{"Range": test.rangeHeader}
			}
			response := get(t, h, http.MethodGet, video.URL(), header)
			if response.Code != test.wantStatus {
				t.Fatalf("Range %q status = %d, want %d", test.rangeHeader, response.Code, test.wantStatus)
			}
			if got := refusedByTheCap(response); got != test.wantCapRefusal {
				t.Errorf("Range %q refused by the cap = %v, want %v (body %q)",
					test.rangeHeader, got, test.wantCapRefusal, strings.TrimSpace(response.Body.String()))
			}
			if got := strings.HasPrefix(response.Header().Get("Content-Type"), "multipart/byteranges"); got != test.wantMultipart {
				t.Errorf("Range %q multipart = %v, want %v (Content-Type %q)",
					test.rangeHeader, got, test.wantMultipart, response.Header().Get("Content-Type"))
			}
			for _, part := range test.wantParts {
				if !strings.Contains(response.Body.String(), part) {
					t.Errorf("Range %q multipart body lacks %q", test.rangeHeader, part)
				}
			}
			if test.wantCapRefusal {
				// A refusal happens before the asset's identity is looked up,
				// so none of the serving headers may appear: they would prove
				// the file was opened and stat'ed for a request that is never
				// answered with content.
				for _, name := range []string{"ETag", "Cache-Control", "Content-Range"} {
					if got := response.Header().Get(name); got != "" {
						t.Errorf("Range %q refusal carries %s = %q; the refusal precedes the asset", test.rangeHeader, name, got)
					}
				}
			}
		})
	}
}

// TestOversizedRangeSetIsNotAnAmplifier pins the property the cap exists
// for: a refused set answers with fewer bytes than the Range header that
// asked for it, and the refusal's size does not grow with the number of
// ranges named, so no set size turns this origin into an amplifier.
func TestOversizedRangeSetIsNotAnAmplifier(t *testing.T) {
	t.Parallel()
	h, fixtures := testHandler(t, 4)
	video := fixtures[1]

	small := oneByteRangeSet(maxRangeSetSize + 1)
	large := oneByteRangeSet(1024)
	smallResponse := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": small})
	largeResponse := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": large})

	for _, refusal := range []*httptest.ResponseRecorder{smallResponse, largeResponse} {
		if refusal.Code != http.StatusRequestedRangeNotSatisfiable || !refusedByTheCap(refusal) {
			t.Fatalf("oversized set = %d %q, want a 416 refused by the cap",
				refusal.Code, strings.TrimSpace(refusal.Body.String()))
		}
	}
	if smallResponse.Body.Len() != largeResponse.Body.Len() {
		t.Errorf("refusal body grew with the range count: %d bytes for %d ranges, %d for 1024",
			smallResponse.Body.Len(), maxRangeSetSize+1, largeResponse.Body.Len())
	}
	if largeResponse.Body.Len() >= len(large) {
		t.Errorf("refusal wrote %d bytes for a %d-byte Range header; a refusal must never exceed the request",
			largeResponse.Body.Len(), len(large))
	}
}

// TestRangeSetCapPrecedesSlotAndFileWork is the ordering proof. The cap is
// only worth having if it runs BEFORE the two resources a hostile request
// wants to consume — the concurrency slot and the open file — so each is
// checked by making that resource unavailable and requiring the 416 anyway:
// under a full semaphore the refusal must be 416 and not the 503 a request
// reaching the acquire would get, and against an empty media root it must be
// 416 and not the 404 a request reaching the open would get.
func TestRangeSetCapPrecedesSlotAndFileWork(t *testing.T) {
	t.Parallel()
	h, fixtures := testHandler(t, 2)
	video := fixtures[1]
	oversized := map[string]string{"Range": oneByteRangeSet(maxRangeSetSize + 1)}

	h.slots <- struct{}{}
	h.slots <- struct{}{}

	t.Run("refused ahead of the slot acquire", func(t *testing.T) {
		response := get(t, h, http.MethodGet, video.URL(), oversized)
		if response.Code != http.StatusRequestedRangeNotSatisfiable || !refusedByTheCap(response) {
			t.Fatalf("saturated oversized set = %d %q, want the cap's 416 rather than 503",
				response.Code, strings.TrimSpace(response.Body.String()))
		}
		if len(h.slots) != 2 {
			t.Errorf("%d slots held after a refusal; a refused request must consume none", len(h.slots))
		}
	})

	t.Run("shedding is unchanged for admissible requests", func(t *testing.T) {
		response := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": "bytes=0-9"})
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("saturated single range = %d, want 503", response.Code)
		}
		if response.Header().Get("Retry-After") != "1" || response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("saturated headers = Retry-After %q, Cache-Control %q",
				response.Header().Get("Retry-After"), response.Header().Get("Cache-Control"))
		}
	})

	<-h.slots
	<-h.slots

	t.Run("the refusal is not an artefact of saturation", func(t *testing.T) {
		response := get(t, h, http.MethodGet, video.URL(), oversized)
		if response.Code != http.StatusRequestedRangeNotSatisfiable || !refusedByTheCap(response) {
			t.Fatalf("idle oversized set = %d %q, want the cap's 416", response.Code, strings.TrimSpace(response.Body.String()))
		}
		atCap := get(t, h, http.MethodGet, video.URL(), map[string]string{"Range": "bytes=0-9,100-109,200-209,300-309"})
		if atCap.Code != http.StatusPartialContent {
			t.Fatalf("idle at-cap set = %d, want 206", atCap.Code)
		}
		if len(h.slots) != 0 {
			t.Errorf("%d slots still held; the handler leaked a token", len(h.slots))
		}
	})

	t.Run("refused ahead of the file open", func(t *testing.T) {
		empty, err := NewHandler(Config{Enabled: true, Root: t.TempDir(), MaxConcurrent: 2})
		if err != nil {
			t.Fatalf("NewHandler() error = %v", err)
		}
		response := get(t, empty, http.MethodGet, video.URL(), oversized)
		if response.Code != http.StatusRequestedRangeNotSatisfiable || !refusedByTheCap(response) {
			t.Fatalf("oversized set against an empty root = %d %q, want the cap's 416 rather than 404",
				response.Code, strings.TrimSpace(response.Body.String()))
		}
		// Control: the same URL really does reach the open, so the 416 above
		// is the cap's ordering and not an unservable path.
		missing := get(t, empty, http.MethodGet, video.URL(), map[string]string{"Range": "bytes=0-9"})
		if missing.Code != http.StatusNotFound {
			t.Fatalf("single range against an empty root = %d, want 404", missing.Code)
		}
	})
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
