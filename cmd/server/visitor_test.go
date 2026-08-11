// visitor_test tells the production story over real transport: each scenario
// boots run() exactly the way main does (via bootScenario, composing the same
// helpers the lifecycle e2e suite uses) and drives it through the
// testsupport.Visitor mock-browser harness, so the suite reads as visitor
// scenarios — first visit, repeat visit, hostile probing — rather than
// isolated endpoint checks. The harness asserts the security-header baseline
// on every single navigation. These scenarios ADD user-story framing on top
// of the contract-focused lifecycle tests in main_test.go; they replace
// nothing. Sequential by design, mirroring the existing e2e discipline: every
// scenario owns a live port and ends with process-global SIGTERM delivery.
package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/snaraj/lidersea.com/internal/testsupport"
)

// bootScenario starts run with the exact NotifyContext composition main uses
// — so a later real SIGTERM drives the same drain path production takes — and
// returns the base URL once the readiness poll answers. A missing embedded
// bundle fails fast through waitReady with run's own error, matching the
// doctrine that CI always tests the real artifact.
func bootScenario(t *testing.T) (string, <-chan error) {
	t.Helper()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	t.Cleanup(stop)
	port := reservePort(t)
	runResult := startRun(t, ctx, port)
	base := "http://127.0.0.1:" + port
	waitReady(t, base, runResult)
	return base, runResult
}

// drainScenario is the shared epilogue of every visitor scenario: deliver the
// same SIGTERM Kubernetes sends and require the clean drain main promises. It
// runs outside any subtest so it executes even after a failed chapter.
func drainScenario(t *testing.T, runResult <-chan error) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("deliver SIGTERM: %v", err)
	}
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("run() = %v after SIGTERM, want nil", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not drain within 15s of SIGTERM")
	}
}

// TestVisitorBrowsesTheSite is the ordinary reader's story: a first visit
// downloads the shell fresh and caches its hashed assets forever, a repeat
// visit revalidates everything down to cheap 304s, and a mistyped deep link
// stays an opaque 404 — all with the security baseline asserted by the
// harness on every navigation.
func TestVisitorBrowsesTheSite(t *testing.T) {
	base, runResult := bootScenario(t)
	session := testsupport.NewVisitor(t, base)
	var assets []string

	t.Run("first visit: shell 200 no-cache and hashed assets immutable", func(t *testing.T) {
		visitor := session.On(t)
		shell := visitor.Navigate("/")
		if shell.StatusCode != http.StatusOK {
			t.Fatalf("GET / = %d", shell.StatusCode)
		}
		if got := shell.Header.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("shell Cache-Control = %q, want no-cache", got)
		}
		if got := shell.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Errorf("shell Content-Type = %q", got)
		}
		// Structure, never copy: the static-fallback marker is the document
		// contract; the shell's text will change when the real site ships.
		if !bytes.Contains(shell.Body, []byte("data-static-fallback")) {
			t.Error("served document lacks the static application fallback marker")
		}
		assets = visitor.AssetReferences(shell.Body)
		if len(assets) == 0 {
			t.Fatal("document references no built assets to follow")
		}
		for _, asset := range assets {
			response := visitor.Navigate(asset)
			if response.StatusCode != http.StatusOK || len(response.Body) == 0 {
				t.Fatalf("GET %s = %d, %d bytes", asset, response.StatusCode, len(response.Body))
			}
			if got := response.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
				t.Errorf("%s Cache-Control = %q, want the immutable policy", asset, got)
			}
		}
	})

	t.Run("repeat visit: shell and assets revalidate to 304", func(t *testing.T) {
		visitor := session.On(t)
		if len(assets) == 0 {
			t.Skip("first visit failed; nothing cached to revalidate")
		}
		for _, path := range append([]string{"/"}, assets...) {
			response := visitor.Navigate(path)
			if response.StatusCode != http.StatusNotModified {
				t.Errorf("revisit %s = %d, want 304 from the replayed validator", path, response.StatusCode)
			}
			if len(response.Body) != 0 {
				t.Errorf("revisit %s carried %d body bytes, want an empty 304", path, len(response.Body))
			}
		}
	})

	t.Run("visitor deep-links a missing page: opaque 404, headers intact", func(t *testing.T) {
		missing := session.On(t).Navigate("/services/detailing")
		if missing.StatusCode != http.StatusNotFound {
			t.Fatalf("GET /services/detailing = %d, want 404", missing.StatusCode)
		}
		if got := strings.TrimSpace(string(missing.Body)); got != "404 page not found" {
			t.Errorf("404 body = %q; it must stay the opaque default", got)
		}
	})

	drainScenario(t, runResult)
}

// TestHostileVisitorStaysBlind probes the origin the way an attacker's
// crawler would — traversal, encoded traversal, duplicate separators,
// dotfiles, build placeholders, and development artifacts — and requires each
// answer to be the same opaque 404 with the security baseline intact
// (asserted by the harness on every navigation).
func TestHostileVisitorStaysBlind(t *testing.T) {
	base, runResult := bootScenario(t)
	session := testsupport.NewVisitor(t, base)

	probes := map[string]string{
		"path traversal":         "/assets/../index.html",
		"encoded traversal":      "/assets/%2e%2e/index.html",
		"duplicate separator":    "//etc/passwd",
		"dotfile":                "/.env",
		"build placeholder":      "/.gitkeep",
		"development entrypoint": "/src/main.ts",
		"source map":             "/assets/application.js.map",
	}

	for name, target := range probes {
		t.Run(name, func(t *testing.T) {
			response := session.On(t).Navigate(target)
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s = %d, want an opaque 404", target, response.StatusCode)
			}
			if got := strings.TrimSpace(string(response.Body)); got != "404 page not found" {
				t.Errorf("GET %s body = %q; it must stay the opaque default", target, got)
			}
		})
	}

	drainScenario(t, runResult)
}
