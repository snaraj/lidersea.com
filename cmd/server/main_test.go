package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestListenPort locks the pod's listener contract to the Helm service port and
// ensures malformed environment values fail before the process starts serving.
func TestListenPort(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "default", value: "", want: 8080},
		{name: "explicit", value: "9090", want: 9090},
		{name: "lowest", value: "1", want: 1},
		{name: "highest", value: "65535", want: 65535},
		{name: "not a number", value: "http", wantErr: true},
		{name: "zero", value: "0", wantErr: true},
		{name: "too high", value: "65536", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := listenPort(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("listenPort(%q) error = %v, wantErr %v", test.value, err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("listenPort(%q) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}

// The lifecycle tests below run the real run function against real TCP
// sockets, like the embed test they need the pinned frontend build first.
// They deliberately do not use testing/synctest: a synctest bubble requires
// every goroutine to block on bubble-visible operations, and genuine network
// I/O is not one, so readiness is polled with bounded real-time deadlines
// generous enough for CI.

// fakeEnv returns an environment lookup covering only the given variables.
// Injecting the lookup instead of mutating the process environment with
// t.Setenv keeps every value local to its subtest, which is what allows
// t.Parallel here — t.Setenv and t.Parallel are mutually exclusive.
func fakeEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

// reservePort finds a currently free TCP port and releases it for run to
// claim. The gap between close and bind can race another process, but the
// failure mode is a clear bind error surfaced through run's result — never a
// false pass.
func reservePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split reserved address: %v", err)
	}
	return port
}

// startRun launches run on its own goroutine with a PORT-only environment and
// hands back the one-result channel run's outcome arrives on.
func startRun(t *testing.T, ctx context.Context, port string) <-chan error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, fakeEnv(map[string]string{"PORT": port})) }()
	return errCh
}

// waitReady polls the real listener until /livez answers 200, failing fast
// with run's own error if the process exits first (for example when the
// pinned frontend build has not populated the embedded bundle).
func waitReady(t *testing.T, base string, errCh <-chan error) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("run() exited before becoming ready: %v", err)
		default:
		}
		response, err := client.Get(base + "/livez")
		if err == nil {
			ok := response.StatusCode == http.StatusOK
			response.Body.Close()
			if ok {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("server never became ready")
}

// TestRunServesRealTrafficUntilCancelled is the end-to-end lifecycle: run
// binds a real socket, serves the embedded site with its full security and
// cache identity over the wire, and drains cleanly when its context is
// cancelled — exactly what a pod experiences between scheduling and
// replacement. Sequential: it owns a real port and the shared HTTP client.
func TestRunServesRealTrafficUntilCancelled(t *testing.T) {
	port := reservePort(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errCh := startRun(t, ctx, port)
	base := "http://127.0.0.1:" + port
	waitReady(t, base, errCh)

	response, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if response.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("GET / = %d with %d bytes", response.StatusCode, len(body))
	}
	if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q", got)
	}
	// This fetch is direct — no edge, no X-Forwarded-Proto — exactly how
	// kubelet probes and port-forward validation reach the pod. The HSTS
	// promise must not answer it: an HSTS pin teaches a client to refuse
	// plain HTTP for a year, and an undeclared leg has demonstrated no such
	// transport. TLS-declared traffic is pinned to carry the exact promise
	// in TestRunEnforcesTheForwardedProtoContract.
	if got := response.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("Strict-Transport-Security = %q on a direct fetch, want absent", got)
	}
	if response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("ETag") == "" {
		t.Error("root response is missing its security or cache identity headers")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return after cancellation")
	}
	if response, err := http.Get(base + "/livez"); err == nil {
		response.Body.Close()
		t.Fatal("listener still serving after shutdown")
	}
}

// TestRunDrainsOnTerminationSignal proves the exact composition main uses — a
// NotifyContext feeding run — against a real SIGTERM, the signal Kubernetes
// sends when replacing a pod. os/signal intercepts the signal once
// NotifyContext has registered it, so raising it here cancels only the
// derived context and never kills the test process. Sequential: signal
// registration is process-global.
func TestRunDrainsOnTerminationSignal(t *testing.T) {
	port := reservePort(t)
	ctx, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := startRun(t, ctx, port)
	waitReady(t, "http://127.0.0.1:"+port, errCh)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("raise SIGTERM: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("SIGTERM shutdown returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return after SIGTERM")
	}
}

// forwardedGet performs one request with an explicit X-Forwarded-Proto state
// over real transport and returns the raw response. protoValue "" sends no
// header at all — the direct, never-crossed-the-edge shape.
func forwardedGet(t *testing.T, client *http.Client, method, url, protoValue string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	if protoValue != "" {
		request.Header.Set("X-Forwarded-Proto", protoValue)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	response.Body.Close()
	return response
}

// TestRunEnforcesTheForwardedProtoContract proves the origin's whole
// X-Forwarded-Proto contract over real transport: the exact declaration
// "http" is answered with a permanent redirect to the identical URL over TLS
// (host, escaped path, and query byte for byte; HEAD bodiless like GET), the
// exact declaration "https" earns the exact HSTS promise, and every other
// state — no header, case variants, unknown protos — fails closed to normal
// serving with no redirect and no promise. Wire transport is the point:
// header-NAME canonicalization only exists where a real parser reads real
// bytes, so the mixed-case-name row lives here and not in the unit matrix.
// Sequential: it owns a real port like the other lifecycle suites.
func TestRunEnforcesTheForwardedProtoContract(t *testing.T) {
	port := reservePort(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errCh := startRun(t, ctx, port)
	base := "http://127.0.0.1:" + port
	host := "127.0.0.1:" + port
	waitReady(t, base, errCh)
	// The redirect's https target is terminated at the edge, outside this
	// origin; chasing it would test the dialer, not the site. Surface it.
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Run("plain-http GET bounces to TLS with the URL intact", func(t *testing.T) {
		response := forwardedGet(t, client, http.MethodGet, base+"/services/detailing?boat=42&q=a%20b", "http")
		if response.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("status = %d, want 301", response.StatusCode)
		}
		if got, want := response.Header.Get("Location"), "https://"+host+"/services/detailing?boat=42&q=a%20b"; got != want {
			t.Errorf("Location = %q, want %q", got, want)
		}
		if got := response.Header.Get("Strict-Transport-Security"); got != "" {
			t.Errorf("redirect carries HSTS %q; the plain leg has earned no promise", got)
		}
		// The bounce still carries the security baseline: it is written
		// inside the securityHeaders wrapper.
		if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("redirect X-Content-Type-Options = %q, want nosniff", got)
		}
	})

	t.Run("plain-http HEAD bounces identically with no body", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodHead, base+"/services/detailing?boat=42", nil)
		if err != nil {
			t.Fatalf("build HEAD: %v", err)
		}
		request.Header.Set("X-Forwarded-Proto", "http")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("HEAD: %v", err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatalf("read HEAD body: %v", err)
		}
		if response.StatusCode != http.StatusMovedPermanently || len(body) != 0 {
			t.Fatalf("HEAD = %d with %d body bytes, want a bodiless 301", response.StatusCode, len(body))
		}
		if got, want := response.Header.Get("Location"), "https://"+host+"/services/detailing?boat=42"; got != want {
			t.Errorf("Location = %q, want %q", got, want)
		}
	})

	t.Run("any header-name casing reaches the same policy over the wire", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, base+"/", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		// Assigning the map key directly bypasses the client's Set-side
		// canonicalization, so these exact bytes go on the wire; the server's
		// parser canonicalizes the NAME on read (RFC 9110 field names are
		// case-insensitive). The VALUE stays exact-match by design.
		request.Header["x-fOrWaRdEd-pRoTo"] = []string{"http"}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("GET with mixed-case header name: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusMovedPermanently {
			t.Errorf("status = %d, want 301: header-name case must not defeat the policy", response.StatusCode)
		}
	})

	t.Run("TLS-declared GET serves with the exact promise", func(t *testing.T) {
		response := forwardedGet(t, client, http.MethodGet, base+"/", "https")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.StatusCode)
		}
		if got := response.Header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
			t.Errorf("Strict-Transport-Security = %q, want %q", got, "max-age=31536000")
		}
	})

	t.Run("TLS-declared HEAD carries the same promise", func(t *testing.T) {
		response := forwardedGet(t, client, http.MethodHead, base+"/", "https")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.StatusCode)
		}
		if got := response.Header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
			t.Errorf("Strict-Transport-Security = %q, want %q", got, "max-age=31536000")
		}
	})

	t.Run("undeclared probes and port-forwards serve with no promise", func(t *testing.T) {
		for _, path := range []string{"/readyz", "/livez", "/"} {
			response := forwardedGet(t, client, http.MethodGet, base+path, "")
			if response.StatusCode != http.StatusOK {
				t.Errorf("GET %s = %d, want 200 with no forwarded proto", path, response.StatusCode)
			}
			if got := response.Header.Get("Strict-Transport-Security"); got != "" {
				t.Errorf("GET %s carries HSTS %q on an undeclared leg, want absent", path, got)
			}
		}
	})

	t.Run("case-variant and unknown declarations fail closed", func(t *testing.T) {
		for _, proto := range []string{"HTTPS", "HTTP", "ws"} {
			response := forwardedGet(t, client, http.MethodGet, base+"/", proto)
			if response.StatusCode != http.StatusOK {
				t.Errorf("GET / with proto %q = %d, want 200: only the exact lowercase tokens act", proto, response.StatusCode)
			}
			if got := response.Header.Get("Strict-Transport-Security"); got != "" {
				t.Errorf("proto %q minted HSTS %q; only the exact %q declaration may", proto, got, "https")
			}
		}
	})

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return after cancellation")
	}
}

// TestRunRejectsBadListenerConfiguration locks startup fail-fast: a malformed
// PORT must return an error before any socket is opened or the bundle is
// touched, so Kubernetes sees an immediate crash instead of a half-alive pod.
func TestRunRejectsBadListenerConfiguration(t *testing.T) {
	t.Parallel()
	for name, port := range map[string]string{
		"not a number": "http",
		"zero":         "0",
		"too high":     "65536",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := run(t.Context(), fakeEnv(map[string]string{"PORT": port})); err == nil {
				t.Fatal("run() accepted an invalid PORT")
			}
		})
	}
}

// TestRunSurfacesListenFailure occupies run's port first so ListenAndServe
// must fail, proving the serving goroutine's error — not a hang or a
// swallowed nil — is what run returns when the socket cannot be owned.
func TestRunSurfacesListenFailure(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split occupied address: %v", err)
	}
	if err := run(t.Context(), fakeEnv(map[string]string{"PORT": port})); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("run() error = %v, want address-in-use", err)
	}
}
