// Command server runs the single lidersea.com application artifact. It joins
// the embedded Svelte frontend with the Go HTTP handler and shuts down cleanly
// when Kubernetes replaces or terminates a pod.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/snaraj/lidersea.com/internal/server"
	website "github.com/snaraj/lidersea.com/internal/web"
)

// main owns process termination and the operating-system signal contract:
// Kubernetes sends SIGTERM before a pod's grace period expires, and deriving
// the lifecycle context from both SIGTERM and local interrupts here gives
// every environment the same orderly shutdown path through run.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// run assembles the immutable site, starts its hardened HTTP server, and
// blocks until the server fails or ctx is cancelled, then drains gracefully.
// The context and the environment lookup are parameters rather than process
// globals so tests can drive the complete lifecycle — configuration, serving,
// and shutdown — deterministically, and in parallel where no real signal or
// socket forbids it.
func run(ctx context.Context, lookupEnv func(string) string) error {
	port, err := listenPort(lookupEnv("PORT"))
	if err != nil {
		return err
	}
	// Surface and media configuration parses fail-closed before any socket
	// opens: the zero-value default is the strictly read-only origin, and a
	// malformed or partial gate crashes the pod here instead of serving with
	// guessed intent.
	cfg, err := server.ConfigFromEnv(lookupEnv)
	if err != nil {
		return err
	}

	assets, err := website.FileSystem()
	if err != nil {
		return err
	}
	handler, err := server.NewSite(assets, cfg)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		// Explicit limits protect the Pi-hosted origin from slow or oversized
		// requests while leaving enough time for normal traffic through the tunnel.
		Addr:              ":" + strconv.Itoa(port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxRequestHeaderBytes,
	}

	// A one-result buffer lets the serving goroutine report an early failure even
	// when context cancellation wins the select and shutdown begins first.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("lidersea.com listening", "port", port)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case serveErr := <-errCh:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// listenPort validates the only runtime listener setting. The stable 8080
// default matches the Helm chart, while strict bounds fail bad pod configuration
// before Kubernetes can route traffic to the process.
func listenPort(value string) (int, error) {
	if value == "" {
		return 8080, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("PORT must be an integer between 1 and 65535")
	}
	return port, nil
}
