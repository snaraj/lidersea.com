// types.go collects the command's package-level constants so the
// process-lifecycle tuning values can be surveyed in one place. The boot,
// serve, and configuration logic stays in main.go.

package main

import "time"

const (
	// maxRequestHeaderBytes bounds all request metadata far below net/http's
	// 1 MiB default. Every route on this origin answers small GET and HEAD
	// requests, so megabyte header allowances would serve attackers, not
	// visitors.
	maxRequestHeaderBytes = 32 * 1024
	// shutdownTimeout bounds graceful shutdown so a stuck connection cannot
	// hold a rollout open indefinitely. Kubernetes can still terminate the
	// process after this window.
	shutdownTimeout = 10 * time.Second
)
