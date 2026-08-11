// types.go holds the package's single package-level declaration: the embedded
// frontend bundle. The accessor logic that exposes it stays in assets.go.

package web

import "embed"

// frontendAssets is populated by the pinned Svelte build before Go compilation.
// Keeping the embed pattern rooted at dist prevents source files and development
// configuration from becoming reachable through the production HTTP server.
//
//go:embed dist/*
var frontendAssets embed.FS
