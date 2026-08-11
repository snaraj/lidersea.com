// types.go collects the package's type declarations so the data model can be
// surveyed in one place. The construction, routing, and serving logic stays in
// server.go.

package server

import "io/fs"

// handler serves the immutable frontend files after New has validated the
// bundle's entrypoint. It remains private so callers cannot bypass the mux's
// health endpoints or the securityHeaders wrapper.
type handler struct {
	// assets is the read-only, build-generated frontend filesystem.
	assets fs.FS
	// index is loaded during construction so a broken image fails before the
	// process becomes ready rather than failing on the first visitor request.
	index []byte
}
