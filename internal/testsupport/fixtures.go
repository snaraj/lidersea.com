// fixtures.go builds the canonical fixture: the healthy in-memory frontend
// bundle every suite constructs handlers from.

package testsupport

import "testing/fstest"

// FrontendShellSentinel is the fixture-only text inside the canonical
// index.html. Suites assert this sentinel — never real site copy — so the
// temporary placeholder shell can grow into the real site without breaking a
// single handler-behavior test.
const FrontendShellSentinel = "lidersea-fixture-shell"

// FrontendFS returns the canonical healthy frontend bundle every suite builds
// handlers from:
//
//	index.html            the entrypoint: a complete document with the single
//	                      <html> root element the origin stamps a theme onto,
//	                      carrying the data-static-fallback structural marker
//	                      and the FrontendShellSentinel text
//	assets/app-abc123.js  one content-hashed asset (immutable cache class)
//	.gitkeep              the checkout placeholder that must never be served
//
// The root element carries no theme attribute of its own: the origin stamps
// one per themed variant, and a pre-stamped fixture would hide that stamp
// from every suite that builds a handler from this bundle.
//
// A fresh map is returned on every call, so a test may mutate its copy
// freely without affecting any other test.
func FrontendFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte(`<!doctype html><html lang="en"><body><main data-static-fallback><h1>` +
				FrontendShellSentinel + `</h1></main></body></html>`),
		},
		"assets/app-abc123.js": &fstest.MapFile{Data: []byte("console.log('app')")},
		".gitkeep":             &fstest.MapFile{Data: []byte("build placeholder")},
	}
}
