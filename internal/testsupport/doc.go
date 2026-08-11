// Package testsupport holds the API-level test fixtures and harnesses shared
// by this module's Go suites: the canonical healthy frontend bundle and the
// Visitor mock-browser harness for end-to-end scenarios. Centralizing them
// keeps every suite exercising the same shapes instead of hand-copied
// near-duplicates that drift apart.
//
// Only fixtures that need public surface area live here. White-box fakes that
// reach unexported internals — the fault-injecting, read-counting filesystem
// in internal/server — deliberately stay in their own packages, next to the
// internals they observe: this package must never import the packages under
// test, or the in-package suites that consume it could not import it back.
//
// Fixture text is sentinel-only by policy: suites assert markers and
// structure, never real site copy, so shipping real content can never break a
// handler-behavior test.
//
// Everything here is test scaffolding. It runs only inside test binaries and
// is excluded from the enforced coverage denominator by the PR gate.
package testsupport
