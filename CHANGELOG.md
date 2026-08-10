# Changelog

All notable changes to lidersea.com. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
SemVer and match image/chart tags exactly.

## [Unreleased]

Nothing yet.

## [0.1.4] - 2026-08-10

### Added
- Go module renamed to the standalone identity github.com/snaraj/lidersea.com.
- Standalone repository: complete history imported from the
  `website-infrastructure` monorepo with authorship preserved.
- Production CI: PR gate (frontend + Go tests with coverage, chart lint,
  dual-arch container build, secret/history scanning, actionlint,
  dependency review) and CodeQL.
- Tag-triggered release publisher: multi-arch image + OCI Helm chart to
  GHCR, Cosign keyless signing, SBOM, SLSA provenance, GitHub Releases.
- Documentation: README, agent contract (AGENTS.md), security policy,
  MIT license with all-rights-reserved site content.

## [0.1.3] and earlier

Released from the monorepo publishers (`ghcr.io/snaraj/lidersea-com`
`v0.1.2`, `v0.1.3`): hello-world frontend contract, health/readiness
endpoints, embedded-serving hardening, fail-closed media subsystem. See
the monorepo history (imported here) for details.
