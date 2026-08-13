# Security

## Reporting

Report suspected vulnerabilities privately via GitHub's security advisory
form for this repository ("Report a vulnerability"). Please do not open a
public issue for anything security-sensitive. Reports are read by the
owner; you should normally hear back within a week.

## Supported versions

Only the latest released version (the newest `vX.Y.Z` tag) is supported.
Releases are immutable; fixes ship as new versions, never as re-tags.

## Posture (what you can rely on)

- The service is a single static Go binary in a shell-less distroless
  image, running as a non-root user, serving embedded static content on
  port 8080 with no runtime dependencies and no outbound calls.
- Images and charts are published only after successful main CI by an
  exact-SHA orchestrator that creates the immutable version tag and explicitly
  dispatches the publisher on that tag. The publisher remains multi-arch,
  keyless-signed (Cosign), with SBOM and SLSA provenance. Deployment consumes
  immutable digests.
- CI is secretless on pull requests; all third-party actions are pinned to
  full commit SHAs; scanners are checksum-pinned; secret scanning covers
  full history on every PR.
- Security behaviors have no toggles: there is no flag, env var, or config
  path that disables verification, probes, signing, or the fail-closed
  defaults — by design, and by review policy.

## Out of scope

Site content licensing, the hosting platform's infrastructure (tracked in
its own repository), and reports requiring physical or LAN access to the
origin host.
