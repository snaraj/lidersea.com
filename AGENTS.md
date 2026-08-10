# Agent contract — lidersea.com

Rules for any AI agent (or hurried human) working in this repository. The
platform repository's deeper doctrine applies when the two meet.

## Build and test, in this order

1. `cd frontend && npm ci --ignore-scripts && npm run check && npm test && npm run build`
   — the build lands in `internal/web/dist`, which the Go embed test needs.
2. `gofmt -l .` must be empty; `go vet ./...`; `CGO_ENABLED=0 go test ./...`;
   `go test -race ./...`.
3. `helm lint chart && helm template smoke chart` for chart changes.
4. `docker build .` when the Dockerfile or build inputs change.

## Invariants (do not negotiate these in code)

- Port 8080; `/livez` and `/readyz` stay truthful — readiness reflects real
  serving ability, never a hardcoded yes.
- The Go module stays dependency-free (standard library only). Adding a
  dependency is an owner decision, not a convenience.
- Images deploy by digest. Version tags are immutable and never reassigned.
  The release workflow has no skip flag, no force path, no manual dispatch —
  never add one.
- **No security behavior may be made toggleable.** No boolean, env var,
  build tag, or config field may silently disable signing, verification,
  probes, TLS, header policy, or fail-closed sentinels. If a security check
  blocks you, fix the cause or surface the conflict — never weaken or flag
  off the check. Tests should make dangerous states unrepresentable.
- Heavy media never enters git, the bundle, the embed, the image, or a
  ConfigMap/Secret. Small assets respect the documented category and size
  ceilings.
- Frontend URLs come from `src/lib/media.ts`; components never know hosts,
  volumes, or origins.

## Versioning and releases

`VERSION`, `chart/Chart.yaml` (`version` + `appVersion`), and the git tag
move together (CI enforces). SemVer per the platform's ADR 0014: releases
are strict bumps; history is append-only. Update `CHANGELOG.md` in the same
PR as the change it describes.

## Conduct

- Work through PRs into `main`; the owner merges. Never push `main`, never
  force-push, never create tags outside the release flow.
- Commit messages and PR bodies are signed `- Fable5` when authored by the
  agent; no co-author trailers (owner attribution decision, 2026-08-10).
- No credential, token, private host fact, or personal data ever enters
  this repository — including in tests, fixtures, and docs.
