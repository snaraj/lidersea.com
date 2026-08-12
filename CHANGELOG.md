# Changelog

All notable changes to lidersea.com. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
SemVer and match image/chart tags exactly.

## [Unreleased]

### Fixed
- Media Range-matrix test determinism (post-merge advisory on #23, High):
  the matrix built one handler with `MaxConcurrent: 4` and then ran its
  subtests in parallel, so more than four in-flight responses made the
  handler correctly shed with 503 where the test expected 206 — correct
  product behavior, nondeterministic test. The matrix (and the parallel
  opaque-404 table, same class) now sizes its handler's semaphore to the
  subtest count so every request is admitted; overload shedding remains
  deliberately covered by `TestBoundedConcurrencySheds`. Proven with the
  media suite at `-count=20` plain and under `-race`, plus three
  whole-repo runs.
- AGENTS.md internal drift: the "Quality gates" coverage-floor citation
  (88.2/91.2, from the handbook PR merging alongside #23) now matches
  requirement 7's enforced 95.0 (measured 97.6).

### Security
- Origin-side HTTPS enforcement (#29): every request the edge declares
  as plain HTTP (`X-Forwarded-Proto: http`) is answered with a `308`
  permanent redirect to the identical URL over TLS — host from the
  request's Host header, escaped path and query preserved byte for
  byte, on every route, HEAD and POST bodiless like GET — as defense
  in depth behind the edge's own HTTPS enforcement. `308` (not `301`)
  preserves the request method and body: the redirect runs ahead of
  routing, so a `POST` to the gated reviews/estimates carve-outs over
  the plain leg is bounced here, and `301` would rewrite it to `GET`
  and drop the body while `308` replays it to the TLS URL intact. The
  edge's own Always-Use-HTTPS remains the primary redirect. Matching
  is a byte-exact equality (pinned against any future
  trim/prefix/contains regression): trailing/leading whitespace and
  comma-list proto values are "not our edge" and neither redirect nor
  mint the promise. The HSTS header keeps its
  exact value (`max-age=31536000`: the application is the sole HSTS
  owner, edge-managed HSTS stays off, and includeSubDomains/preload
  remain deferred owner decisions pending a subdomain inventory and a
  rollback path) but now rides only responses the edge declares as TLS
  (`X-Forwarded-Proto: https`). Behavior change for undeclared
  traffic: probe, port-forward, and local-dev responses — which
  previously carried HSTS on connections that never demonstrated TLS —
  now serve without it; nothing else about undeclared serving changes.
  Matching is exact and fail-closed: case variants and unknown proto
  values neither redirect nor mint the promise, and the forwarded
  header is trusted for this scheme decision only. The read-only
  contract and gated write carve-outs are byte-unchanged for declared-
  TLS and undeclared requests alike.

## [0.1.9] - 2026-08-11

### Added
- Surface API (issues #19/#20/#21, wiring only): the site's own
  `surface/v1` envelope `{schema, id, kind, title, generatedAt,
  status: ok|stale|unavailable, data}` with an explicit-route registry —
  `GET /api/board` (media-mosaic/v1: image/video/text blocks carrying
  width/height/aspect and pre-declared variants for zero-CLS layout,
  fixed-size cursor pagination) and `GET /api/reviews` (reviews/v1:
  embedded samples with a server-computed integer-tenths aggregate).
  Unknown `/api/` paths are opaque 404s; sample-backed envelopes carry a
  fixed publication instant so their digest ETags revalidate to 304s;
  payload budgets (board page ≤ 48 KiB, reviews ≤ 16 KiB) are pinned by
  tests. Domain logic lives in dedicated packages (`internal/board`,
  `internal/reviews`, `internal/estimates`) that the server composes.
- Estimates domain (estimates/v1): pure integer-cent computation — int64
  cents and basis points only, one documented rounding mode (half up,
  once, on the summed taxable base), overflow-decomposed tax product
  proven at the caps' extremes — plus a renderer registry
  (`internal/estimates/render`: markdown and HTML in pure Go, byte-exact
  goldens, renderers never recompute; PDF v1 is the browser's
  print-to-PDF and true server-side PDF is a flagged owner dependency
  decision) and a delivery contract (`internal/estimates/delivery`:
  interface plus an honest "not configured" refusal; transport waits on
  the platform egress design). `POST /api/estimates/preview?format=`
  ships behind `ESTIMATES_ENABLED` (default off: opaque 404).
- Gated review write path: `POST /api/reviews` behind
  `REVIEWS_WRITE_ENABLED` (default off). The default build keeps the
  GET/HEAD-only contract test and the `form-action 'none'` CSP
  byte-intact; the enabled mode is a narrowly-scoped carve-out (only
  this route, strict validation, size caps, honest 503
  "storage not configured" until persistence exists) asserted by its own
  explicit suite, and the security-header policy is byte-identical in
  every mode.
- Media pipeline (`internal/media`): env-gated
  (`MEDIA_ENABLED`/`MEDIA_ROOT`/`MEDIA_MAX_CONCURRENT`, all-or-nothing,
  fail-closed at startup) serving the digest-immutable URL class
  `/media/immutable/<sha256>/<name>` with explicit Range support pinned
  by a start/middle/suffix/open/multipart/malformed/416 matrix, digest
  strong ETags with the immutable cache class, a distroless-safe media
  content-type allowlist (no SVG), kernel-enforced root containment
  (`os.Root`), and bounded concurrency with honest 503 shedding. Chart
  media-volume wiring is documented, deliberately unwired, until the
  platform storage design lands.
- Visitor-scenario end-to-end suites: a hand-written stdlib mock-browser
  harness (`internal/testsupport.Visitor`) remembers and replays ETags
  like a browser cache, follows the document's asset references, and
  asserts the security-header baseline on every navigation; scenarios
  cover first visit, repeat visit, missing deep links, and hostile
  probing (traversal, encoded traversal, duplicate separators, dotfiles,
  build placeholders, development artifacts) over real transport.
- `internal/testsupport`: shared API-level fixtures — the canonical
  sentinel frontend bundle — excluded from the coverage denominator as
  test scaffolding; white-box fakes stay in the packages whose internals
  they observe.
- `CLAUDE.md` bridge importing `AGENTS.md`, now the canonical
  vendor-agnostic agent contract (purpose and architecture,
  numbered requirements, testing doctrine, package layout, build and
  release flows, sanctioned evolution).

### Changed
- Provider neutrality (owner requirement R9): the NetworkPolicy's ingress
  peer is now values-driven (`ingress.peerNamespace`,
  `ingress.peerAppName`, defaulting to the current Cloudflare Tunnel
  connector) and the policy resource is renamed
  `cloudflared-to-lidersea-com` to `ingress-to-lidersea-com`; a provider
  swap is a values override, never a template or code edit. A fail-closed
  pin test asserts zero provider names in application code, frontend
  source, and chart templates — chart values defaults are the only
  sanctioned location.
- Package layout convention: each Go package keeps its types and
  package-level const/var declarations in `types.go` (genuine shared
  utilities in `utils.go` — none currently qualifies); the
  graceful-shutdown window is a named constant.
- Tests assert structure and sentinel fixtures, never placeholder copy,
  so the temporary hello-world shell can become the real site without
  breaking behavior tests; AGENTS.md documents this and the other
  sanctioned-evolution paths.
- Go coverage floor raised 88.0% to 88.2%, then 88.2% to 95.0% with the
  surface suites (ratchet-only; measured 97.6% on the
  scaffolding-excluded production denominator).

### Fixed
- The frontend badge no longer publishes a vacuous coverage percentage:
  the shell tests read source as text, so no application file executes
  and the experimental coverage table had zero file rows behind its
  "100%" total. The badge now reports the truthful passing-test count
  ("frontend tests: N passing"); a coverage badge returns when real
  component tests execute the frontend code.
- Documentation drift: AGENTS.md step 3 now includes the
  `--kube-version v1.36.0` flag CI actually uses for `helm template`,
  and cites the enforced coverage floor.

## [0.1.8] - 2026-08-11

### Added
- End-to-end lifecycle tests for the server process over real TCP sockets:
  serve → graceful drain on context cancellation and on a real SIGTERM,
  invalid `PORT` rejection before any socket opens, and surfaced bind
  failures (`EADDRINUSE`).
- Fault-injection tests through a hand-written instrumented filesystem
  (`faultFS`): the fail-closed 500 response when a read fails after a
  successful stat (headers intact, no internal detail leaked), and proof
  that `index.html` is read exactly once at construction, never per
  request.
- The PR gate now enforces a Go total-coverage floor (88%, measured 91.2%
  at introduction). The floor only ratchets upward.

### Changed
- `run` receives its lifecycle context and environment lookup as
  parameters; `main` owns the signal contract. Behavior is unchanged —
  the seam exists so the full lifecycle is testable and subtests can run
  in parallel without process-global state.
- Request header metadata is capped at 32 KiB instead of net/http's 1 MiB
  default, matching naranjo.online.
- Ambiguous request paths (traversal, dot segments, duplicate separators,
  trailing slashes, backslashes, NUL bytes) now receive a terminal 404
  before routing instead of a canonicalizing redirect, matching
  naranjo.online.

### Fixed
- Documentation drift: `src/lib/media.ts` and `frontend/src/assets/` are
  naranjo.online structures that do not exist here yet; AGENTS.md and
  README now say so explicitly instead of implying they are present.
- The 0.1.7 release date below (released 2026-08-10, not 2026-08-11).

## [0.1.7] - 2026-08-10

### Changed
- Serve the application shell as `no-cache` instead of `no-store`, so the
  edge and browser may store it while still revalidating every navigation.
  An unchanged site now answers with a small `304` instead of shipping the
  whole document from the origin through the tunnel each time; the shell
  was the one uncacheable resource on an otherwise fully cached site. The
  document is public and its `ETag` is a content digest, so nothing is
  traded for the gain. Content-hashed assets keep their immutable caching.

### Added
- `TestNoRequestMethodCanEverMutate` pins that every route refuses every
  mutating method — the executable safety contract that makes TLS 1.3
  0-RTT (early data, which can be replayed) admissible at the edge.

## [0.1.6] - 2026-08-10

### Fixed
- Release pipeline: capture helm push's stderr so the chart digest is
  read for signing and the Release notes. v0.1.5 published a signed
  image and an unsigned chart artifact before the digest parse refused;
  tags are immutable, so v0.1.6 is the first complete signed release
  (image + signed OCI chart + GitHub Release).

## [0.1.5] - 2026-08-10

### Fixed
- Release pipeline: removed the invalid GitHub attestation step (buildx
  SLSA provenance + SBOM and the Cosign signature remain the integrity
  evidence). v0.1.4 published a valid signed image but no chart or
  GitHub Release; tags are immutable, so v0.1.5 is the first complete
  release.

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
