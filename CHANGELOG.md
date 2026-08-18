# Changelog

All notable changes to lidersea.com. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `VERSION`, chart
metadata, these headings, and Helm's strict OCI chart tag use numeric SemVer.
Git, image, and GitHub Release tags use the exact plain `vX.Y.Z` form.

## [Unreleased]

## [0.1.11] - 2026-08-18

### Changed

- CI: `github/codeql-action/init` and `github/codeql-action/analyze` bumped
  together from 4.37.6 to 4.37.7 (`.github/workflows/codeql.yml`). Both
  actions are full-SHA pinned in the same `analyze` job, and CodeQL
  requires matching CLI versions between `init` and `analyze` within one
  job, so Dependabot's per-artifact PRs #50 (`init`) and #51 (`analyze`)
  mutually blocked each other's CI with "Loaded a configuration file for
  version X, but running version Y." This single commit moves both pins
  together. `.github/dependabot.yml` now groups future
  `github/codeql-action*` updates under one `github-actions` group so
  this pairing arrives as one PR instead of two.

## [0.1.10] - 2026-08-13

### Added

- Every protected-main merge now carries and publishes its own semantic patch
  release. Pull requests (including docs and dependency updates) must advance
  the four committed source locks by exactly one patch from their protected
  base. The PR, protected-main, and recovery paths share one intermediate-state
  machine: each commit retains `VERSION` or advances one patch; skips,
  reversions, transient future values, and collapsed multiple boundaries fail.
  Successful main CI binds the exact final SHA, creates its annotated plain-v
  Git tag, and explicitly dispatches the publisher definition from protected
  `main` with the authoritative completed-run ID.

  A read-only run-authorization job rejects manual/unmerged dispatches. Before
  tag, registry, signing, attestation, or Release effects, structurally separate
  environment-gated jobs mint a current-repository Administration-read-only App
  token and authoritatively recheck immutable Releases, SHA-pinned Actions,
  signed-commit/main rules, strict checks, and repository security. The token is
  step-local and never crosses into a mutation job; ordinary `GITHUB_TOKEN` is
  the sole mutation credential.

  Rapid merges have exact-SHA, noncancelling paths. Real shell create, verify,
  conflict, race, and bounded retry paths are hostile-tested. Complete image
  reuse authenticates the exact `linux/amd64` and `linux/arm64` SBOM/provenance
  set. The final image digest is HIGH/CRITICAL vulnerability-gated before
  signing. New Releases are created Draft with exactly one canonical mode-0600
  `release-manifest.json` machine asset binding source, image digest, chart
  digest, signature, SBOM, and provenance expectations. Asset name/count/size,
  SHA-256, canonical content, draft/upload/publish state, and final immutable
  state are exact; human title/notes are informational. The workflow then ends
  with an unconditional REST rebind of both annotated tag records.

  Image `vX.Y.Z` and Helm `X.Y.Z` registry tags are explicitly mutable aliases;
  only their recorded digests are immutable artifact identities. A scheduled
  read-only audit revalidates the Release/manifest/tag, alias-to-digest
  bindings, image/chart signatures, exact SBOM/provenance set, chart digest, and
  an immutable-digest vulnerability rescan. Recursive duplicate JSON members
  are rejected at every event, REST, registry, Buildx, manifest, and Cosign
  boundary. Repository server controls remain an external Ready gate proven by
  the closed GET-only settings receipt.
- A deployed Pod now states which release it is. The shared labels helper
  emits `app.kubernetes.io/version` on every rendered object, taken from the
  chart's own `appVersion` rather than from values, and the container image
  renders as `ghcr.io/snaraj/lidersea-com:vMAJOR.MINOR.PATCH@sha256:<hex>`
  instead of the digest alone — so `kubectl describe pod` and
  `kubectl get po -L app.kubernetes.io/version` both answer the question
  without anyone resolving a digest by hand.

  Nothing about the digest changed. It stays mandatory in `values.schema.json`,
  stays what Kubernetes actually resolves, and stays what cosign and the
  platform's admission policies verify (requirement 10). The tag accompanies
  it; it never replaces it. The PR gate's version lock now has four legs
  instead of three — VERSION, chart `version`, `appVersion`, and the image tag
  — and additionally asserts the rendered reference still carries a full
  digest. `internal/doctrine/release_identity_test.go` pins the whole contract,
  including that the version label never becomes a selector key.
- Ratings across platforms: a new `ratings/v1` surface under the site's
  `surface/v1` envelope (`GET /api/ratings`) and a footer strip that
  renders it. The strip lists the third-party platforms the business
  publishes on — Google, Yelp, Facebook, Trustpilot, and the Better
  Business Bureau — with each platform's captured rating, review count, and
  an outbound link to its public profile. It is rendered entirely with this
  site's own markup and CSS: no third-party script, widget, iframe, embed,
  or image is involved anywhere, so the CSP is unchanged and the frontend
  stays local-origin-only. Outbound links carry `rel="noopener noreferrer"`,
  open in a new tab, and say so in their accessible name. Values are paired
  with text and shape — the number, a length meter, the review count —
  never colour alone.

  The data is schema-first and owner-editable:
  `internal/ratings/platforms.json` is embedded, decoded, and VALIDATED
  during construction, so a malformed or half-filled file fails startup
  rather than reaching a visitor. A platform is either published with a
  rating, a review count, a capture instant, and a profile URL, or it is
  pending with none of them — the partially-populated state is
  unrepresentable, which is what stops an invented number from being
  presented as a business fact. Ratings are authored and validated as
  integer tenths and served as a derived one-decimal number; the summary is
  server-computed, weighted by review count, and OMITS its average entirely
  when nothing is published, because a zero there would read as a rating of
  zero rather than as an absence. The envelope's status follows the same
  honesty: `unavailable` when no rating has been captured, `stale` when the
  newest capture is past the configured refresh window, `ok` otherwise. The
  update procedure is documented in AGENTS.md and in the `internal/ratings`
  package doc. The shipped snapshot lists every platform as pending with no
  URLs: nothing about the business is invented.

  An optional producer (`internal/ratings/collect`) can refresh the
  snapshot from each platform's own feed, and it ships OFF behind
  `RATINGS_COLLECTOR_ENABLED` (with a required interval and timeout, parsed
  all-or-nothing and fail-closed). It is honest about what it can do today:
  no supported rating platform offers a rating read without an account
  credential, so the shipped snapshot declares no feed URLs and an enabled
  collector on a stock build fetches nothing — the mechanism is a reviewed,
  tested contract for a future authenticated ingest. Its safety properties
  are fixed in code and reachable from no configuration and no data file:
  https only, a per-platform host allowlist re-checked at call time,
  redirects refused rather than followed, a 16 KiB body cap, a JSON
  content-type requirement, a strict decode, bounded
  connect/handshake/request timeouts, and a final pass of the whole result
  through the same validation the shipped file must satisfy. Every pass is
  snapshot-first and fail-soft: a platform that cannot be read keeps the
  value it already had, so no failure mode can blank a published rating.

  The GET/HEAD-only origin contract, the CSP, and the
  `REVIEWS_WRITE_ENABLED` / `ESTIMATES_ENABLED` gates are untouched; the new
  route is read-only with every gate open.

- Reading themes: the site now serves a light theme, a dark theme, and a
  system theme that follows the visitor's own device, selected by the
  `lidersea_theme` cookie and delivered without a first-paint flash or a
  layout shift. The origin precomputes one shell per catalog theme during
  construction — each already carrying its `data-theme` attribute — so a
  navigation is answered by choosing precomputed bytes and never by
  editing a document on the request path; the browser therefore parses a
  document that already declares its theme and there is no scripted
  correction to flash. The origin never SETS a cookie: the switcher writes
  the preference client-side (`SameSite=Lax`, `Secure` on TLS, a display
  value with no identifier and no security meaning) and the origin only
  reads it, so the read-only posture is unchanged. Absent, unknown,
  oversized, and hostile cookie values all resolve to the default theme
  and never reach a document. The shell — and only the shell — answers
  `Vary: Cookie`, so each variant keeps its own digest ETag and its own
  cache entry, and a bundle whose document cannot be stamped fails
  construction instead of serving every visitor an unthemed page.
  `styles.css` becomes the token layer the frontend floors called for:
  colour literals exist only in the palette block, both palettes are
  validated against WCAG 2.2 contrast floors by the frontend suite rather
  than asserted, and every theme rule may declare custom properties ONLY —
  the mechanical form of the zero-layout-shift promise, since a theme can
  then change colour and nothing that occupies space. Rendering-lane
  stage-1 floors land with it: `viewport-fit=cover` plus safe-area insets,
  44px touch targets, 1rem control text, `100svh` with a percentage floor
  (never `100vh`), an `@supports` guard, `prefers-reduced-motion`, and no
  fixed size that could scroll a 320px viewport sideways. Payload budgets
  ship as tests over the real built artifact (every themed shell variant,
  each content-addressed asset, the whole bundle) and over shell source
  size.

- Release publisher attaches the BuildKit SLSA v1 provenance as keyless
  cosign attestations (`slsaprovenance1`) on the immutable image digest,
  immediately after image signing — read back per platform from the
  just-pushed index, bound to this release (builder run, vcs source, vcs
  revision) before anything is attached, then verified in the same run —
  `cosign verify-attestation` against this workflow's tag identity, plus
  a count of the attestations the digest actually carries afterwards — so
  a release whose attestations are missing, unverifiable, or clobbered by
  the fallback-tag read-modify-write fails at release time rather than at
  promotion. The platform set is derived from the index and asserted to
  equal the build's, so a missing or extra platform fails the release and
  no hardcoded list can drift from the build step. No new actions, no new
  permissions (the unused `attestations: write` grant is dropped — this
  workflow uses cosign, never GitHub's attestation API), no skip path;
  effective from the next tagged release. The attestations are a lossy
  normalized copy: cosign v3.1.3 drops the BuildKit metadata subtrees
  (including vcs source and revision) and rebinds each per-platform
  predicate to the index digest, so the index-embedded provenance
  remains the authoritative content evidence. Completes this site's
  precondition for the platform promotion ratchet
  (website-infrastructure#58).

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
- The chart's ingress NetworkPolicy can now name its peer **completely**
  (#40). It admitted a peer by namespace and `app.kubernetes.io/name` —
  the only peer facts the values exposed — but the peer namespace is
  shared by several per-site connectors that publish the same app name
  and are separated only by `app.kubernetes.io/instance`. The rendered
  selector therefore admitted every connector in that namespace rather
  than the one that fronts this site. The deployed policy was
  hand-tightened with the instance pin (dated observation, 2026-08-11;
  revalidate read-only before relying on it), so a chart-driven apply
  would have WIDENED the running policy — a security regression
  delivered by a routine release rather than by a bad edit. `ingress`
  now carries `peerInstance`, defaulted to this site's own connector so
  the pinned policy is what renders with no flags at all, and
  `values.schema.json` requires it non-empty: a blank or absent value
  fails validation instead of rendering an unpinned policy.
  `scripts/ci/chart-ingress-pin.sh` runs in the PR gate and proves all
  three properties — the default render pins namespace + app name +
  instance byte for byte against the values, blank and absent are both
  refused, and overriding the instance moves the pin while the app name
  stays identical, which is exactly why the app name alone cannot tell
  two connectors apart.
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
