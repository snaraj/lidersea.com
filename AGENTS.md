# Agent contract — lidersea.com

This is the CANONICAL, vendor-agnostic agent contract for this repository:
any frontier model — or hurried human — must be able to operate here cold
from this document alone. Tool-specific entrypoints (CLAUDE.md) only import
it; nothing is duplicated elsewhere. The platform repository's deeper
doctrine applies when the two meet.

## Purpose and architecture

lidersea.com is the web home of Lidersea — luxury yacht maintenance,
customization, and detailing. It is a Svelte frontend embedded into a single
dependency-free Go binary (`cmd/server`, `internal/server`, `internal/web`),
shipped as a distroless multi-arch container plus a Helm chart, and deployed
by digest onto a self-hosted Kubernetes platform. The origin speaks standard
HTTP (RFC 9110/9111) only and is provider-neutral per the
deployment-provider contract below. Unlike its sibling naranjo.online, this
repository has NO media subsystem: `src/lib/media.ts` and
`frontend/src/assets/` are naranjo.online structures that do not exist here.
The current hello-world shell is temporary placeholder content headed for
the real site, and the test suite is built so that growth is a conscious
edit, never a fight (see Sanctioned evolution).

## Requirements

Numbered for citation, repo-scoped, none negotiable in code:

1. **Zero spend, no external services.** Everything runs on owner hardware
   and free CI. No paid API, SaaS, tracker, CDN, or third-party runtime
   dependency may be introduced — the frontend stays local-origin-only.
2. **Owner-only merges; protected history.** Work lands through PRs into
   `main`; the owner merges. Never push `main`, never force-push, never
   create tags outside the release flow.
3. **Commit-metadata privacy and attribution.** Commits are authored AND
   committed as the owner's GitHub noreply identity (both fields). No
   co-author trailers. Agent-authored commit messages and PR bodies are
   signed `- Fable5` (owner attribution decision, 2026-08-10).
4. **Fail-closed doctrine — never weaken.** No security behavior may be
   made toggleable: no boolean, env var, build tag, or config field may
   silently disable signing, verification, probes, TLS, header policy, or
   fail-closed sentinels. Never weaken a check, guard, validator, or test;
   if one blocks you, fix the cause or surface the conflict. Narrow,
   justified exceptions only, stated where the owner will read them. Tests
   should make dangerous states unrepresentable.
5. **Site independence.** lidersea.com shares conventions with its sibling
   repository (naranjo.online) but depends on nothing from it: no shared
   code, secrets, infrastructure state, or cross-repo references in build
   or runtime.
6. **Provider neutrality (owner requirement R9).** The origin knows no
   ingress, DNS, edge, or access provider. Provider names live exclusively
   in chart values defaults; `TestProviderNeutrality` enforces zero
   occurrences anywhere else. See the deployment-provider contract below.
7. **Ratchet-only coverage floor.** The PR gate enforces
   `GO_COVERAGE_FLOOR` (currently 88.2%, measured 91.2%). Raise it as
   coverage grows; lowering it weakens an enforced check and is out of
   policy.
8. **Truthful serving contract.** Port 8080; `/livez` and `/readyz` stay
   truthful — readiness reflects real serving ability, never a hardcoded
   yes.
9. **Dependency-free Go.** The Go module stays standard-library only.
   Adding a dependency is an owner decision, not a convenience.
10. **Digest deploys, immutable releases.** Images deploy by digest.
    Version tags are immutable and never reassigned. The release workflow
    has no skip flag, no force path, no manual dispatch — never add one.
11. **No secrets, no personal data.** No credential, token, private host
    fact, or personal data ever enters this repository — including in
    tests, fixtures, and docs.

### Deployment-provider contract

The origin speaks standard HTTP (RFC 9110/9111) only. Ingress, DNS, edge,
and access are injected deployment concerns and never appear in application
code, frontend source, or chart templates. Provider names live exclusively
in the chart's values defaults — `ingress.peerNamespace` and
`ingress.peerAppName` in `chart/values.yaml`, the single binding point the
NetworkPolicy consumes — so a provider swap is a values override, never a
template or code edit. The pin test
(`internal/doctrine/provider_neutrality_test.go`) enforces this, failing
closed on any provider name under `cmd/`, `internal/`, `frontend/src/`, or
`chart/templates/`; in reduced build contexts an absent tree is a stated
capability skip, never a pass, and the full-checkout gate enforces every
tree on every PR.

## Testing doctrine

- Coverage is enforced per requirement 7. `internal/testsupport` is test
  scaffolding — it runs only inside test binaries — and is excluded from
  the coverage denominator by the gate's profile filter; that exclusion
  may never grow to cover production packages.
- Filesystem boundaries are proven with deep fakes: the read-counting,
  fault-injecting `faultFS` in `internal/server` pins the fail-closed 500
  branch (opaque body, headers intact) and that the entrypoint is read
  exactly once at construction, never per request.
- End-to-end suites boot `run(ctx, lookupEnv)` over real TCP and drain on
  a real SIGTERM; they deliberately avoid `testing/synctest` because
  genuine network I/O cannot block inside a synctest bubble, so readiness
  is polled with bounded real-time deadlines. Visitor-scenario suites
  (`cmd/server/visitor_test.go`) drive the same boots through the
  `testsupport.Visitor` mock browser — ETag replay, asset-reference
  following, the security-header baseline asserted on every navigation —
  and must read as user stories.
- Fixture text is sentinel-only: tests assert structure and markers
  (`data-static-fallback`, fixture sentinels, non-empty labelled
  headings), never site copy.
- Repo-doctrine pins live in `internal/doctrine` (currently provider
  neutrality).
- Tests are stdlib-only with hand-written fakes; no assertion libraries,
  no mock frameworks.

## Package layout

- Each Go package keeps its type/struct declarations and package-level
  const/var blocks in `types.go`; methods and logic stay beside the files
  they serve. A `utils.go` exists only where a genuinely shared cross-file
  utility does — never create an empty or speculative one (none currently
  qualifies in this repository).
- Shared API-level fixtures and the mock-browser harness live in
  `internal/testsupport`; white-box fakes that need unexported access
  stay in the package they observe (testsupport never imports the
  packages under test). Visitor scenarios live in
  `cmd/server/visitor_test.go`.

## Build, test, and release flows

Build and test, in this order (the same gate CI enforces):

1. `cd frontend && npm ci --ignore-scripts --no-audit --no-fund &&
   npm run check && npm test && npm run build` — the build lands in
   `internal/web/dist`, which the Go embed test needs.
2. `gofmt -l .` must be empty; `go vet ./...`;
   `CGO_ENABLED=0 go test ./...`; `go test -race ./...`. CI additionally
   enforces the coverage floor (requirement 7) on the
   scaffolding-filtered profile.
3. `helm lint chart && helm template smoke chart --kube-version v1.36.0`
   for chart changes (the chart requires the platform's Kubernetes
   target; plain `helm template` defaults to older capabilities).
4. `docker build .` when the Dockerfile or build inputs change.

Releases: `VERSION`, `chart/Chart.yaml` (`version` + `appVersion`), and
the git tag move together (CI enforces the three-way lock). SemVer per the
platform's ADR 0014: releases are strict bumps; history is append-only.
Update `CHANGELOG.md` in the same PR as the change it describes; release
dates in the changelog are owner-local dates. Pushing `vX.Y.Z` publishes
the signed multi-arch image, the signed OCI chart, and a GitHub Release;
deployment consumes digests, never tags.

## Sanctioned evolution

The following are expected changes, and the suite is built to make them
conscious edits, never fights:

- Real content replacing the placeholder shell: components, routes, styles,
  and copy for the actual Lidersea site. Content is not a contract — tests
  pin structure and markers (the `data-static-fallback` marker, fixture
  sentinels, non-empty labelled headings), so shipping real copy must not
  break a handler or shell test.
- The remote-origin guard in `frontend/tests/experience.test.mjs` today
  rejects every `//` occurrence in the shell sources. When real content
  lands, its scoping will need a documented adjustment (still banning
  remote origins per requirement 1, while permitting legitimate local
  patterns) — adjust it consciously in that content PR, never delete it.
- Small UI assets, when they arrive, live under documented categories with
  size ceilings, mirroring naranjo.online. Heavy media (portfolio video,
  high-resolution photography, audio) never enters git, the bundle, the
  embed, the image, or a ConfigMap/Secret — it belongs to dedicated
  platform storage, and introducing a media pipeline here is an owner
  decision, not incremental drift.
- CSP changes happen in lockstep: `securityHeaders` in
  `internal/server/server.go`, `testsupport.SiteContentSecurityPolicy`,
  and every pinned test value move in the same commit.
- Ingress provider changes: a values override of the `ingress` block per
  the deployment-provider contract.

None of this relaxes the requirements above: security behavior stays
non-toggleable, provider names stay confined to values defaults, and the
coverage floor only rises.
