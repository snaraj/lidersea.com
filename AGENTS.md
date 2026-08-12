# Agent contract — lidersea.com

This is the CANONICAL, vendor-agnostic agent contract for this repository:
any frontier model — or hurried human — must be able to operate here cold
from this document alone. Tool-specific entrypoints (CLAUDE.md) only import
it; nothing is duplicated elsewhere. The platform repository's deeper
doctrine applies when the two meet.

## Cold start — first-session checklist

A new agent operates from this repository alone; nothing is relayed by
the owner. In order:

1. Read this file end to end — it is the whole briefing; CLAUDE.md only
   imports it.
2. `git fetch origin` and work from `origin/main`. Never trust a local
   `main`, a stale worktree, or another agent's summary of remote state —
   verify remote facts directly (`gh pr view`, `git ls-remote`).
3. Verify identity and tooling: `gh auth status` shows the owner's
   account; commits carry the noreply identity per "Commit identity
   mechanics"; know CI's pinned toolchain (Go 1.26.5, Node 24.19.0,
   npm 11.17.0 — the gate verifies these exactly).
4. Survey the live state yourself: `gh issue list`, `gh pr list` —
   including the open-agent-PR count against the PR budget below.
5. Claim work through an issue, branch from `origin/main`, and follow
   "Working a change end to end".

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
   `GO_COVERAGE_FLOOR` (currently 95.0%, measured 97.6%). Raise it as
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
- The remote-origin guard in `frontend/tests/experience.test.mjs` is scoped
  to the two shapes a remote origin can take: an absolute `https?://` URL,
  and a protocol-relative `//host` reference inside a string, attribute, or
  `url()`. It previously rejected every `//` occurrence, which also outlawed
  JavaScript line comments; the narrowing was the documented adjustment the
  first real component required, and requirement 1 is unchanged in force.
  Any further scoping is a conscious edit in the PR that needs it, never a
  deletion — and any remote reference the site ever needs arrives as data
  from this origin's own API, never as a literal in shell source.
- **Publishing a rating platform.** `internal/ratings/platforms.json` is the
  owner's data file and the ONLY place platform names, profile URLs, and
  captured values live. To publish one: read the rating and review count
  from that platform's own public profile; set `profileUrl` to the public
  profile (https, host on that platform's allowlist); set `ratingTenths` to
  the rating times ten, `reviewCount`, and `capturedAt` (RFC 3339 UTC); set
  `state` to `published`; bump the file's `publishedAt`; run the Go suite.
  Every rule is enforced by `ratings.Snapshot`, which `NewSite` calls during
  construction, so a malformed file fails startup instead of reaching a
  visitor. A platform may carry a `profileUrl` while still `pending` — a
  listed profile with no rating yet is a legitimate, honest state. Adding a
  new platform is a CODE change, not a data change: its allowed hosts live
  in `internal/ratings/types.go` so a data file can never introduce an
  outbound destination nobody reviewed. The full procedure is in the
  `internal/ratings` package doc.
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

## Adversarial review protocol

Every substantive PR receives an independent adversarial review BEFORE it
leaves draft. The mechanism is vendor-agnostic: any capable agent — or a
human — runs it with git, a shell, and this repository's own gates; no
step assumes a particular AI tool. (Claude sessions load this contract
automatically through CLAUDE.md; other agents read AGENTS.md directly.
Neither gets a different protocol.)

**Reviewer independence.** The reviewer is a different agent or context
than the author — a fresh session of the same vendor qualifies; a
different lane is better. The reviewer works in a disposable worktree at
the PR head, stays read-only toward the author's workspace, reverts every
experiment, and removes the worktree afterward.

**The review must:**

1. Audit every claim in the PR body and commit messages against the
   actual diffs, reproducing every number the body cites. Overstatement
   is a finding even when the code is right.
2. Build a mutation kill matrix: for each guard or test the PR adds or
   changes, apply the exact regression it claims to prevent — the suite
   must go red. Revert between mutations. A surviving mutant is a
   finding.
3. Probe for vacuity: a guard that cannot fail is no guard. For each new
   or changed assertion, demonstrate at least one input that turns it
   red (the kill matrix usually supplies it); an assertion no input can
   fail is decorative, and decorative checks are findings.
4. Probe for flakes: the full suite at least three times, plus the race
   detector where the language has one. Any nondeterminism is a finding
   naming the test.
5. Check hygiene: commit identity (owner noreply in BOTH author and
   committer), signature conventions and agent labels, no co-author
   trailers, secret scan clean, out-of-lane paths untouched.
6. Check doctrine: nothing weakened — every gate, validator, or test
   change is additive or strengthening; exceptions are narrow, named,
   and justified where the owner will read them.
7. For CI-invisible paths (jobs that run only on pushes to main), demand
   simulated evidence of both directions in the PR and treat the first
   post-merge run as part of the change under review.

**Verdict format** — posted as a PR comment, so every vendor and the
owner see the identical record: APPROVE or REQUEST-CHANGES; numbered
findings with severity and file:line; the mutation kill matrix; flake
results; a claim-audit table (SUPPORTED / OVERSTATED per claim); explicit
"no finding — checked X, Y, Z" statements so silence is never ambiguous;
confirmation the scratch workspace was removed; the reviewing agent's
signature in the form `- <Agent> (adversarial reviewer)`, matching its
agent label. Posting the verdict also removes the `requires-review`
label, whichever way the verdict went — the item is no longer waiting on
review attention. A REQUEST-CHANGES verdict returns the work to the same
branch owner — fixes land on the same branch and receive a delta
re-review of the changed scope. A PR flips from draft to ready only
after an APPROVE verdict (or after findings are fixed and re-verified),
and the evidence comment remains on the PR as the permanent record.

A green check, a peer approval, or a ready state is evidence, never
authority: the owner alone merges.

## GitHub conventions

- **Issues first.** Substantive work is tracked as a labeled issue before or
  alongside its PR; PRs declare `Closes #N` so merges close the record.
  Feature intake lands as a `features`-labeled issue with the architectural
  constraints stated, even when implementation waits.
- **Labels.** One taxonomy, identical names/colors/meanings across all
  three repositories: `production-readiness`, `conventions`, `security`,
  `tests`, `ci`, `docs`, `release`, `fix`, `provider-neutrality`,
  `delivery-lane`, `features`, `requires-review`. New labels are added to
  all three at once.
- **`requires-review` — the review-readiness signal.** The author lane
  applies `requires-review` the moment a PR or issue is
  complete-from-author — every commit pushed, body and evidence final —
  so review attention is productive. Its ABSENCE on an open
  agent-authored PR or issue means the item is still in flight:
  reviewers and other lanes must not spend review effort on it. The
  reviewer removes it when posting the verdict; on REQUEST-CHANGES the
  author re-applies it once the fix commits are pushed. On an issue it
  carries the same meaning — complete enough to act on or decide — and
  whoever then acts on it or records the decision removes the label;
  opening a PR that claims the issue counts as acting. It is
  a coordination signal only: never a substitute for draft/ready state,
  for the APPROVE verdict that flips a PR ready, or for owner merge
  authority.
- **Agent labels.** Every agent-created PR and issue carries TWO further
  labels: the umbrella `agent-authored` AND the acting agent's own label —
  `fable5` (Claude Fable 5), `5.6-sol` (ChatGPT 5.6 SOL ULTRA), `opus5`
  (Claude Opus 5), `opus4.8` (Claude Opus 4.8). The body signature must
  match the label (`- Fable5` ↔ `fable5`), and adversarial-review
  verdicts carry the same identity as `- <Agent> (adversarial reviewer)`.
  These repositories are worked by several frontier models in parallel
  lanes; labels plus signatures keep authorship auditable with no owner
  relay. When a new model joins, its label — description "Authored by
  <model>" — is created in ALL THREE repositories before its first PR,
  per the one-taxonomy rule.
- **PR budget.** At most 3 agent PRs open in this repository by default;
  parallel pushes beyond that need explicit owner authorization first.
- **Merge authority.** THE OWNER ALONE MERGES. Never merge, never
  self-approve, never treat a peer approval or a green check as
  authority, and never force-push a shared ref. Every PR opens as a
  draft.
- **Milestones.** Every PR and issue carries one. Release milestones close
  when the release ships; completed arcs close their milestone.
- **Assignee.** The owner is assignee on every PR and issue (authorship is
  already the owner's account by token identity).
- **Linear history.** Merge commits are disabled in repository settings;
  the owner merges by squash (or rebase). Branches auto-delete on merge;
  stale local branches are pruned as work lands. History is append-only
  and never rewritten.
- **Commits.** Detailed bodies to the review protocol's evidence standard —
  problem, mechanism, enumerated changes, evidence — signed per lane.

## Working a change end to end

The complete delivery loop, each step gated by the sections around it:

1. **Claim the work.** File (or take) the issue; state intent and
   constraints. Label it — including both agent labels — assign the
   owner, set a milestone. Apply `requires-review` once the issue is
   complete-from-author — the problem stated, the acceptance criteria
   final; until it carries that label, the issue is still being drafted.
2. **Branch from `origin/main`** after `git fetch origin`; branch names
   are lane-prefixed (`fable5/<topic>`). One writer per branch, always —
   a branch that is not yours is a branch you never push to.
3. **Build the change** inside the requirements and doctrine above.
   Docs-only diffs still run the gates.
4. **Run the full local gate** ("Quality gates" below), then both secret
   scans, then commit under the pinned identity with a body to the
   evidence standard, ending with your signature.
5. **Push and open a DRAFT PR**: `Closes #N`, the same labels, owner as
   assignee, a milestone, body signed. Every number in the body must be
   reproducible — the adversarial review will reproduce it. Apply
   `requires-review` once the PR is complete-from-author — every commit
   pushed, the body final; until it carries that label, nobody reviews
   it.
6. **Adversarial review** per the protocol above; findings are fixed on
   the same branch by the same writer and delta re-reviewed before the
   flip to ready.
7. **Owner comments** are handled per the owner review protocol below.
8. **The owner merges.** Nothing you can do — approval, green checks,
   ready state — substitutes for that.

## Commit identity mechanics

Requirement 3, made operational. The identity — BOTH author and
committer, on every outgoing commit — is exactly:

    Samuel Naranjo <39077795+snaraj@users.noreply.github.com>

- Pin it per command with environment variables, never with `git config`
  (repository or global): configuration outlives the session, leaks into
  unrelated work, and hides identity decisions from review.

      GIT_AUTHOR_NAME='Samuel Naranjo' \
      GIT_AUTHOR_EMAIL='39077795+snaraj@users.noreply.github.com' \
      GIT_COMMITTER_NAME='Samuel Naranjo' \
      GIT_COMMITTER_EMAIL='39077795+snaraj@users.noreply.github.com' \
      git commit ...

- EVERY history-writing command runs under the same pinned environment —
  `commit`, `commit --amend`, `rebase`, `cherry-pick`. A rebase rewrites
  the COMMITTER of every replayed commit, and the privacy gate checks
  the committer field, so an unpinned rebase silently reintroduces the
  machine identity into otherwise-clean commits.
- No `Co-Authored-By` trailers, ever. Agent-authored commit bodies, PR
  bodies, and issue bodies end with the acting agent's signature (this
  lane: `- Fable5`), matching its agent label.
- Treat the Git index as public (requirement 11): no hostname, IP
  address, machine or account identifier, username, workspace path,
  token, or private operational fact enters any commit, message,
  fixture, or doc — what reaches history cannot be unpublished.

## Owner review protocol

Comments the owner leaves on PRs ARE code reviews — address each
promptly, reply IN-THREAD per comment describing the resolution, then
notify the owner the PR is ready to re-check; never mark a PR ready
with unaddressed owner comments.

## Stacked pull requests

Stacking is sanctioned for dependent work; these rules exist because a
squash-merge repository punishes careless stacks:

- The stacked PR's base is THE BRANCH IT STACKS ON, so its diff shows
  only the increment.
- A stacked PR STAYS DRAFT UNTIL ITS BASE MERGES. Squashing a stacked
  PR before its base would duplicate the base's entire content into
  `main`.
- When the base merges: `git fetch --prune`; rebase the stacked branch
  onto `main` under the pinned identity environment (the committer
  rewrite above); re-run the full gate on the rebased head; then
  `git push --force-with-lease` to YOUR OWN single-writer branch — the
  sole force-push an agent ever performs (CI's force-update of the
  generated `badges` branch is machinery's own documented exception).
  GitHub retargets the PR to `main` automatically; verify the retarget
  and the residual diff yourself.
- One writer per branch, always, and remote truth is checked directly —
  `gh pr view`, `git ls-remote` — never assumed from another agent's
  report.

## Quality gates — exact commands and patterns

The full local gate, in order, before every push — docs-only diffs
included; it is the same battery CI enforces:

    cd frontend && npm ci --ignore-scripts --no-audit --no-fund && \
      npm run check && npm test && npm run build && cd ..
    test -z "$(gofmt -l .)"
    go vet ./...
    CGO_ENABLED=0 go test ./...
    go test -race ./...
    helm lint chart && helm template smoke chart \
      --kube-version v1.36.0                    # chart changes
    docker build .                              # Dockerfile/build-input changes
    gitleaks git --no-banner --redact --max-target-megabytes=2 .
    gitleaks dir --no-banner --redact .

- **Coverage floor.** `GO_COVERAGE_FLOOR` is 95.0 (measured 97.6 when
  last raised), enforced in `.github/workflows/pr-gate.yml` on total
  production statements with `internal/testsupport` filtered from the
  profile — the ONLY exclusion, and it may never grow to cover
  production packages. Ratchet only (requirement 7).
- **Perf budgets are tests.** Payload and bundle caps ship as pinned
  suite assertions, so a budget regression is a red build, never a
  discussion. Two batteries exist: `internal/web` measures the REAL
  built artifact (every themed shell variant, each content-addressed
  asset, the whole embedded bundle), and
  `frontend/tests/experience.test.mjs` caps shell SOURCE size. Every
  surface the feature arcs add lands WITH its caps pinned the same way.
  Caps ratchet DOWN as payloads are trimmed; raising one to admit a
  regression on an UNCHANGED surface is the move the budget exists to
  prevent and stays forbidden. The one sanctioned exception: a PR that
  adds a new surface may raise that surface's cap to its newly measured
  size plus working room, because the old cap measured a shell that no
  longer exists. Such a raise is not silent — the PR body states the old
  cap, the new cap, and the measured size, so a reviewer can check the
  headroom is working room and not cover for a regression. The values are
  derived from this repository's own measurements and are never copied
  from elsewhere (requirement 5).
- **Ratchet pairs.** When a stated requirement and shipped behavior
  disagree across lanes, record the gap loudly instead of greenwashing
  it: one green test pins current behavior, and a paired
  expected-failure test asserts the pending contract, flipping the
  suite red the day the implementation tightens — which forces the
  marker's removal and turns the note into an enforced rule. The
  canonical exemplar lives in the platform repository
  (`tests/security/test_containerd_cri_health_contract_matrix.py`); Go
  suites here express the same pair as a behavior pin plus a named
  pending-contract test documented in its comment.
- **Secret scan, both modes.** `gitleaks git` (full history) AND
  `gitleaks dir` (working tree) run before every push — the same scans
  CI runs. This repository keeps no `.gitleaksignore` today; if a
  verified false positive in already-pushed history ever requires one,
  the entry is a commit-scoped fingerprint (`commit:file:rule:line`)
  with an in-file justification, and the working tree must always scan
  clean WITHOUT it. Never allowlist to make new content pass.
- **Flake probe.** Before a PR leaves draft the full suite has run at
  least three times (author and reviewer independently); any
  nondeterminism is a finding naming the test.

## CI map

- **pr-gate.yml** — pull requests AND pushes to `main` (plus manual
  dispatch): `security` (checksum-verified tool install, actionlint,
  `gitleaks git` over full history, `gitleaks dir`),
  `dependency-review` (PRs only; fails on high severity), `application`
  (toolchain pinned AND verified — Node 24.19.0, npm 11.17.0,
  Go 1.26.5; frontend check/test/build; gofmt/vet/tests/race; the
  coverage floor), `chart` (helm lint + render at
  `--kube-version v1.36.0`; the VERSION ↔ chart `version` ↔
  `appVersion` three-way lock), `container` (both production
  architectures built, never published).
- **coverage-badges** — `main` pushes only: recomputes the Go coverage
  and the frontend test tally with the gate's own recipes and
  force-updates the generated single-commit `badges` branch
  (`go-coverage.json`, `frontend-tests.json`). Badge numbers are
  CI-computed, never hand-edited; the badge publishes the identical
  number the gate enforced.
- **codeql.yml** — pull requests, `main` pushes, weekly cron.
- **release-publisher.yml** — version tags only; no manual dispatch, no
  skip flag, no force path (requirement 10).
- **Zero-spend guardrails.** Workflows declare top-level
  `permissions: {}` with narrow per-job read grants;
  `persist-credentials: false` on every checkout; GitHub-hosted
  `ubuntu-24.04` runners only; every action pinned to a full commit SHA
  with a version comment; third-party tools installed only through the
  checksum-verifying `scripts/ci/install-tools.sh`. No external service
  ever receives repository content or measurements — the self-hosted
  badge pipeline exists precisely so no coverage processor does.

## Frontend and UX floors

Owner directives (2026-08-11) for both site repositories; each
implements them independently — patterns may rhyme, but code, values,
and tests re-derive per repository (requirement 5). The current
placeholder shell predates these floors; they are the bar for every new
or changed frontend surface, retrofitted by the rendering-lanes arc
(issue #22):

- **Design tokens only.** `styles.css` is a CSS custom-property token
  layer: palette and spacing live as tokens on `:root`, theme overrides
  are `[data-theme]` blocks, and components consume tokens — never raw
  palette literals. Frontend tests enforce all three: colour literals
  may appear only in the palette block, every theme must define the same
  token set, and both palettes are VALIDATED (not asserted) against
  WCAG 2.2 contrast floors — 4.5:1 for text pairs, 3:1 for interface
  boundaries.
- **Dataviz floors.** A value is never encoded by color alone: pair
  color with position, text, or shape, and use palettes validated for
  contrast under every theme.
- **Rendering lanes, stage 1** (issue #22; static cross-browser floors
  pinned by frontend tests — iPhone/Android plus
  Safari/Chrome/Firefox/Edge): viewport meta with safe-area-inset
  padding; touch targets ≥ 44px; input font-size ≥ 16px; `svh`/`dvh`,
  never `100vh`; `@supports` fallbacks so layouts degrade gracefully;
  no horizontal body scroll at ≥ 320px (wide content scrolls inside its
  own container); `prefers-reduced-motion` respected; autoplaying
  video, when it ever arrives, is `playsinline` and muted. Stage 2 —
  browser-emulated smoke lanes in CI — is an owner decision, gated in
  that issue.
- **Reading themes.** The site serves one shell per theme in
  `internal/theme`'s catalog (`system`, `light`, `dark`), each stamped
  with its `data-theme` attribute during `NewSite` and chosen per request
  by the `lidersea_theme` cookie. The invariants, each pinned by tests:
  the origin NEVER sets a cookie (the browser writes the preference, the
  origin only reads it); an absent, unknown, oversized, or hostile cookie
  value resolves to the default theme and never reaches a document; the
  shell — and only the shell — answers `Vary: Cookie`, so each variant is
  its own cached resource with its own digest ETag; and a bundle whose
  document cannot be stamped fails construction rather than serving an
  unthemed page. Adding a theme means adding a catalog entry, its
  `[data-theme]` token block, and its switcher option; nothing else
  changes.
- **Zero CLS.** Theme switches and async data arrivals cause no layout
  shift; space for late content is reserved up front. The theme rule is
  mechanical rather than aspirational: every `[data-theme]` block and the
  `prefers-color-scheme` mapping may declare CUSTOM PROPERTIES ONLY, so a
  theme can change colour and nothing that occupies space — a frontend
  test fails on any other declaration in those blocks. The static shell
  reserves the chrome the mounted switcher fills, so hydration adds a
  control without moving the page.
- **Third-party ratings, first-party markup.** The footer ratings strip
  renders platform ratings with THIS site's own markup and CSS. No
  third-party script, widget, iframe, embed, or image is ever used —
  which is exactly why the CSP can stay as strict as it is — and the
  values arrive as data from this origin's own `ratings/v1` surface, so
  no remote origin appears in shell source. Outbound profile links carry
  `rel="noopener noreferrer"`, open in a new tab, and state that in their
  accessible name. Every value is paired with text and shape (the numeric
  rating, a length meter, the review count), never colour alone, and a
  platform with no captured rating says so rather than showing a zero.
- **Honest states.** Empty, loading, disabled, and unavailable states
  tell the truth: a missing backend renders an explicit unavailable
  state — an honest "storage not configured" answer, never fabricated
  data, placeholder reviews passed off as real, or a pretend success
  path.

## Security invariants beyond the numbered requirements

- **GET/HEAD-only origin.** Every route — site and probes — enforces
  the read-only contract: `allowReadMethod` answers anything else with
  405 and `Allow: GET, HEAD`, `TestNoRequestMethodCanEverMutate` sweeps
  the mutation methods across routes, and the CSP's `form-action
  'none'` closes the browser-side path.
- **Gated outbound reads.** The ratings collector
  (`internal/ratings/collect`) is the origin's only outbound capability and
  ships OFF: the zero-value configuration collects nothing, the shipped
  snapshot declares no feed URLs, and the cluster denies egress by default,
  so enabling it is an explicit decision on three independent axes. Its
  safety properties are fixed in code and reachable from no configuration
  and no data file — https only, the per-platform host allowlist re-checked
  at call time, redirects REFUSED rather than followed, a hard body cap, a
  JSON content-type requirement, a strict decode, bounded
  connect/handshake/request timeouts, and a final pass of the whole result
  through the same validation the shipped data file must satisfy. Every
  pass is snapshot-first and fail-soft: a platform that cannot be read
  keeps the value it already had, so no failure mode can blank a published
  rating. Widening the allowlist is a reviewed code change, never an
  environment or data edit.
- **Gated write carve-outs.** Any write path (the reviews and estimates
  surfaces) ships contract-DEFINED but DISABLED: the capability sits
  behind an explicit environment flag whose default is off, the default
  build keeps the GET/HEAD contract and CSP byte-intact, and the
  enabled mode is a narrow, documented carve-out — that path only,
  strict validation, size caps, honest unavailability until persistence
  exists — asserted by its own explicit test variant. Enabling a write
  path is an owner decision, never drift.

## Docs and attribution conventions

- **CHANGELOG discipline.** Keep a Changelog format; SemVer matching
  image/chart tags exactly; the entry lands under `[Unreleased]` in the
  SAME PR as the change it describes, and the release PR moves it under
  the version heading. Release dates are owner-local dates.
- **Truthful README.** Badges and claims report only what CI actually
  measured or the repository can demonstrate — the badges publish the
  gate's own numbers, and prose never advertises a capability or
  deployment state that does not exist yet.
- **Attribution for third-party assets.** No third-party creative
  assets exist here today. Any that arrive land with their reviewed
  license alongside the asset, and IP used under a fan or brand policy
  carries that policy's exact required notice, pinned by a frontend
  test wherever it renders (the sibling repository's Jagex Fan Content
  Policy notice is the model).
