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
   mechanics"; know CI's pinned toolchain (Go 1.26.6, Node 24.19.0,
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
   `main`; the repository owner alone merges. An agent must NEVER merge, auto-merge, squash,
   rebase into, or push `main`; must never force-push or delete refs; and must
   stop and question even a later request to do so. Tags exist only through
   the release workflow.
3. **Commit-metadata privacy and attribution.** Commits are authored AND
   committed as the owner's GitHub noreply identity (both fields). No
   co-author trailers. Agent-authored commit messages and PR bodies end
   with the ACTING agent's own signature — never a fixed lane — exactly
   matching its agent label from the roster in "Agent labels" below
   (`- Fable5` ↔ `fable5`, `- Sonnet5` ↔ `sonnet5`, `- Opus5` ↔ `opus5`,
   `- 5.6 Sol` ↔ `5.6-sol`). The original single-signer rule (every agent
   PR signed `- Fable5`, owner attribution decision 2026-08-10) is
   superseded by the owner's model-tiering directive (2026-08-18), which
   routes work across parallel Sonnet5/Opus5/5.6-Sol/Fable5 lanes by task
   tier; merged precedent #53 (signed `- Sonnet5`, owner-merged the same
   day) already follows the per-lane rule.
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
10. **Every artifact merge releases after the server gate; deploy remains
    separate.** Every PR whose range touches any artifact surface advances
    exactly one patch from its current protected base across numeric
    `VERSION`, chart `version`, `appVersion`, changelog `X.Y.Z`, and plain-v
    image alias. A range whose every commit is individually confined to the
    closed documentation allowlist — root `AGENTS.md`, `README.md`,
    `.gitignore`, and Markdown files under `docs/` — classifies no-artifact:
    it advances nothing, and the orchestrator re-derives that class from git,
    re-proves the whole retained-tag-to-head gap as documentation, and skips
    the publisher with an explicit logged verdict instead of dispatching it.
    Removing the release from a documentation-only merge weakens nothing:
    the artifact is unchanged, so there is nothing to version, sign, scan,
    or attest. The classifier has exactly two verdicts and no flag,
    environment variable, or configuration input; a non-allowlisted path
    with an unchanged version, a mixed range without its one exact patch,
    an unparseable diff entry, or a non-regular file mode all deny; renames
    decompose into add plus delete, so a rename crossing the allowlist
    boundary denies through its non-allowlisted side. Widening the allowlist
    is itself an artifact-classified gate change that releases. PR, protected-main,
    and recovery validation inspect every intermediate state: retain or advance
    one patch only; skip, reversion, transient future, or multiple integration
    boundaries are denied. Successful main CI binds one exact-SHA,
    noncancelling path: the paginated PR-gate inventory requires five success
    conclusions plus the explicit push-only dependency-review skip, and the
    separate same-SHA CodeQL run requires both analyze jobs to succeed. Before
    tag/registry/signing/Release effects, separate
    `platform-release` jobs use only a repository-scoped
    Administration-read-only App token for authoritative settings GETs; they
    expose no token output, and ordinary `GITHUB_TOKEN` is the sole mutation
    credential. Before registry effects, the dotted repository
    `snaraj/lidersea.com` binds only to the explicit, non-derived packages
    `ghcr.io/snaraj/lidersea-com` and
    `ghcr.io/snaraj/charts/lidersea-com`. New Releases carry one canonical mode-0600
    `release-manifest.json` identity asset and must report `immutable: true`;
    both Release author and sole asset uploader are the canonical
    `github-actions[bot]` ID `41898282`; notes are informational, and the terminal step rebinds the annotated tag
    records. Registry version tags are mutable aliases—both intended aliases
    are re-resolved after push, before manifest staging, and before immutable
    publication; only their manifest-bound digests are immutable artifact
    identities. Exact non-null, signed amd64/arm64 SPDX payloads are mandatory
    for new, reused, and audited images. Final-digest HIGH/CRITICAL
    scanning and the scheduled read-only digest/signature/SBOM/provenance/chart
    audit are mandatory. The automatic-release PR remains Draft until the
    external closed receipt in `docs/release-governance.md` is exact. There is
    no skip, force, credential-crossover, deployment, or promotion path.
11. **No secrets, no personal data.** No credential, token, private host
    fact, or personal data ever enters this repository — including in
    tests, fixtures, and docs.

### Deployment-provider contract

The origin speaks standard HTTP (RFC 9110/9111) only. Ingress, DNS, edge,
and access are injected deployment concerns and never appear in application
code, frontend source, or chart templates. Provider names live exclusively
in the chart's values defaults — `ingress.peerNamespace`,
`ingress.peerAppName`, and `ingress.peerInstance` in `chart/values.yaml`,
the single binding point the NetworkPolicy consumes — so a provider swap is
a values override, never a template or code edit. The pin test
(`internal/doctrine/provider_neutrality_test.go`) enforces this, failing
closed on any provider name under `cmd/`, `internal/`, `frontend/src/`, or
`chart/templates/`; in reduced build contexts an absent tree is a stated
capability skip, never a pass, and the full-checkout gate enforces every
tree on every PR.

It takes all three facts to name one peer, and the instance is the
load-bearing one: the peer namespace is shared by several per-site
connectors that publish the same app name and are separated only by
`app.kubernetes.io/instance`, so a namespace + app selector admits every
connector deployed there. `values.schema.json` requires the instance
non-empty — blank or absent fails validation rather than rendering a wide
policy — and `scripts/ci/chart-ingress-pin.sh` renders the chart and proves
the pin holds: the default render, the refusal of an unpinned instance, and
the demonstration that the instance is what separates one connector from
another.

### Release-lock closure

Requirement 10's one-patch advance touches a CLOSED set of four locations,
every one bumped in the same commit:

1. `VERSION` — the numeric `X.Y.Z`.
2. `chart/Chart.yaml` — both `version` and `appVersion`, numeric, matching (1).
3. `chart/values.yaml` — `image.tag`, plain `vX.Y.Z`, matching (1).
4. `CHANGELOG.md` — a new `## [X.Y.Z] - <ISO date>` heading immediately
   after the empty `## [Unreleased]` heading.

CI proves all four mechanically: the `chart` job's numeric `VERSION` ↔
numeric chart `version` ↔ numeric `appVersion` ↔ plain-v `image.tag`
four-way lock, plus `test_release_contract.py`'s own changelog-format
assertions over the same four files. The set used to hold a fifth
location — a hand-advanced tag literal inside `GovernanceReceiptTests`'
live-snapshot assertion — retired because a literal inside the checker is
the one lock the checker cannot enforce on itself: it broke PR #53's
first head as a bare assertion diff rather than a `DENY:` message. The
pin is now derived from the raw bytes of `VERSION` behind a strict
full-match on `X.Y.Z` plus exactly one trailing newline, so the assertion
still refuses an internally inconsistent snapshot, a malformed `VERSION`,
and any parse-normalization drift between the file bytes and the computed
tag — while the value that used to be hand-advanced can no longer be
missed. A PR that advances the release bumps all four in the same commit,
never three.

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
3. `helm lint chart && helm template smoke chart --kube-version v1.36.0`,
   then `./scripts/ci/chart-ingress-pin.sh`, for chart changes (the chart
   requires the platform's Kubernetes target; plain `helm template`
   defaults to older capabilities).
4. `docker build .` when the Dockerfile or build inputs change.

Releases: every artifact-classified PR advances numeric `VERSION`, chart
`version`, `appVersion`, and changelog `X.Y.Z`, plus plain `vX.Y.Z`
`image.tag`, by exactly one patch from its current protected base; a
documentation-only range (requirement 10's closed allowlist) advances nothing
and skips release orchestration entirely. Every intermediate commit retains
the current version or advances one patch. Successful main CI creates the annotated Git tag
at the exact merged SHA and explicitly dispatches the protected-main publisher
with that successful run's ID. The read-only authorization job verifies the
exact run/repository/workflow/event/conclusion/branch/SHA. Separate
environment-gated settings jobs use the pinned App action and step-local
Administration-read token before any side effect; no token crosses into the
write/packages/OIDC job. The Release's sole machine identity is canonical
`release-manifest.json`; its Release author and sole asset uploader must be the
canonical workflow bot. Human notes are not identity. The production repository
and both image/chart package paths are explicit closed identities, never a
lossy dot-to-hyphen derivation. Image `vX.Y.Z` and Helm
`X.Y.Z` tags are mutable registry aliases, while their recorded digests are
immutable and signed. Histories and annotated Git tags are append-only; stale
concurrent PRs resync and take the new next patch. Deployment resolves digests,
never aliases. A failed/unknown external receipt leaves the PR Draft and grants
no permission to create credentials, change settings, or merge.
The rendered image reference carries both —
`repository:vX.Y.Z@sha256:<hex>` — so a Pod states which release
it is, while only the digest selects the bytes and only the digest is signed,
attested, and verified at admission (requirement 10).

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

**Exact-head receipt.** Review identity is textual because agents share the
owner's GitHub account; it is not a claim of separate GitHub principals. The
reviewer posts one normal PR comment using this complete shape, with exactly one
mutation audit, exactly one claim audit, and the signature as the final nonblank
line (numbered findings or explicit no-finding scope may appear between them):

```text
HEAD: <40-lowercase-hex>
VERDICT: APPROVE | REQUEST-CHANGES
Mutation audit: <mutants attempted and killed, or explicit no-finding scope>
Claim audit: <SUPPORTED / OVERSTATED results for every material claim>
- <distinct context> (adversarial reviewer)
```

Replace every placeholder with concrete evidence; the displayed shape itself
must validate after substitution. Any head change invalidates the receipt. The
author replies with reproduction and repair evidence; a fresh independent
context re-reviews the new exact head. If the owner merges first, record a
post-merge audit and classify—not erase—the gap.

**Main Worker receipt.** After author completion, exact-head CI, settings, and
base freshness have been evaluated, the Main Worker posts one bounded normal
comment containing exactly these five nonblank lines (with one concrete verdict
and a distinct context signature):

    HEAD: <40-lowercase-hex>
    ROLE: MAIN-WORKER
    VERDICT: PASS | BLOCK
    SCOPE: architecture,merge-order,authority,settings,base-freshness,required-checks
    - <distinct context> (Main Worker)

Any head change invalidates it. `PASS` is evidence for the coordinator, never
review, Ready, settings, merge, or release authority.

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

**Verdict format** — posted as a normal PR comment, so every vendor and the
owner see the identical record: exact `HEAD`, exact `VERDICT`, numbered
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
  alongside its PR; PRs use an exact standalone `Closes #N` line for an issue
  in the same repository so GitHub closes it only when the owner merges.
  Feature intake lands as a `features`-labeled issue with the architectural
  constraints stated, even when implementation waits.
- **Labels.** One taxonomy, identical names/colors/meanings across all
  three repositories: `production-readiness`, `conventions`, `security`,
  `tests`, `ci`, `docs`, `release`, `fix`, `provider-neutrality`,
  `delivery-lane`, `features`, `requires-review`. New labels are added to
  all three at once.
- **`requires-review` — the review-readiness signal.** `requires-review` is
  PR-head-only. The author lane applies `requires-review` only when the exact PR
  head, body, commits, and evidence are author-complete, so review attention is
  productive. Its ABSENCE on an open agent-authored PR means the PR is still in
  flight: reviewers and other lanes must not spend review effort on it. The
  reviewer removes it when posting either verdict; on REQUEST-CHANGES the
  author re-applies it only after the complete replacement head is pushed.
  Never apply or interpret `requires-review` on an issue: an issue has no head
  and cannot satisfy an exact-head receipt or Ready gate. Use an explicit normal
  comment for issue-spec review; treat legacy issue uses as coordinator cleanup
  residue. The label is a coordination signal only: never a substitute for
  draft/ready state, for the APPROVE verdict that flips a PR ready, or for owner
  merge authority.
- **Agent labels.** Every agent-created PR and issue carries TWO further
  labels: the umbrella `agent-authored` AND the acting agent's own label —
  `fable5` (Claude Fable 5), `5.6-sol` (ChatGPT 5.6 SOL ULTRA), `opus5`
  (Claude Opus 5), `opus4.8` (Claude Opus 4.8), `sonnet5` (Claude Sonnet 5).
  The body signature must match the label (`- Fable5` ↔ `fable5`), and
  adversarial-review verdicts carry the same identity as `- <Agent>
  (adversarial reviewer)`.
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
  the owner merges by squash or rebase. The release contract accepts either
  the one-commit squash range or a multi-commit rebase range and binds one
  release to its exact final tree. Branches auto-delete on merge; stale local
  branches are pruned as work lands. History is append-only and never rewritten.
- **Commits.** Detailed bodies to the review protocol's evidence standard —
  problem, mechanism, enumerated changes, evidence — signed per lane.
- **Dependabot.** Dependency PRs obey the same issue/milestone/assignee,
  next-patch, changelog, exact-head review, CI, and base-freshness controls.
  Infrastructure/tool outages are reported as infrastructure failures; they do
  not waive a real product failure or justify lowering this repository's
  coverage floor. A version-locked pair Dependabot splits across separate PRs
  (`github/codeql-action` init+analyze; `svelte`+`svelte-check`) is superseded
  by ONE agent PR bundling both bumps plus the root-cause `groups:` stanza in
  `.github/dependabot.yml`, in the same commit, so the pair stops arriving as
  mutually-blocking PRs (merged precedents #53, #55).
- **Merge readiness.** Draft remains Draft until every check is successful at
  the exact head, the base equals current protected `main`, all discussions and
  findings are resolved, a fresh exact-head APPROVE receipt exists, a fresh
  exact-head canonical `ROLE: MAIN-WORKER` / `VERDICT: PASS` receipt exists, the
  next patch still follows that base, the automatic release consequence is
  proven, and the owner-observed release-control receipt proves immutable
  releases plus strict exact required checks with no bypass. Only the
  coordinator flips Ready. The author and reviewer never do.

## Parallel agents in one checkout

Several agents — different models and vendors, executors and reviewers — work
this repository at once, sometimes on one machine. Git worktrees are the
isolation mechanism, and these rules are part of the contract: they bind every
lane whether or not any vendor-specific tooling is present.

- **The shared checkout is nobody's workspace.** It stays on `main`, clean, and
  is used only for coordination — `git fetch`, worktree creation and removal,
  ceremony reads. No agent builds, edits, or checks out a branch there. It may
  lag `origin/main` harmlessly: every actor works from `origin/main` after its
  own `git fetch origin`, never from a local `main`.
- **One worktree per acting context, named for its lane.** Executors run
  `git worktree add .claude/worktrees/<lane>-<topic> -b <lane>/<topic>
  origin/main`. The directory and the branch carry the SAME lane, because the
  cleanup rule below depends on ownership being legible to every other agent.
  A worktree whose name and branch disagree, or a branch with no lane prefix,
  is a contract violation.
- **Reviewers work disposably.** A detached-HEAD worktree at the exact pull
  request head (`git worktree add .claude/worktrees/<lane>-review-<PR#>
  <headSHA>`), removed once the receipt posts. A reviewer stays read-only
  toward every other workspace and reverts every experiment inside its own.
- **One writer per branch, one branch per worktree.** A worktree that is not
  yours is a worktree you never write to. Treat reads with care: a tree that
  advances under you mid-operation is a live executor, not stale state.
- **Some git state is shared — that is the trap.** HEAD, index, and working
  tree are per-worktree; refs, remotes, config, and stash are repository-wide.
  So `git fetch`, `git branch -d/-D`, and `git worktree prune` act on every lane
  at once: run them only from the main checkout during deliberate cleanup,
  never mid-task. Never `git config` anything — identity is env-pinned per
  command per "Commit identity mechanics", and one lane's config write poisons
  all of them. A branch checked out in any worktree cannot be deleted or
  checked out elsewhere; that lock marks live ownership.
- **Clean only your own lane, and only after the owner merges.** Confirm the
  merge against the remote, then remove your worktree and delete your branch
  from the main checkout with `git worktree remove` and `git branch -d` — no
  `--force`, no `-D`. Those refusals are the safety net: a dirty tree or an
  unmerged branch is somebody's live work, very possibly another lane running
  right now. Another lane's leftovers are that lane's to remove.
- **Shared machines contend.** Heavy suites in several worktrees compete for CPU
  and load-sensitive tests can flake under contention. Treat a contention flake
  as an environment finding — name it, rerun it, never weaken the test — and
  stagger the heaviest batteries when many lanes run at once.

## Working a change end to end

The complete delivery loop, each step gated by the sections around it:

1. **Claim the work.** File (or take) the issue; state intent and
   constraints. Label it — including both agent labels — assign the
   owner, set a milestone. Never apply or interpret `requires-review` on the
   issue; request any issue-spec review through an explicit normal comment.
2. **Branch from `origin/main`** after `git fetch origin`; branch names
   are lane-prefixed (`<lane>/<topic>`, e.g. `fable5/<topic>`,
   `sonnet5/<topic>`, `opus5/<topic>`, `5.6-sol/<topic>`). One writer per
   branch, always —
   a branch that is not yours is a branch you never push to. Reserve the exact
   next patch from that base; if another PR lands, create a fresh branch from
   current main, carry the still-valid diff without rewriting published
   history, take the new next patch, and close/supersede the stale PR.
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
7. **Obtain the Main Worker receipt.** After the author tree and exact-head
   adversarial verdict are final, a distinct Main Worker runs the bounded
   canonical check defined above and posts its exact-head PASS comment. A
   later push invalidates both exact-head receipts.
8. **Prove server release controls.** For an automatic-release change, the
   repository owner runs the GET-only preflight in
   `docs/release-governance.md`; immutable releases, strict current-base
   required checks, and the no-bypass ruleset must be exact before Ready.
9. **Owner comments** are handled per the owner review protocol below.
10. **The owner merges.** Nothing you can do — approval, green checks,
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

- EVERY authorized commit runs under the same pinned environment. Agents do
  not amend, rebase, cherry-pick onto a published branch, or rewrite history;
  use additive commits or a fresh branch from current main.
- No `Co-Authored-By` trailers, ever. Agent-authored commit bodies, PR
  bodies, and issue bodies end with the acting agent's own signature —
  never a fixed lane — matching its agent label per the roster mapping in
  requirement 3.
- Agent commits are SSH-signed per command with the owner-registered Mac
  key, never via `git config`:

      git -c gpg.format=ssh \
          -c user.signingkey="key::$(ssh-add -L | grep ssh-ed25519)" \
          commit -S ...

  The key was registered 2026-08-18; agent commits show `Verified` on
  GitHub. Main-only merge enforcement (requirement 2) is what keeps the
  owner's phone and other-machine merges unblocked — signing is a
  commit-level property, not a branch-protection identity gate.
- Treat the Git index as public (requirement 11): no hostname, IP
  address, machine or account identifier, username, workspace path,
  token, or private operational fact enters any commit, message,
  fixture, or doc — what reaches history cannot be unpublished.

## Owner review protocol

Comments the owner leaves on PRs ARE code reviews — address each
promptly, reply IN-THREAD per comment describing the resolution, then
notify the owner the PR is ready to re-check; never mark a PR ready
with unaddressed owner comments.

## Dependent pull requests

Dependent work may be described as a merge order, but every eventual PR to
protected main must independently carry its next patch release. Keep a
dependent PR Draft until its predecessor lands. Then fetch current main, create
a fresh branch without force/rebase, port only the residual diff, allocate the
new exact patch, rerun every gate, open a replacement Draft PR, and obtain a
fresh exact-head review. Never retarget or merge a dependency stack in a way
that duplicates predecessor content.

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
    ./scripts/ci/chart-ingress-pin.sh           # chart changes
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
  `gitleaks git` over full history, `gitleaks dir`, HIGH/CRITICAL source
  dependency and repository-configuration gates; the filesystem scan pins
  `--include-dev-deps` and proves every direct frontend build dependency is in
  its report),
  `dependency-review` (PRs only; fails on high severity), `application`
  (toolchain pinned AND verified — Node 24.19.0, npm 11.17.0,
  Go 1.26.6; frontend check/test/build; gofmt/vet/tests/race; the
  coverage floor), `chart` (the ingress peer-identity pin,
  `scripts/ci/chart-ingress-pin.sh`; helm lint + render at
  `--kube-version v1.36.0`; the numeric VERSION ↔ numeric chart `version` ↔
  numeric `appVersion` ↔ plain-v chart `image.tag` four-way lock, plus a render
  assertion that the emitted reference still carries a full digest),
  `container` (both production
  architectures built, never published).
- **coverage-badges** — `main` pushes only: recomputes the Go coverage
  and the frontend test tally with the gate's own recipes and
  force-updates the generated single-commit `badges` branch
  (`go-coverage.json`, `frontend-tests.json`). Badge numbers are
  CI-computed, never hand-edited; the badge publishes the identical
  number the gate enforced.
- **codeql.yml** — pull requests, `main` pushes, weekly cron.
- **release-after-main.yml** — success-only exact-SHA main-CI completion;
  its separate `platform-release` job uses only the isolated settings token and
  must pass before the ordinary-token job paginates and validates the exact
  PR-gate job inventory, boundedly waits for the separate same-SHA CodeQL run
  and its two successful analyze jobs, creates/verifies the annotated tag, and
  dispatches the publisher on protected `main` with both completed-run IDs.
  Recovery validates the full intermediate history. Distinct main SHAs
  share no cancellation group.
- **release-publisher.yml** — explicit dispatch on protected `main`; a
  read-only authorization job GETs and validates both exact successful
  aggregate runs and their paginated PR-gate/CodeQL job inventories, then a
  separate environment-gated Administration-read-only App job
  rechecks live settings. Only after both succeed can ordinary `GITHUB_TOKEN`
  publish/sign. Its first binding also validates the exact dotted production
  repository and both explicit hyphenated package destinations before registry
  effects. The final digest scan, bot-authored/bot-uploaded sole canonical manifest asset,
  draft/upload/publish state machine, and unconditional terminal REST tag
  rebind are load-bearing; manual/unmerged dispatch, skip, force, clobber, or
  token crossover cannot publish (requirement 10).
- **release-integrity-audit.yml** — scheduled/manual read-only audit of the
  latest immutable manifest: annotated tag/source, mutable registry alias to
  immutable digest bindings, image/chart signatures, exact two-platform signed
  SPDX SBOM payloads and provenance attestations, chart digest, and HIGH/CRITICAL image-digest
  rescan. It has no signing, package-write, Release-write, or build path.
- **GitHub event basis.** GitHub documents that `GITHUB_TOKEN`-created refs
  suppress recursive workflow events except explicit dispatch, that
  `workflow_run` fires regardless of conclusion and uses default-branch
  context, and that concurrency ordering is not a release ledger. Therefore
  the success check, payload `head_sha`, protected-main dispatch with the
  completed-run ID, and independent per-SHA paths are load-bearing. See
  <https://docs.github.com/en/actions/concepts/security/github_token>,
  <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run>,
  and <https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency>.
- **Zero-spend guardrails.** Workflows declare top-level
  `permissions: {}` with narrow per-job read grants;
  `persist-credentials: false` on every checkout; GitHub-hosted
  `ubuntu-24.04` runners only; every job has a positive timeout; PR concurrency
  may cancel only the superseded run for that PR while main uses exact-SHA,
  noncancelling groups; every action is pinned to a full commit SHA
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

- **CHANGELOG discipline.** Keep a Changelog format; every artifact-classified
  PR immediately follows an empty `[Unreleased]` heading with its exact
  next-version and ISO date, matching every source lock; a documentation-only
  PR leaves `CHANGELOG.md` untouched (the file sits outside the documentation
  allowlist precisely so a no-release range can never claim one). There is no
  later release PR; dates are owner-local dates.
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
