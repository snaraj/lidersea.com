# Changelog

All notable changes to lidersea.com. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `VERSION`, chart
metadata, these headings, and Helm's strict OCI chart tag use numeric SemVer.
Git, image, and GitHub Release tags use the exact plain `vX.Y.Z` form.

## [Unreleased]

## [0.1.40] - 2026-08-28

### Changed

- The ratings meter's fill now clears WCAG 2.2's 3:1 non-text contrast floor
  against its own track, and both meter boundaries join the palette contrast
  sweep instead of sitting outside it as a documented exclusion. The fill was
  `--accent` painted onto the `--edge` track, measuring 1.97:1 light, 2.28:1
  sepia and 2.56:1 dark — the boundary that carries the value was the least
  legible edge in the widget. The fill now takes its own `--meter-fill` token:
  `--accent` moved in OKLCH lightness alone until the boundary clears the
  floor, with hue drift under one degree and chroma held wherever the sRGB
  gamut allows, so the bar still reads as the brand colour rather than a
  second one. Measured on the built binary in Chromium at 390px and 1440px in
  every reading mode: fill/track 3.14:1 light, 3.12:1 dark, 3.10:1 sepia. The
  track deliberately keeps `--edge`, so its own contrast against the card is
  unchanged at 3.81/3.18/3.61:1 and the meter's share of the card area is
  unchanged at 3.11% mobile and 1.37% desktop — the fill became more legible
  without becoming larger or heavier.

## [0.1.39] - 2026-08-28

### Changed

- Comment-truth pass across the tree. Every corrected comment made a factual
  claim the code beside it contradicted, so each was load-bearing for the next
  reader's decision and wrong. `internal/server`'s package doc said the handler
  "serves only the embedded frontend and Kubernetes health probes" — it also
  serves `/api/` and, when gated, the media path. `surfaces.go` justified its
  unchanged CSP with "the UI submits gated writes with `fetch()`"; no UI
  submits anything, and the real reason is stronger — `decodeJSONBody` requires
  `application/json`, which no HTML form can emit, so a carve-out is
  unreachable by form submission and `form-action 'none'` never has to move.
  `internal/board` described "the chart's media volume" as documented but
  unwired; the chart declares no media volume at all. `estimates/render` twice
  named a UI print stylesheet and print view that do not exist.
  `internal/server/types.go` credited `New` with validating the entrypoint;
  `NewSite` does. `TestCatalogIsTheClosedSetOfThemes` said "the two explicit
  reading themes" while requiring three.
- `styles.css` claimed a custom-properties-only theme rule is "what makes a
  theme switch incapable of moving a box". The enforcing test checks only the
  `--` prefix, so a theme redefining a spacing token would pass it; the
  no-shift OUTCOME is measured by the browser lane, and the comment now says
  which half is which. The same block said "both themes" where three palettes
  are defined, and the contrast test was named "both palettes".
- The contrast test's "every foreground the shell paints on every background"
  was false: the ratings meter's fill on its own track is a real painted pair
  and is absent. The exclusion is now stated with its reason — the meter is
  `aria-hidden` and repeats a value the number and review count already carry
  in text, so it is not a graphic required to understand the content — and
  records that it does not clear 3:1 today, so promoting it to the sole
  encoding of a value would be a palette decision, not a free change.
- Cross-repository references removed from code and comments (requirement 5):
  a header-cap value said to match the sibling site, a fault-suite header
  written "to be portable verbatim" to it, a path guard described as "shared
  with" it, and an install-script provenance sentence. None was verifiable
  from this repository, which is the point of the requirement.
- `AGENTS.md` said browser-emulated smoke lanes in CI were still an owner
  decision; `browser-smoke.yml` has been shipping them, and the CI map omitted
  the workflow entirely. Both corrected, with the lane's one honest limit
  stated: `npx playwright install` fetches the engine builds itself, so they
  are not checksum-verified the way `scripts/ci/install-tools.sh` verifies
  every other third-party binary. The same file still deferred "introducing a
  media pipeline" as an owner decision while `internal/media` exists; what
  remains deferred is enabling it.
- `SECURITY.md`'s posture bullet described an earlier, simpler binary
  ("embedded static content", "no outbound calls" unqualified). It now names
  the surface API and states that the outbound collector, the media directory,
  and both write carve-outs are separate environment gates whose absence is
  off and whose malformed value fails startup.

### Added

- `codeql.yml`'s concurrency guard carries its rationale. The guard was already
  correct; nothing recorded why it may not be simplified to `true`. The weekly
  cron resolves to the same group as a push run at that SHA, and the release
  orchestrator polls `codeql.yml/runs?branch=main&event=push&head_sha=<merged>`
  while `select_codeql_main_run` accepts only `success` — so a cancelled push
  run leaves the schedule's own `event: schedule` run outside the filter.
- `frontend/playwright.config.mjs` now rejects a port above 65535. The shape
  check admitted `99999`, which is not a port, so the guard's message
  ("must be an unprivileged port number") promised more than it enforced.

### Fixed

- `release-publisher.yml` read the four release locks but only compared three.
  Its fourth line was `test "${tag}" = "v${version}"`, comparing the line above
  it to itself; the lock actually missing there — `image.tag` in
  `chart/values.yaml` — is now the one it reads.
- `commit_identity.py`'s `main()` re-inlined the three statements of `audit()`
  instead of calling it, so the suite exercised a function CI never reached.
  `audit()` now returns the SHAs alongside the findings and is the enforcement
  path.
- `serveBoard` hardcoded the text of `board.ErrUnknownCursor` rather than
  reading the sentinel, so the same message existed twice with nothing linking
  the two.

### Removed

- Dead code and vacuous assertions, each removed and the full gate re-run:
  `_FULL_SHA` in `commit_identity.py` (zero references repository-wide);
  `test "$(basename "${manifest}")" = release-manifest.json` in the publisher
  (basename of a literal path); `expect(parts.length).toBeGreaterThan(0)` in
  the browser lane (`String.split` always returns at least one element);
  `TestIndexReadOnceAtConstruction`, whose subject, fake, and assertions are a
  strict subset of `TestThemedShellsAreStampedOnceAtConstruction` — its
  availability framing moved into the surviving test's comment, and the
  broken-bundle half it also documented stays pinned by
  `TestNewRejectsMissingEntrypoint` and `TestNewRejectsAnUnstampableShell`.
- Resolved-history narration that outlived its subject: a comment in
  `chart_render_census.py` whose entire topic was the edit history of the six
  lines above it; two of three retellings of an empty-table pin that no longer
  exists, leaving the forward-looking rule once in the function that
  implements it; the "main-worker role retired with issue #124" note, replaced
  by what the code does; `at 0.1.37` stamps in `ci_gate_allowlist.toml` that
  re-stale every release; and a suite size ("14 tests") that is now 16, where
  the evidence was "the mutation stayed green" and the count was decoration.
- The 24-line third copy of the egress argument in `pr-gate.yml`, reduced to
  the anti-deletion warning plus a pointer to the two files that make the
  argument in full. Verbose restatements of the code below them, in Go and in
  the frontend tests. And the orphaned "Fail-closed sentinel" sentence in
  `chart/values.yaml`, which sat at the head of the `tag:` comment block while
  describing the `digest:` field two keys below — the one place a reader could
  conclude the release tag was the fail-closed sentinel.

## [0.1.38] - 2026-08-28

### Added

- Released changelog history is now append-only, proved base to head. The only
  changelog edit a release may make is an insertion ABOVE the previously newest
  dated heading: everything from that heading through end of file — every
  shipped section and the undated tail block below them — must survive
  byte-identical. `require_changelog_append_only` in
  `scripts/ci/release_contract.py` reduces the whole property to one byte
  comparison, testing that the base's released history is an exact SUFFIX of
  the head. It is a suffix and not a containment on purpose: a containment
  check keeps every shipped byte satisfied while a forged version block is
  written UNDER the oldest release, and a fabricated release corrupts the
  ledger exactly as much as a deleted one.
- `validate_snapshot` additionally reads ALL the dated headings in one file,
  where before it read the current version's heading and nothing else. A
  duplicate version, a reordered pair, a date that is not a real calendar date,
  a historical date that postdates a newer release, and a newest heading that
  is not the version being released each deny. Those rules constrain shape and
  cannot see a DELETED heading — nothing in one file says what used to be in
  it — which is why the base comparison is the load-bearing half.

### Fixed

- A pull request could silently delete released changelog headings with every
  gate green. `validate_snapshot` validated the changelog by finding exactly
  ONE dated heading for the CURRENT version and asserting it immediately
  followed an empty `## [Unreleased]`; that was the whole changelog check, so
  every heading below the first was unguarded. A range could delete a shipped
  release — one heading, or all of them — reorder two, misdate one, or rewrite
  a historical entry's body, and the four-way release lock, the transition
  contract, the full PR gate, and the publisher all stayed green. The tag
  ledger and the GitHub Releases stayed correct either way, so the damage was a
  silent divergence between the changelog and the real release history. The
  failure mode is a plausible MECHANICAL edit, not a hostile one: an edit
  meaning to insert a new version block above an older heading instead replaced
  the span from `[Unreleased]` down to and including that heading.

### Changed

- `validate_transition` compares the base's `CHANGELOG.md` to the head's, so
  the rule holds on every pull request, every push to `main`, and in recovery:
  `classify_transition`'s artifact branch and `discover_transition_window` both
  route through it. The no-artifact branch already required `CHANGELOG.md`
  byte-identical base to head, which implies append-only, so it gained no
  redundant call.
- Every append-only refusal names the sanctioned repair. Correct a shipped
  entry by writing a NEW erratum entry under the version the range is
  releasing, naming the release it corrects — never by editing the section that
  already shipped. That is the documented lift and it is one line in one pull
  request, so this gate deliberately ships no allowlist table: an entry there
  would be keyed by a released version and no suite could ever prove it stale,
  leaving a permanent hole in exactly the property the gate exists to hold.

## [0.1.37] - 2026-08-26

### Security

- The egress deny is now bound to the workload it governs, closing the half of
  the defect 0.1.36 explicitly did not close. A NetworkPolicy has two
  independent halves: `spec.podSelector` says WHICH Pods it governs, and
  `policyTypes` plus the rule lists say what those Pods may do. Every
  assertion 0.1.36 added reads the second half, so every one of them is
  satisfied by a policy that governs NOTHING. Retarget only the Deployment's
  Pod-template labels — leaving `chart/templates/network-policy.yaml`
  byte-identical — and Kubernetes matches the policy against ZERO Pods. A
  policy that selects no Pod governs nothing, so the running Pods have full
  outbound access, while `helm lint`, `scripts/ci/chart-ingress-pin.sh`, the
  four-way release lock, the provider-neutrality pin AND 0.1.36's own text pin
  and whole-render census all stay green — because the policy's text is
  untouched and perfect. It simply applies to nothing.
- `scripts/ci/chart_render_census.py` therefore gained
  `bind_policy_to_workload`, run as part of the same whole-render census in
  `scripts/ci/chart-egress-pin.sh` assertion (c). It proves the render's one
  Deployment sits in the policy's namespace; that its Pod template carries
  labels the `podSelector` actually matches under Kubernetes' own
  `matchLabels` subset semantics; that the Deployment's own selector matches
  its own template, since Kubernetes refuses a Deployment where it does not
  and a deny proven over zero Pods is not a proof; and that the selector names
  both `app.kubernetes.io/name` and `app.kubernetes.io/instance`, because the
  name alone still matches this workload while additionally governing every
  other release of this chart in the namespace.
- An all-namespace `podSelector: {}` is REFUSED, deliberately and not by
  oversight. For the egress half it is strictly more restrictive — it denies
  more — but it matches this workload for the same reason it matches
  everything, so accepting it would make the binding assertion vacuous on
  exactly the drift it exists to catch; and the same object's ingress
  allow-list would then apply to co-tenant Pods nobody reviewed.
  `matchExpressions` is refused on the module's standing principle: set-based
  selection is not evaluated here, so it is refused with the reason named
  rather than guessed at.
- The whole-render mutation battery grew from 48 to 53, and the battery was
  actually run rather than the floor merely raised: five new mutants rewrite
  the REAL Helm render so the NetworkPolicy document comes out byte-identical
  (or, for the over-selection case, still self-consistent) — Pod-template
  labels retargeted, the instance label dropped from the Pods, the Deployment
  detached from its own template, the workload moved to another namespace, and
  the policy's selector stripped of its instance key. All 53 are refused;
  `chart-egress-pin.sh` assertion (g) pins the floor and
  `test_chart_render_census.py` pins the floor against the battery's real
  size, so neither can drift. The unit suite grew from 145 to 159 tests.

### Added

- A gate proving every subcommand `scripts/ci/release_contract.py` registers
  has a caller (`scripts/ci/test_subcommand_callers.py`). The module registers
  its subcommands with argparse while workflows invoke them by name as opaque
  strings, and nothing connected the two sides: a subcommand could go dead
  while still reading live, or be deleted while a LINE-WRAPPED invocation
  still called it. The gate reads the names from the parser itself — never a
  hand-maintained list, which would drift exactly as the workflows already do
  — and searches the bare token across workflows, scripts, docs and tests, so
  wrapping cannot hide a caller. It reports each caller's TIER: a doc-only
  caller is a real caller (`settings-receipt` is an operator escape hatch
  invoked from `docs/release-governance.md`), while test-only callers and zero
  callers both fail. Both rules are driven by hostile fixtures as well as by
  the live repository: at this head nothing is dead and the allowlist is
  empty, so every live-data assertion would be satisfied just as well by a
  classifier that refused nothing at all. Measured at this head: 33 registered
  subcommands, none dead, none test-only.
- A workflow-integrity gate (`scripts/ci/workflow_integrity.py` and
  `scripts/ci/test_workflow_integrity.py`) refusing three specific constructs
  in `.github/workflows` that every other gate here is blind to:
  `continue-on-error: true` on a job or step of a required check, which makes
  a failed gate report success and satisfies branch protection with a red
  build; a step-level `env:` that captures a pin — either shadowing a
  workflow-level or job-level binding, or rebinding a tool version or checksum
  that `scripts/ci/install-tools.sh` pins — so the step runs a different value
  while the pin still reads correct; and a custom `shell:` on a gate step,
  which changes failure semantics and can drop `pipefail`. The gate-job set is
  derived from `release_contract.py`'s own `REQUIRED_STATUS_CHECKS` and
  `PR_GATE_MAIN_JOBS`, and the protected variables are read out of
  `install-tools.sh`, so both track the repository instead of a copy of it.
  It reads the block-YAML subset workflows use with a stdlib reader
  (requirements 1 and 9 leave no PyYAML) that consumes `run:` bodies opaquely
  — a shell script containing the text `shell:` is not workflow structure —
  and refuses tabs, duplicate keys and ragged indentation rather than
  guessing. Its entrypoint carries a positive control, because "the repository
  is green" is an assertion an audit that returned nothing would satisfy for
  free: the same entrypoint is pointed at a scratch directory holding one
  violating workflow and must report it. It pins NO step inventory, and both
  files argue at length why one must never be added.
- A commit-identity gate (`scripts/ci/commit_identity.py` and
  `scripts/ci/test_commit_identity.py`) closing a surface the enforced secret
  scan structurally could not reach. `gitleaks git` and `gitleaks dir` both
  read BLOB CONTENT; commit author/committer identities and commit message
  bodies are neither, so the two rules requirement 3 states — the owner
  noreply identity in BOTH fields, and no co-author trailer ever — were prose
  with zero mechanical coverage. An agent that forgot to pin
  `GIT_AUTHOR_EMAIL` would have pushed a foreign address past every green
  check, and it would have become permanently public on merge. The gate walks
  the range a pull request PROPOSES and refuses both, with two stated
  non-goals: it is not a history audit, because history is append-only and a
  gate that could only refuse an unfixable past would need a permanently
  growing exemption list; and it does not run on `main` pushes, because the
  owner's merge is stamped with GitHub's own web-flow committer — 59 of
  `main`'s 86 commits would be refused by a history-wide run — and refusing
  that would hold main CI red forever while proving nothing an agent could act
  on. No failure message
  echoes the address it refused, because those messages land in public CI
  logs.
- Five historical exceptions recorded in the allowlist rather than erased: the
  root commit, whose author and committer predate the noreply rule, and four
  onboarding-era squashes carrying five co-author trailers between them. All
  are ancestors of `main`, permanently public, and unrepairable without
  rewriting history from the root, which requirement 2 forbids. They are
  keyed by SHA and never by address — an allowlist keyed by address would copy
  a third party's contact detail into a tracked file, which is exactly what
  requirement 11 exists to prevent — and the suite proves each names a real
  commit that really does break a rule, so an exemption that stopped exempting
  anything would be reported instead of kept.
- A behavioural pin on the gate step's own `if:` guard
  (`TheGateStepRunsOnPullRequestEventsOnly` in
  `scripts/ci/test_commit_identity.py`). The SUITE half of the main-push
  boundary is held by `test_a_push_to_main_proposes_no_range`; the WORKFLOW
  half was held by nothing, so a future edit could delete
  `if: github.event_name == 'pull_request'` from the step and discover the
  consequence only when the owner's next merge turned main red. Both directions
  were measured: with the guard gone, a main push supplies no pull-request
  payload, so the step's range variables expand empty and the module exits 1 on
  a range it cannot read; hand it a real push range instead and it still exits
  1, on GitHub's web-flow committer. The pin selects the step BY THE MODULE IT
  INVOKES and matches the condition by pattern, so steps may be added, renamed,
  reordered or removed and both the bare and `${{ … }}` spellings pass — it is
  behaviour, not a step inventory, and `pull_request_target` does not satisfy
  it. Its failure message states why the guard exists rather than inviting an
  agent to re-record a pin, and it carries no allowlist line on purpose: the
  lift mechanism exists so a gate can stop refusing a construct that turned out
  to be safe, and an entry that switches this guard off is not that. Killed by
  four mutants — guard deleted, guard swapped for a different event test, the
  step reader collapsed to one blob, and the condition pattern widened.
- `scripts/ci/ci_gate_allowlist.toml`, the shared lift mechanism for all three
  gates. Every refusal above is liftable with ONE line carrying a written
  reason, and every failure message names the file and prints the exact line
  to add. An entry with a blank reason fails closed, and a stale entry — one
  whose case has resolved — fails until deleted, so every entry still describes
  a live case. It deliberately does not bound how MANY entries the table holds;
  the Fixed entry below states that trade in full. Seeded EMPTY: at
  this head no subcommand is dead or test-only, and no workflow declares
  `continue-on-error`, a custom `shell:`, or a pin-capturing step `env:`.
  The allowlist is excluded from the subcommand-caller search set for the same
  reason `release_contract.py` is: an exemption NAMES the subcommand it
  exempts, so counting it as a caller would deadlock the lift — the added line
  would hand its own subcommand a script-tier caller, the stale-entry rule
  would demand the line be deleted, and deleting it would trip the zero-caller
  rule again. The full round trip is a test, not an assumption, and so is the
  exclusion each rule depends on.

### Fixed

- The `security` job, which this pull request had held RED at two consecutive
  heads while every local run reported green — a gap that is the point of the
  entry, not a footnote to it. `scripts/ci/test_commit_identity.py` resolved
  `HEAD`, and under a `pull_request` event `actions/checkout` checks out
  `refs/pull/N/merge`: GitHub's synthetic merge of the branch into its base,
  whose committer is GitHub's own web-flow identity. Three assertions therefore
  read that merge commit instead of the branch tip, and this pull request's own
  new commit-identity gate refused it — correctly. Locally `HEAD` *is* the tip,
  so the suite passed on every developer machine. Only the suite was affected:
  the workflow's gate step passes the exact base and head SHAs from the event
  payload and resolves no symbolic name at all.
- The repair does not teach the suite to walk back from a merge ref; it stops
  the suite asking `HEAD` at all. `proposed_range()` reads
  `pull_request.base.sha` and `pull_request.head.sha` from the event payload —
  the SAME two values the workflow's gate step passes to `commit_identity.py` —
  so the suite and the gate judge one identical range and neither depends on
  what the checkout happens to have put at `HEAD`. Nothing regresses if the
  checkout's depth or ref changes later. It fails CLOSED: under a pull request
  an unreadable or incomplete payload raises rather than falling back to
  `HEAD`, because that fall-back is precisely the silent, green, wrong
  behaviour being removed. The module's CLI already took the same position —
  `--base` and `--head` are `required=True` with no default, so the range can
  never be reached by omission.
- Two alternatives were rejected on the record. Teaching `violations()` to ADMIT
  a two-parent commit carrying GitHub's committer would punch a hole in the one
  rule the module exists to enforce, and
  `test_githubs_own_merge_identity_is_not_sanctioned_either` asserts the
  opposite: that identity is out of SCOPE, never sanctioned. The bug was in
  WHICH COMMITS GET READ, not in which identities are allowed, and treating it
  as an identity-allowlist problem would have weakened the gate while appearing
  to fix it. Allowlisting the merge commit by SHA would be stale on the next
  push, since GitHub rebuilds the ref every time.
- A SECOND defect, found while making the range explicit and worse than the
  first: the suite's workflow step carries no `if:` guard, so it also runs on
  pushes to `main` — where `HEAD` is the owner's squash merge under GitHub's
  web-flow identity. A failure count is meaningless without the CHECKOUT SHAPE
  it was measured under, so both shapes are stated rather than one bare figure.
  Under the shape `actions/checkout` with `fetch-depth: 0` actually produces on
  a push to `main` — the branch fetched to `refs/remotes/origin/main` at the
  pushed SHA, so `origin/main` equals `HEAD` and the merge-base range collapses
  to empty — the pre-repair suite fails **2 of 37**, and two further assertions
  pass VACUOUSLY over that empty range. Under a checkout whose `origin/main`
  LAGS `HEAD` the range is non-empty, those two are genuinely reached, and it
  fails **3 of 37** — a different failing SET, not merely one more. An earlier
  draft of this entry gave the bare figure 3 of 37, which is the second shape
  only. The same counts hold on `workflow_dispatch`, a THIRD unguarded event
  this entry did not previously name: `pr-gate.yml` declares that trigger too,
  and the pre-repair suite is red under it in both shapes. Every combination is
  red, so the defect is confirmed either way and only the figure moves — any of
  them would have held main CI permanently red after this pull request
  merged and blocked the release chain, over a commit no pull request can
  repair. The repair keys on "not `pull_request`" rather than on "push", which
  is why it closes the `workflow_dispatch` path in the same stroke. The gate
  STEP was already guarded `if: github.event_name ==
  'pull_request'` for exactly this reason; the suite now honours the same
  boundary, returning no range on any non-pull-request event and skipping the
  real-range assertions with a stated reason rather than auditing a range the
  gate itself declines to audit. A structural `HEAD^2` resolution would NOT
  have fixed this — on a push `HEAD` has one parent, so it resolves to `HEAD`
  and fails identically.
- Proven in a throwaway clone against a hand-built merge ref and a
  GitHub-shaped event payload, in five directions: green on the CI shape (merge
  ref checked out, payload supplying the range); green on a developer checkout
  with no event variables; green with stated skips on a simulated push to
  `main`; RED — naming the offending commit and never the merge ref — when the
  payload's head side really carries a refused commit; and RED on an unreadable
  payload, which is the fail-closed direction.
- Three surviving divergence mutants in `scripts/ci/workflow_integrity.py`.
  `audit()` and `refusable_entries()` are independent loops over
  `_workflow_paths()` that each recompute the gate-job set, and every existing
  fixture pointed the reader at a directory holding ONE file, so reading only
  the first path survived in either half, as did a WIDER gate-job set in one
  half than the other. That last one is a fail-open on gate SCOPE. A
  three-file fixture — one file per rule, plus a non-gate job declaring the
  same construct a gate job is refused for — kills all three: the two halves
  must name exactly the same entries, and neither may name the non-gate job.
  The non-gate job is what makes it a scope pin rather than a consistency pin,
  since equality alone survives a widening applied to both halves.
- The untested empty-directory guard in `_workflow_paths()`. `if False`
  survived the whole suite, and both entrypoints are fail-open without it: an
  `audit()` over no files reports no finding, and a `refusable_entries()` over
  no files makes every shipped allowlist entry read as stale. Pinned now in
  both directions, including the positive twin that stops a mutant raising
  unconditionally.
- A vacuous test, replaced rather than kept. The old
  `test_the_shipped_allowlist_file_is_restored_afterwards` claimed to prove
  that the fixture restores the tracked allowlist, and did not: deleting the
  restore left the suite fully green while stripping the entire
  `[commit_identity]` table and all five recorded historical exceptions out of
  the working tree. Two causes compounded — its "before" snapshot was read
  after an earlier test in the class had already done the damage, and
  rewriting an already-damaged file reproduces it byte for byte. A baseline
  captured at import, asserted in `tearDown`, replaces it in both suites; that
  is strictly stronger, covering every test in each class against pristine
  bytes rather than one test against possibly-damaged ones. The shipped
  `finally` was correct throughout — the test was what could not fail.
- A pin for the fixture that inserts a blank-reason allowlist entry under its
  OWN table header rather than appending it. Appending would put the key in
  whichever table is LAST, which is `[commit_identity]`, so the two spellings
  are indistinguishable from inside either suite while the target table is
  empty. The helper is now driven against a document whose target table is not
  last, which is the only arrangement that tells them apart.
- `AGENTS.md`'s SSH-signing instruction, which was broken for any agent with
  more than one ed25519 key loaded. It documented
  `key::$(ssh-add -L | grep ssh-ed25519)`; `grep` matches every loaded
  ed25519 key, so with two keys the value expands to both concatenated and
  Git is handed a malformed signing key. It worked only while a single key
  happened to be loaded. This is portable doctrine, not a local quirk — a
  stranger cloning this repository with two ed25519 keys hits it too. The
  instruction now selects the account's registered signing key explicitly by
  exact type-and-blob match and fails closed when no loaded key matches.
- `AGENTS.md` now states the verification requirement that makes the above
  checkable: the `gpg.ssh.allowedSignersFile` principal must be a SPACE-FREE
  token — the bare email — because the file is whitespace-delimited, so a
  `Name <email>` principal splits and ssh reports `invalid key`. It also
  records the false-pass trap this creates: a broken principal produces
  `No principal matched.`, which is exactly what a genuinely bad signature
  produces, so a negative control run against a broken file passes for the
  wrong reason. Both controls must run against the same file, and a negative
  control is evidence only once its positive twin prints `G`.
- The workflow-integrity gate's own one-line lift, which did not work. Its
  suite asserted that the `[workflow_integrity]` table of
  `scripts/ci/ci_gate_allowlist.toml` equalled `{}`, so applying verbatim the
  line a refusal prints silenced the refusal and immediately failed that
  assertion — a lift instruction that lands in a public CI log and turns the
  build red when an agent follows it. This is the same defect this release
  found and fixed for `[subcommand_callers]`, one table over. The empty-table
  pin is replaced by the stale-entry rule the sibling gate already used
  (`stale_allowlist_failures`): every entry must still name a construct some
  workflow really declares, so an exemption cannot outlive its case and cannot
  reserve room for a violation nobody has proposed, while the documented lift
  stays open. This is a TRADE, and an earlier draft of this entry claimed it as
  a free win — it said the table "cannot accumulate exemptions", which is not
  true. As a predicate over the table's contents the new rule is strictly
  WEAKER than the one it replaces: an empty table satisfies "no stale entry"
  vacuously, while the converse fails — a table carrying one live, correct
  exemption is green under the new rule and was red under the old. What goes
  with it is a tripwire. Under the empty-table pin the FIRST legitimate
  exemption forced a reviewed edit to the suite in the same pull request;
  under the stale-entry rule it lands as one silent line in a data file. The
  gate design doctrine asks for exactly that — a strict check is worth keeping
  only if widening it is cheap — so the trade is deliberate and, on balance,
  right. It is recorded here rather than glossed, because the reviewer is owed
  the honest version: the table CAN accumulate exemptions; what it cannot do is
  keep one whose case has resolved. A FIFTH copy of the same retracted claim
  shipped in `AGENTS.md`'s gate design doctrine — added by this pull request
  itself and missed by the four-place sweep — where "the allowlist keeps
  describing reality instead of accumulating exemptions" made the identical
  move. It is corrected there too, and at more length than the others on
  purpose: `AGENTS.md` is the canonical contract a cold agent operates from, so
  a false capability claim in it outlives the pull request that introduced it.
  A repository-wide re-sweep for a sixth copy — the wording rather than the
  phrase, across every tracked file — found none. The one further occurrence
  anywhere is inside `e97d7df`'s commit message, which append-only history
  (requirement 2) makes unfixable and which `a1b1c86`'s message already
  retracts on the record. `refusals()` is now allowlist-blind and both
  `check_workflow` and `refusable_entries` read it, so the set a lift can
  silence and the set a lift may name cannot drift apart. The round trip is a
  test rather than a promise, in both directions.
- A surviving mutant in `scripts/ci/commit_identity.py`: the reader's
  five-field record guard had no test. A commit message containing a literal
  `0x1f` byte produces six fields, and without the guard the message field is
  truncated at the stray byte — dropping a `Co-authored-by:` trailer written
  after it, a fail-open on the exact rule the gate enforces. The guard was
  already correct and is unchanged; only the test was missing.
- The stated rationale for a mutation-audit survivor in
  `scripts/ci/workflow_integrity.py`. The `\s*` before the colon in `_KEY` and
  the `.strip()` on the captured key were reported as two defences of one
  property, both redundant. Only `.strip()` is: on a QUOTED key with a space
  before the colon the fixed `"[^"]*"` alternative cannot absorb the space and
  the bare alternative excludes a leading quote, so without `\s*` the reader
  refuses the line instead of reading it. Fail-closed either way, but a real
  behaviour change in an input class the suite did not cover between its
  quoted-no-space and bare-with-space cases. The intersection is now asserted.
- `AGENTS.md` credited "Successful main CI" with creating the release tag.
  The tag is created by `release-after-main.yml`, the success-only
  `workflow_run` that fires when main CI completes — not by main CI, and not
  by the publisher, which only GETs the tag object to verify identity and
  rebinds the REST ref in its terminal step. The CI map already described
  this correctly; the release-flow prose did not.

### Changed

- `AGENTS.md` gains a "Gate design doctrine" section stating the two rules
  every gate here now follows: pin behaviour rather than inventory, and ship
  a documented lift mechanism so widening a gate is one line in one PR. It
  states explicitly that this does not relax requirement 4 — an allowlist
  reaches repository mechanics, never a fail-closed security behaviour — and
  that adding an entry with a written reason is a normal part of active
  development, not a security event.

### Removed

- The dead `release-record` subcommand of `scripts/ci/release_contract.py`. It
  had no caller of any kind: of the 34 subcommands the module defines, it was
  the only one with zero references outside the module itself — no workflow,
  script, doc, or test named the literal string, in wrapped or unwrapped form.
  `validate_release_record` is UNTOUCHED and stays live through
  `classify_release_state`, which backs the `release-state` subcommand the
  publisher and the integrity audit both invoke.

## [0.1.36] - 2026-08-26

### Security

- The chart's egress deny is now GATED, where before it was only rendered.
  `chart/templates/network-policy.yaml` denies every outbound connection, and
  0.1.35 named the line that carries that deny — but nothing failed if the
  line went away. `scripts/ci/chart-ingress-pin.sh` scopes itself to
  `spec.ingress` by construction, so it cannot see `policyTypes`, and neither
  can `helm lint`, the render smoke, the four-way release lock, or the
  provider-neutrality pin. Deleting `- Egress` from `policyTypes` while
  leaving `egress: []` in place therefore passed every check in the
  repository while restoring unrestricted outbound access, because
  `NetworkPolicySpec.Egress` is `json:"egress,omitempty"` upstream and the API
  server drops the empty list from the stored spec — leaving that one
  `policyTypes` entry as the entire deny. New `scripts/ci/chart-egress-pin.sh`
  closes that: it renders the chart and compares `podSelector`, `policyTypes`
  and `egress` against pinned literals in full, refuses 19 hostile rewrites of
  the real render (the inert-policy trap, allow-all v4 and v6, a DNS
  exception, a ports-only rule, `- {}`, namespace and pod peers, a duplicate
  key, a widened or emptied selector), and proves no shipped values override
  can move the answer. Wired into the `chart` job of
  `.github/workflows/pr-gate.yml`, so it runs on every pull request.
- That text pin never ships alone, because on its own it would be a claim this
  repository could not support. A raw-line pin recognises a document by a line
  whose prefix is exactly `kind`; YAML permits `kind :`, a quoted key, and
  escapes inside a double-quoted key, so a SECOND NetworkPolicy in the same
  rendered file can be invisible to it while parsing, under a real YAML
  reader, as an empty-selector `policyTypes: [Egress]` policy with one empty
  egress rule. NetworkPolicy allowances are ADDITIVE, so that document hands
  every Pod unrestricted egress while the first still reads "default deny".
  New `scripts/ci/chart_render_census.py` answers it: a stdlib-only YAML
  reader that resolves keys to their canonical spelling BEFORE matching,
  flattens list wrappers, refuses every construct it does not fully understand
  rather than guessing, checks that everything it counts is installable, and
  requires the COMPLETE installable render — every template, CRDs included, no
  `--show-only` blindfold — to hold exactly one NetworkPolicy equal to an
  expectation the gate states itself. The egress pin drives 48 hostile
  whole-render mutations through it and requires every one to be refused.
- New `scripts/ci/test_chart_render_census.py` pins the reader itself, 145
  tests, one hostile input per test, and pins the two mutation floors against
  the batteries' real sizes so neither can be quietly shrunk. It runs in the
  `security` job under its own exact glob, matching how that job already
  discovers the release-contract and Dependabot suites — a suite that stops
  being collected is then a visible edit rather than a silent gap.

### Changed

- `scripts/ci/install-tools.sh` now verifies `gitleaks` and `helm` the way
  0.1.35 taught it to verify Trivy, closing the gap that release reported
  rather than fixed. Both printed their versions without asserting them, which
  is a log line and not a check: a checksum binds the ARCHIVE, never which
  binary the extraction placed on PATH. `gitleaks version` prints a bare
  `X.Y.Z`, so the pin is compared with its `v` stripped;
  `helm version --short` appends the build's git hash, so the assertion reads
  `helm version --template='{{.Version}}'`, which returns exactly `vX.Y.Z`,
  while `--short` stays as the human-legible log line. No version or checksum
  pin changed. All three tools now assert before they print.
- `.gitignore` ignores `__pycache__/`. Every documented invocation of the
  Python contract suites passes `-B` and writes nothing, but `-B` is a flag a
  person can forget, and the run that omits it leaves `.pyc` files a later
  lane has to clean by hand. Only `__pycache__/` is listed: CPython 3 writes
  bytecode nowhere else, and this repository has no pytest — the suites are
  stdlib `unittest` — so a `.pytest_cache` rule would be a guess at a tool
  that is not here.

## [0.1.35] - 2026-08-26

### Security

- `scripts/ci/install-tools.sh` now VERIFIES the Trivy it installed, instead
  of only pinning the one it meant to install: the post-install assertion
  `test "$(trivy --version | awk 'NR == 1 {print $2}')" = "${TRIVY_VERSION#v}"`
  makes the binary state its own version and fails the step when that
  disagrees with the pin. The checksum lock already bound the BYTES; this
  binds the resulting binary's identity to the version the file names, so a
  version/hash pair updated out of step, or a `trivy` resolved from somewhere
  other than the verified install root, is a red step rather than a silently
  different scanner. The download also gains the supply-chain rationale it
  lacked: the archive URL plus repository-owned SHA-256 is deliberate, and
  `trivy-action`/`setup-trivy` are deliberately not used because the Trivy
  action ecosystem suffered a 2026 tag/Release compromise. The v0.73.0 pin is
  unchanged. `gitleaks` and `helm` still print their versions without
  asserting them — the same gap, reported rather than silently widened here.
- `chart/templates/network-policy.yaml`'s egress comment stops pointing a
  future maintainer at the wrong line. It read as though `egress: []` were
  what denies outbound traffic. It is not: `NetworkPolicySpec.Egress` is
  `json:"egress,omitempty"` upstream, so the API server drops the empty list
  from the stored spec and the admitted object carries the deny through the
  `- Egress` entry in `policyTypes` ALONE. The comment now names that entry
  as the load-bearing line and states the failure mode — dropping it while
  leaving the empty list in place silently restores full outbound access.
  Comment only: the rendered manifest parses to a byte-identical object.

### Removed

- The `application` job's "Report frontend test coverage" step. It published
  a coverage percentage that measured nothing: `frontend/tests/` reads
  `../src` through `readFile`, never `import` and never `await import(`, so
  no application file executes under `--experimental-test-coverage` and the
  table it printed had zero file rows. The sibling `coverage-badges` job
  already documents this and publishes a TAP pass-count instead — that job
  and its badge are untouched. The step also ran the whole frontend suite a
  second time on every pull request (after `npm test` in the same job) purely
  to print that vacuous table, so removing it returns CI minutes and removes
  no signal. `PR_GATE_MAIN_JOBS` pins job NAMES and conclusions, never step
  names, so no release-authorization surface is touched.
- A stale `.gitignore` sentence defending an exception for a tracked
  `.claude/settings.json`. No `.claude/` path is tracked in this repository,
  and the rule beside it ignores only `.claude/worktrees/`, so the sentence
  described an exception to a rule that never covered that file. The
  worktree-ignore rule and its first sentence are unchanged.

## [0.1.34] - 2026-08-25

### Security

- The replacement Ready-flip rule is now pinned closed over the
  governance DOCUMENTS, not a window (issue #130; found independently by
  the Daybreak Blue round-2 review of PR #125 and the post-merge audit of
  PR #128): every block of AGENTS.md, the PR template, and the release
  runbook that speaks the word "ready" must hash-match an enumerated pin
  in `require_ready_flip_rule`, and every pin must remain present, so a
  competing Ready authority displaced outside the canonical section — a
  new paragraph on either side of it, a second runbook paragraph, or the
  Merge-readiness bullet rewritten — is red instead of representable.
  All previously surviving mutants ship killed in the same test.

## [0.1.33] - 2026-08-25

### Changed

- Risk-based review ceremony (issue #124, owner directive 2026-08-22
  re-affirmed 2026-08-25, lockstep with naranjo.online PR #191, its
  issue #190): the Main Worker receipt is retired — after the
  independent adversarial review approves the exact final head and all
  required checks are green, the coordinator flips Ready and the owner
  merges, with no third distinct-context pass. Review depth is now
  stated as risk-based (security-surface / normal code / docs classes)
  instead of identical for every PR; the author runs the complete local
  gate once on the final head and the reviewer re-runs the full suite
  only with specific cause; ordinary labels, body text, and process
  comments are named coordination signals while the App-posted
  exact-head review verdict — actor and head binding — remains control
  evidence. The enforcement is repointed: `validate_review_receipt`
  accepts no receipt role but adversarial (the retired `main-worker`
  branch and `MAIN_WORKER_SCOPE` are gone from the production
  validator), a retirement test proves the formerly-valid receipt now
  fails closed, and the governance-docs test pins the replacement rule
  CLOSED — the AGENTS.md rule and the runbook's retirement block must
  equal the canonical text exactly, so a contradictory permission
  inserted beside the rule is as red as a deletion (review round 1
  proved the substring pin let one survive) — while failing if the
  retired ceremony's canonical shapes resurface in AGENTS.md, the PR
  template, or the release runbook. Removed control, stated plainly: no
  second independent context re-checks architecture, merge order,
  authority, settings, base freshness, or required checks before Ready —
  base freshness and required checks stay coordinator-verified at the
  flip, and the owner merge gate remains terminal. Commit identity and
  SSH signing, owner-only merge, the release transition gate, the
  four-way version lock, and the independent adversarial review itself
  are all untouched.

## [0.1.32] - 2026-08-24

### Changed

- Five dependabot dependency bumps, reproduced on an agent lane because
  dependabot cannot pair an artifact-surface change with this
  repository's required one-patch release advance (issue #119,
  supersedes #114-#118): `svelte` 5.56.9 -> 5.56.10 and `vite` 8.2.1 ->
  8.2.2 (dev dependencies, frontend); `github/codeql-action`
  init+analyze v4.37.7 -> v4.37.8; `actions/upload-artifact` v4.6.2 ->
  v7.0.1 (pr-gate.yml's push-only `transition-verdict` upload);
  `docker/setup-buildx-action` v4.2.0 -> v4.3.0 across pr-gate.yml,
  release-integrity-audit.yml, and release-publisher.yml. All three new
  action commit SHAs were independently re-verified against their
  upstream tags before landing.

## [0.1.31] - 2026-08-24

### Changed

- The SLSA builder identity in `build_attestation_statement` is now bound to
  ONE exact Actions run instead of prefix-matched against the repository
  (issue #111). The old check,
  `builder["id"].startswith(source + "/actions/runs/")`, was satisfied by
  every run of every workflow in this repository forever — the digits after
  `/actions/runs/` were never examined — while every neighbouring identity in
  the same function was already bound exactly. It is now an anchored full
  match on `<source>/actions/runs/<run>/attempts/<n>` behind a new REQUIRED
  `--builder-run-id`, itself validated as a positive decimal run ID. The
  attempt segment is MANDATORY, not tolerated: measured on this repository's
  own published provenance for v0.1.24, v0.1.27, v0.1.28, v0.1.29 and v0.1.30
  (both `linux/amd64` and `linux/arm64`), BuildKit always emits it and always
  names the publisher run that built those bytes. Its NUMBER stays a pattern
  because GitHub's re-run recovery keeps `GITHUB_RUN_ID` and increments only
  the attempt. Because the produced statement is byte-identical for a correct
  run ID, every already-published attestation stays exactly reproducible.
- The publisher's fresh-build path passes its own `GITHUB_RUN_ID`, which is
  the authoritative builder there — that job runs only when the image state
  was `absent`, so the step above it produced those bytes. The existing-image
  classifier does NOT, and could not: a re-dispatch recovery legitimately
  reuses bytes an earlier run built, so its own run ID would classify a valid
  reuse as `burned` and fail the release. It and the scheduled integrity audit
  instead recover the builder run from the first platform's predicate through
  a new read-only `attestation-builder-run` subcommand and require every other
  platform to name that same run — one image, one builder run, where before
  the two architectures could name different runs and both pass.
- `embedded_predicate` in `test_release_contract.py` now carries the
  `/attempts/<n>` segment BuildKit really emits; the fixture previously
  modelled a builder ID shape this repository has never published.

## [0.1.30] - 2026-08-24

### Fixed

- The `securityHeaders` doctrine comment no longer claims this application is
  the sole owner of the HSTS policy (issue #95) — a claim the same tree's own
  README contradicted. The comment now records the measured two-layer reality:
  exactly one `Strict-Transport-Security` header reaches a visitor and it is
  the edge's (`max-age=31536000; includeSubDomains`, no `preload`), so the
  edge is the visitor-facing HSTS owner; the origin's own header stays as the
  defense-in-depth promise an origin-direct client would receive; and why the
  origin's value is not the one observed publicly is recorded as undecidable
  from outside rather than asserted either way. Neither layer closes RFC 6797
  §14.6's first-contact gap, which is why the plain-HTTP redirect remains a
  separate control. The `redirectForwardedHTTP` comment also drops an edge
  product-feature name that survived inside a provider-neutral tree, and the
  README stops asserting the suppression mechanism it cannot establish
  (issue #98).

## [0.1.29] - 2026-08-23

### Changed

- The duplicated post-merge container build is gone (issue #109). The PR
  gate's `container` job now carries `if: github.event_name == 'pull_request'`,
  the same condition `dependency-review` has always carried, and the same
  reasoning `browser-smoke.yml` already states in its own header: main pushes
  are the release path, and under squash-or-rebase merges with a strict
  required-check ruleset the merged tree is necessarily the tree this job just
  passed on the pull request. The Dockerfile takes no `ARG` and no git
  metadata and digest-pins every base, so the build is a pure function of that
  tree. `container` remains a REQUIRED pull-request check - nothing merges
  without it - and `release-publisher.yml` still builds, scans, signs, and
  attests the bytes that ship. `PR_GATE_MAIN_JOBS` now requires the resulting
  `skipped` conclusion exactly and refuses a `success` there, so dropping the
  condition denies the release instead of rebuilding an identical tree after
  merge authority has already been exercised. The inventory stays a closed six.

## [0.1.28] - 2026-08-23

### Added

- Browser-emulated smoke lanes in CI (issue #22, stage 2): a separate
  SHA-pinned workflow drives the shipped Go binary - never a dev server -
  through Chromium, WebKit, and Gecko at phone viewports, twenty-one lanes in
  all: the served viewport contract, touch and text floors measured after
  layout at 320px, sideways-scroll refusal with the appearance menu closed and
  open, reduced motion observed in both directions, zero layout shift across
  every reading mode, and an origin lane that watches each request the page
  makes. The structural stage-1 floors strengthen alongside: the
  viewport-height contract becomes a rule over every declaration (vh and lvh
  banned, a guarded svh/dvh must keep an unguarded fallback), and the
  previously unenforced video floors (muted, playsinline, a real poster) gain
  their structural rule and fixtures. `@playwright/test` is pinned exactly
  (1.62.1), declares no install scripts, and the browser binaries enter
  neither git nor the image.

## [0.1.27] - 2026-08-23

### Added

- A named denial test isolating the tag-object HTTP status guard in the
  release orchestration's classify step (`test "${object_status}" = 200`):
  scenario 1's happy path with only the tag-object status flipped to 404 and
  a usable anchor-B run listing supplied, so the denial is provably this
  guard's own - deleting either adjacent guard leaves the new test green.

### Fixed

- The `NoArtifactClassifyShellPathTests` docstring described the retired
  anchor model; it now states both anchors in shipped order and the real
  probe fixture shape.
- The README release-flow paragraph is reflowed: the mid-paragraph orphan and
  the over-long line named by the #89 delta review are gone
  (whitespace-only, token-stream identical).

## [0.1.26] - 2026-08-22

### Added

- Sepia reading mode, a third EXPLICIT choice alongside light and dark rather
  than a variant of either: the same low-light comfort on a paper-toned
  surface instead of a cool one. It lands as a `theme.Catalog` entry, its own
  `[data-theme='sepia']` token block, and its own switcher option - the three
  places the reading-theme contract says a theme is made of - so the origin
  stamps and caches it exactly like the other two, and
  `TestEachThemeHasItsOwnCacheIdentity` covers its distinct ETag with no test
  change at all.
- Every value in the sepia palette is VALIDATED, not asserted: the contrast
  battery now runs light, dark, and sepia through the same nine pairs. Its
  measured floors are text 15.17 / 13.37 / 8.83 / 7.78 / 9.35:1 against the
  4.5:1 requirement, and interface 4.09 / 3.61 / 9.35 / 8.24:1 against 3:1.
- A pin proving the appearance menu is a dismissible disclosure and not a
  colour-only control: both dismissal paths, the text label and tick beside
  every swatch, the trigger's tap-target bounds, and the fixed-width tick
  column that keeps the popover from resizing when the tick moves.

### Changed

- The appearance switcher is one round icon button that opens a popover of
  four swatched modes (System, Light, Dark, Sepia), replacing the row of
  three text buttons. The row had to wrap on a narrow phone; a single
  44px target does not. The popover is absolutely positioned and anchored to
  the trigger's end edge, so opening it reflows nothing and cannot run off a
  320px viewport.
- Dismissal covers two real browser behaviours rather than one: Safari does
  not focus a button when it is clicked, so a blur-only close would leave the
  popover stuck open there. The pointer listener exists only while the menu is
  open and is torn down with it; Escape closes it from the keyboard.
- Source-size caps raised under the new-surface carve-out, disclosed here and
  in the PR body so the headroom can be checked as working room: component
  7600 -> 9600 (measured 9303, 3%), styles 9800 -> 13600 (measured 12724,
  6%). Both headroom figures are stated on the same basis, (cap - measured)
  / cap, and both are measured at this release rather than at the head that
  first proposed the raise. The static fallback gained no surface, so its
  1800 cap does not move.

## [0.1.25] - 2026-08-22

### Added

- Embed the resolved image digest into the chart the publisher packages, so a
  published chart is deployable as published instead of shipping the
  all-zeros sentinel no registry can resolve. The digest comes only from the
  one value the Trivy HIGH/CRITICAL gate, cosign signing, and both the SLSA
  provenance and SPDX SBOM attestations already accepted - never re-derived
  from a mutable tag (#91).
- Perform the identical substitution on BOTH chart packaging paths - the
  chart-state classifier's reproduction and the publish step - so a re-run of
  an already-published version still classifies `complete` rather than a
  false `burned` (#91).
- Fail closed around the substitution: the digest must match
  `^sha256:[0-9a-f]{64}$` and must not be the sentinel, the working copy must
  hold the sentinel or that same digest, and the packaged archive is re-read
  before any registry effect, so a run that would publish the sentinel fails
  instead (#91).

### Changed

- The committed `chart/values.yaml` keeps the sentinel and says so: only the
  published artifact carries a real digest, and the `pr-gate` chart checks
  stay exactly as strict (#91).
- Read the release version, registry password, and actor from the publish
  step's environment instead of interpolating workflow expressions into its
  privileged shell (#91).

## [0.1.24] - 2026-08-21

### Added

- Classify a protected-main merge whose every commit is confined to the
  documentation allowlist as `no-artifact`: no version advance, no tag, no
  Release, no publisher dispatch. Every other range keeps the existing
  one-exact-patch release contract unchanged. Nothing is relaxed - an
  unchanged artifact has nothing to version, sign, scan, or attest, and a
  documentation PR still runs the full gate (#85).
- Prove that class against either of two anchors the merge cannot choose -
  the retained release tag, or the last successful protected-main gate head
  from the Actions record with every release lock required byte-identical to
  it - so a release that failed to tag no longer blocks documentation merges
  (the condition #81 causes). Denial requires BOTH anchors to be unavailable;
  a tag probe that never returns a definitive answer is treated as unknown,
  not absent, and denies (#85).

## [0.1.23] - 2026-08-21

### Changed

- Derive the `GovernanceReceiptTests` release-tag pin from the raw bytes of
  `VERSION`; the release-lock closure shrinks from five surfaces to four and
  release PRs stop editing the checker (#84).

## [0.1.22] - 2026-08-21

### Added

- Publish the parallel-agent worktree contract in `AGENTS.md` so any clone
  carries the isolation, lane-ownership, shared-git-state, and cleanup rules
  that previously lived only in a machine-local skills folder.
- Ignore `.claude/worktrees/` so the layout the contract mandates stays clean
  in a fresh clone instead of relying on a local `.git/info/exclude`.

## [0.1.21] - 2026-08-20

### Fixed

- Release publication, immutable-settings recheck (#78): the live `Protect-Main`
  ruleset's `pull_request` rule gained
  `require_extra_approval_for_unattributed_changes`, and the pinned closed
  parameter field set in `scripts/ci/release_contract.py` denied it as foreign —
  `DENY: pull-request rule parameter fields are missing or foreign` — which left
  0.1.19 and 0.1.20 merged but unpublished. The closed set is re-anchored on the
  new field with an exact-value assertion pinning the live, stricter `True`; the
  set stays closed, so the next foreign field still denies. The pin is
  rule-level, matching `do_not_enforce_on_create`, so the value-only settings
  receipt shape is unchanged. `docs/release-governance.md` states the parameter
  and the split, and the runbook token pins keep either from being dropped.

## [0.1.20] - 2026-08-20

### Added

- Attestation statement flow, python-side test oracles (#66): `AttestationSetTests`
  and `SbomAttestationTests` in `scripts/ci/test_release_contract.py` build
  their "expected" statements with `RC.build_attestation_statement` /
  `RC.build_sbom_statement` and then re-wrap those SAME objects as the
  "verified" cosign records, so `_type` and the `--predicate-output`
  contract were only ever compared against themselves — no input could turn
  either comparison red. Added `AttestationStatementCLITests` and
  `SbomStatementCLITests`, nine tests total driving the real
  `attestation-statement` and `sbom-statement` subcommands end to end
  through `RC.main` against real temp files, independent of the module's
  own constants: each pins its statement's `_type` as the hardcoded literal
  `https://in-toto.io/Statement/v0.1` (never read from
  `RC.INTOTO_STATEMENT_TYPE`); the SBOM class additionally pins
  `predicateType` as the hardcoded literal `https://spdx.dev/Document`
  (never read from `RC.SPDX_PREDICATE_TYPE`); both assert
  `--predicate-output`'s content equals `statement["predicate"]` exactly,
  is never equal to the whole statement, and carries none of the
  statement's own envelope keys; both assert the subcommand exits 2 when
  `--predicate-output` is omitted; both assert the file exists and is
  non-empty after a successful run. Mutation-proved in a scratch copy
  (full kill matrix in the PR body): reverting `INTOTO_STATEMENT_TYPE` to the broken
  `https://in-toto.io/Statement/v1` turns only the two type-literal tests
  red; reverting `SPDX_PREDICATE_TYPE` turns only the SBOM predicate-type
  test red; swapping either subcommand's `--predicate-output` write to the
  whole statement turns only that subcommand's byte-relationship test red;
  `required=False` on either `--predicate-output` turns only that
  subcommand's flag test red; deleting either write turns that
  subcommand's byte-relationship and exists-non-empty tests red.
  `AttestationSetTests` and `SbomAttestationTests` stayed green through
  every mutation, confirming the self-referential blindness the issue
  described. No production code changed; `release_contract.py`'s CLI
  behavior is unchanged.

### Release

- VERSION, chart `version`/`appVersion`, chart `values.yaml` `image.tag`,
  this CHANGELOG entry, and `scripts/ci/test_release_contract.py`'s
  `GovernanceReceiptTests` live-snapshot pin all advance together per the
  release-lock closure (five locations, one commit) — the exact-patch
  discipline requirement 10 enforces.

## [0.1.19] - 2026-08-20

### Added

- CI: `.github/dependabot.yml` now has a machine gate (#56). Nothing
  validated this file before — actionlint covers `.github/workflows/*.yml`
  only, and the release contract's own workflow sweep never matched this
  path either. The adversarial review of PR #55 proved the gap live
  (finding 1): a schema-invalid `groups` stanza (`patterns:` typoed to
  `patternz:`, plus an unrelated `bogus-key`) survived every existing
  repository check. `scripts/ci/dependabot_contract.py` is a new,
  standard-library-only, conservative fail-closed mini-parser for the
  subset of YAML this file actually uses (requirement 9: no PyYAML here;
  the hand-rolled indentation reader in `scripts/ci/chart-ingress-pin.sh`
  is the existing precedent). It rejects tabs, flow-style collections,
  duplicate keys, and any unparseable construct outright, then validates
  the schema itself: `version: 2` exactly; a non-empty `updates:` list of
  mappings; each entry's `package-ecosystem` against GitHub's documented
  ecosystem set, `directory` starting with `/`, and `schedule.interval` in
  {daily, weekly, monthly} (optional `day`/`time`/`timezone` accepted);
  each optional `groups:` entry restricted to {patterns, exclude-patterns,
  dependency-type, update-types, applies-to} with non-empty pattern
  strings. Unknown keys are rejected at every level, mirroring the
  narrow-allowlist precedent in `internal/ratings` and the chart's ingress
  provider binding: widening a schema allowlist here is a reviewed code
  change, never silent drift. `pr-gate.yml`'s `security` job gained two
  steps: a dedicated `unittest discover` step scoped to
  `test_dependabot_contract.py` (the existing release-contract discovery
  step's glob never matched this file, so a sibling step was added rather
  than widening it and mixing two unrelated failure reasons into one step
  name), plus a direct `dependabot_contract.py` invocation so the gate
  still runs even if a future discovery-glob edit drifts. The hostile
  suite proves the exact PR #55 `groups` stanza is rejected, alongside
  `version: 1`, a missing `schedule`, an unknown ecosystem, unknown keys
  at every level, an empty `updates:`, tab indentation, and flow-style
  collections; the repository's own `dependabot.yml` is the load-bearing
  positive case that must keep passing. Mirrors the same gate landing in
  naranjo.online (#59).

### Release

- VERSION, chart `version`/`appVersion`, chart `values.yaml` `image.tag`,
  this CHANGELOG entry, and `scripts/ci/test_release_contract.py`'s
  `GovernanceReceiptTests` live-snapshot pin all advance together per the
  release-lock closure (five locations, one commit) — the exact-patch
  discipline requirement 10 enforces.

## [0.1.18] - 2026-08-20

### Security

- Media pipeline, multipart amplification (#28): the pipeline delegates Range
  handling to `http.ServeContent`, which honours a multi-range request without
  any cap on how many ranges it names. Every named range is answered with its
  own boundary line, `Content-Type`, and `Content-Range` — about 129 bytes of
  generated framing for the handful of bytes that name it — so the response
  grows with the range count while the request barely does. Measured against
  the delegate over this repository's 4 KiB video fixture: 1024 one-byte
  ranges answer an 8,025-byte `Range` header with 131,990 response bytes
  (16x), and the origin writes all of them while holding one of its
  `MEDIA_MAX_CONCURRENT` slots on single-board hardware.
  `internal/media` now caps the SET SIZE at `maxRangeSetSize` (4 — players
  seek with one range, the multipart contract test uses two) and answers
  `416` with a constant-size body for anything larger.
- The refusal is positioned deliberately: it runs after the URL class is
  parsed and BEFORE both the concurrency-slot acquire and the file open, so a
  hostile set costs one short response instead of a slot held for a multipart
  write. `TestRangeSetCapPrecedesSlotAndFileWork` proves the ordering by
  making each resource unavailable in turn — under a saturated semaphore the
  answer must be the cap's `416` and not `503`, and against an empty media
  root it must be `416` and not `404` — with a control request in each case
  showing the request really does reach that stage.
- Range algebra is untouched (requirement 9, no `net/http` fork or
  vendoring): the cap COUNTS comma-separated members of a `bytes=` set and
  decides nothing else. A header that is not a `bytes=` set — a foreign unit,
  a different capitalisation, leading whitespace — is not counted at all and
  still reaches `http.ServeContent`, which rejects every such spelling itself,
  so no set the delegate would expand escapes the count. The refusal body is
  deliberately distinct from the delegate's own Range errors, and the tests
  assert which layer answered rather than status alone. One deliberate
  narrowing: `net/http` skips empty members, so `bytes=0-9,,,,,` would have
  served as a single range and is now refused — counting cannot be made to
  under-count by padding a header with separators, and no player writes that.
- Existing behavior is unchanged and pinned byte-for-byte:
  `TestRangeBehaviorMatrix`, `TestMultipartRangeResponse` (two ranges, still
  served), `TestConditionalRequestsUseTheDigest`, and
  `TestBoundedConcurrencySheds` are untouched.

## [0.1.17] - 2026-08-19

### Fixed

- Release publishing, draft-observation layer (#67): `observe_release` in
  `.github/workflows/release-publisher.yml` polled only
  `GET /repos/{repo}/releases/tags/{tag}`, but GitHub never returns an
  unpublished draft Release on that by-tag endpoint. Run 32201373323
  (v0.1.16) proved it live: `gh release create --draft` succeeded, the
  by-tag poll read "absent" five times anyway, and the step denied with
  `DENY: draft create did not reach a resumable or exact state`, leaving a
  stranded v0.1.16 draft (image and chart artifacts were already complete
  and verified). The resumable-draft states in this same step and in
  `release_contract.py release-state` were correct but unreachable. Fixed
  by keeping the by-tag GET as the first probe — it still serves the
  published/exact state directly — and, only on its 404, adding a second
  probe, `GET /repos/{repo}/releases?per_page=100`, that lists and selects
  locally by `tag_name`: zero matches stays absent; exactly one match is
  written to the same existing-release file and classified by the same
  `release-state` call as the by-tag path (drafts then classify as
  draft-empty/draft-ready per the existing asset logic, unchanged); more
  than one match is a stray-duplicate-draft ambiguity the new
  `release-tag-select` command in `scripts/ci/release_contract.py` refuses
  to resolve silently — it DENYs, names the repository and tag, and points
  at `GET /repos/{repo}/releases` for a human to resolve by hand.
  `release-state`/`classify_release_state` needed no change: it already
  modeled every draft state correctly and only ever lacked a record to
  classify. `release-integrity-audit.yml` uses the unrelated
  `GET /repos/{repo}/releases/latest` endpoint (which by contract never
  returns a draft or prerelease) to audit an already-published Release, so
  it never hits this defect and needed no change. The v0.1.16 stranded
  draft itself is an owner decision (publish it or accept the gap); this
  fix only prevents new releases from stranding the same way.
- Chart rollout strategy: `chart/templates/deployment.yaml`'s
  `maxSurge: 1` / `maxUnavailable: 0` cannot roll within the
  `lidersea-com` namespace's own ResourceQuota (#68). Cluster-proven during
  the same v0.1.16 deploy: applying the chart at `replicaCount: 2` made the
  controller scale the OLD ReplicaSet back up to 2 first, chasing the
  `maxUnavailable: 0` availability floor; that alone filled the quota
  (`pods: 2`, `limits.memory: 256Mi` against this chart's own 128Mi
  per-pod memory limit), so the NEW ReplicaSet's pod was quota-rejected and
  the rollout wedged permanently — no surge of any kind fits this budget.
  Swapped to `maxSurge: 0` / `maxUnavailable: 1`: one old pod is replaced
  by one new pod at a time, 2 pods present throughout and never 3, which
  converges within the quota.
- Chart scale range: per the owner's same-night directive (the cluster
  doubles as the dev environment; workloads scale within the quota rather
  than being shaped by it), `replicaCount`'s schema pin loosened from
  `const: 2` to `minimum: 1` / `maximum: 2` — a user-visible relaxation:
  the chart now accepts `replicaCount: 1`, previously refused. The default
  stays 2 for availability, and the maximum documents the namespace
  quota's real budget, so raising it starts with the quota, not this
  schema. Known trade at `replicaCount: 1`: with `maxUnavailable: 1` the
  rollout floor is zero available pods — a brief outage window per
  rollout, accepted at dev scale and absent at the default 2.

### Release

- VERSION, chart `version`/`appVersion`, chart `values.yaml` `image.tag`,
  this CHANGELOG entry, and `scripts/ci/test_release_contract.py`'s
  `GovernanceReceiptTests` live-snapshot pin all advance together per the
  release-lock closure (five locations, one commit) — the exact-patch
  discipline requirement 10 enforces.

## [0.1.16] - 2026-08-18

### Security

- Go toolchain `1.26.5` -> `1.26.6`, closing 8 HIGH-severity standard-library
  CVEs that the release vulnerability gate caught on the burned `v0.1.15` run
  (32194317079) before that tag's image ever reached a signed Release: the
  tag and an unsigned image exist, but no Release was published. Zero
  CRITICAL findings. Named: CVE-2026-33818 (`encoding/asn1` denial of
  service), CVE-2026-39821 (`net/http` IDNA punycode handling),
  CVE-2026-46600 (`dns/dnsmessage` denial of service), CVE-2026-56853
  (`net/http` h2c denial of service), CVE-2026-56858 (`html/template`
  cross-site scripting), CVE-2026-56859 (`encoding/xml` denial of service),
  CVE-2026-56860 (`net/url` denial of service), and CVE-2026-56862
  (`crypto/tls` KeyUpdate denial of service). All eight are fixed upstream in
  1.26.6; this release makes no application code change. The pin moves in
  the same commit everywhere it is stated: `go.mod`'s `toolchain` directive
  (module `go` directive stays `1.26.0`, unchanged), the Dockerfile's
  `golang:1.26.6-trixie` build stage (digest updated to the matching
  upstream manifest), and the `go-version`/`GOVERSION` pins in
  `.github/workflows/codeql.yml` and `.github/workflows/pr-gate.yml`.

### Fixed

- Release publishing, attestation layer: both SLSA provenance and SPDX SBOM
  attest calls used `cosign attest --yes --statement <file>`, but
  `--statement` is a dead flag on image attest — cosign's `attest.go`
  requires `--predicate` unconditionally
  (`if c.PredicatePath == "" { return "predicate cannot be empty" }`) in
  every checked release (v2.2.4, v2.4.0, v2.5.0, v2.6.5, v3.1.3);
  `StatementPath` is consumed only by `attest-blob`. naranjo.online's
  identical step failed on exactly this in its publisher run 32195803008;
  lidersea's own publisher has not yet reached this step in a completed run
  (0.1.9-0.1.12 failed earlier in `immutable_settings`, fixed in 0.1.14 and
  0.1.15; the furthest-reaching 0.1.15 run died at the Trivy CVE gate
  above), so this closes the same latent defect before lidersea's publisher
  ever reaches it. Reproduced offline with the pinned cosign v3.1.3:
  `--statement` fails immediately with `predicate cannot be empty`, before
  any registry or OIDC call (`.github/workflows/release-publisher.yml`).
- Both attest sites now sign the modified predicate directly —
  `cosign attest --yes --predicate <file> --type <predicateType URI>
  "${IMAGE}@${DIGEST}"` — with the exact URI (`https://slsa.dev/provenance/v1`,
  `https://spdx.dev/Document`) that the corresponding
  `cosign verify-attestation --type` filter resolves to, so sign, verify,
  and the Python comparison stay on one predicateType; a typed alias like
  `slsaprovenance1` is never used to sign, since it routes to cosign's
  protobuf path with `DiscardUnknown` and silently drops BuildKit's custom
  predicate fields. `attestation-statement` and `sbom-statement` in
  `scripts/ci/release_contract.py` now also write the modified predicate —
  the exact bytes cosign embeds — to a new required `--predicate-output`
  path, and their expected-statement `_type` switches to
  `https://in-toto.io/Statement/v0.1`, matching what cosign's
  `generateCustomStatement` actually stamps. The SBOM statement's subject
  also drops its `?platform=` suffix to match cosign's real subject (bare
  image, no platform), since cosign derives the subject only from the CLI
  target. Verified end to end with the pinned cosign v3.1.3: the new
  invocation parses and generates cleanly for both predicate types and
  fails only on a deliberately invalid identity token.

### Release

- VERSION, chart `version`/`appVersion`, chart `values.yaml` `image.tag`,
  this CHANGELOG entry, and `scripts/ci/test_release_contract.py`'s
  `GovernanceReceiptTests` live-snapshot pin all advance together per the
  release-lock closure (five locations, one commit) — the exact-patch
  discipline requirement 10 enforces.

## [0.1.15] - 2026-08-18

### Fixed

- Release publishing, second layer: the 0.1.14 fix let the settings recheck get
  one step further and it denied again. Run 32188071417 — the first
  `release-after-main` run on protected main carrying that fix — failed its
  `immutable_settings` job with `DENY: Protect-Main bypass actors must be a
  JSON array`. `build_settings_receipt` required `bypass_actors` to be an array
  on the `Protect-Main` ruleset detail, but GitHub's "Get a repository ruleset"
  contract states that "the `bypass_actors` property is only returned if the
  user making the API request has write access to the ruleset", and the
  settings jobs mint a repository-scoped App token whose only grant is
  Administration read. The property was therefore absent from every response
  this path can observe, and `_array(None, ...)` denied. As in 0.1.14 the
  repository was configured correctly — the check was reading a field its own
  credential is not entitled to see. The read and its assertion are removed
  rather than made conditional: a control whose strength depends on who holds
  the credential is not a fail-closed control.

### Changed

- The settings receipt no longer carries a `bypass_actors` field, and the
  closed field set now rejects it as foreign so no dangling copy survives.
- `docs/release-governance.md` gains a column table stating which invariants are
  proven by the CI recheck and which by the owner preflight. Zero bypass actors
  and disabled merge commits are in the owner column, each with the GET-only
  command that proves it under a credential REST will answer.

## [0.1.14] - 2026-08-18

### Fixed

- Release publishing: the automatic publisher has been dead since 0.1.9. Every
  `release-after-main` run since #47 failed in its `immutable_settings` job with
  `DENY: repository setting allow_merge_commit is not boolean`, so no tag,
  image, chart, or GitHub Release was produced for 0.1.10, 0.1.11, or 0.1.12.
  `build_settings_receipt` derived the receipt's `merge_methods` from the
  repository record's `allow_merge_commit` / `allow_rebase_merge` /
  `allow_squash_merge` booleans, but REST returns those fields only to
  credentials holding Contents write. The settings jobs mint a
  repository-scoped GitHub App token whose only grant is Administration read,
  so the booleans were absent from every authorized response and the assertion
  could never pass in CI. The repository was configured correctly the whole
  time — the check was reading a field its own credential is not entitled to
  see (`scripts/ci/release_contract.py`).
- The receipt's `merge_methods` now come from the active `Protect-Main`
  ruleset's `pull_request` rule `allowed_merge_methods`, which the
  Administration-read token does receive and which is what actually constrains
  merges into protected `main`. The repository-record boolean loop is deleted
  outright rather than made conditional: a credential-dependent assertion is
  not a fail-closed control. The receipt's external shape is unchanged —
  `merge_methods` is still a sorted list — and
  `validate_settings_receipt`'s exact `{"rebase", "squash"}` gate is byte-for-byte
  unchanged, so a ruleset that permits merge commits, permits only one method,
  or reports a missing, non-array, non-string, empty, or duplicated value still
  fails closed before any tag, registry, signing, or Release effect.

## [0.1.13] - 2026-08-18

### Changed

- Docs: `AGENTS.md` aligned to owner directives the text predated (nine
  fixes). Requirement 3's signature rule now matches the ACTING agent's
  own label instead of a fixed `- Fable5`, superseding the 2026-08-10
  single-signer decision per the owner's 2026-08-18 model-tiering
  directive (merged precedent #53 already follows the per-lane rule).
  The agent-labels roster gains `sonnet5` (Claude Sonnet 5), live
  server-side already. "Commit identity mechanics" drops the hardcoded
  lane example and adds SSH per-command signing (owner-registered Mac
  key, `gpg.format=ssh`, never `git config`; key registered 2026-08-18).
  The Dependabot bullet documents the lockstep-pair practice (merged
  precedents #53, #55). The branch-prefix example generalizes from
  `fable5/<topic>` to `<lane>/<topic>`. A new "Release-lock closure"
  subsection documents all FIVE release-lock file locations as a closed
  set — including `scripts/ci/test_release_contract.py`'s live-snapshot
  pin this same PR advances — citing the PR #53 first-head `security`-job
  failure that motivated it. The merge-readiness bullet now requires the
  Main Worker PASS receipt and "Working a change end to end" gains the
  missing Main Worker step (10 steps), both matching naranjo.online.

## [0.1.12] - 2026-08-18

### Changed

- Frontend: `svelte` bumped from 5.56.8 to 5.56.9 and `svelte-check` from
  4.7.5 to 4.7.6 together (`frontend/package.json`,
  `frontend/package-lock.json`). Dependabot opened these as two separate
  PRs (#48, #49) for a compatibility pair maintained in the same monorepo
  release cadence; bundling them in one commit avoids a partially-upgraded
  toolchain landing between merges. `.github/dependabot.yml` now groups
  the `svelte`/`svelte-check` pattern under the npm ecosystem entry so
  future coupled releases arrive as one PR, mirroring the existing
  `github-actions` `codeql-action` group.

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
