# Release-control readiness receipt

Every protected-`main` integration must remain able to publish one release,
including a one-commit squash and a multi-commit linear rebase. Repository code
validates every intermediate `VERSION` state in either topology, but a pull
request cannot make its own checks mandatory or grant itself repository
administration. Server controls therefore remain a separate readiness boundary.

The automatic-release pull request must remain Draft until the repository owner
has configured and observed all of these controls:

- GitHub immutable releases enabled before the first affected Release is
  published. Enabling the control later does not retrofit an older Release.
- Actions enabled with the repository's existing `all` policy, full-SHA action
  pinning required, default workflow-token permissions read-only, and workflows
  unable to approve pull-request reviews.
- Exactly squash and rebase enabled; merge commits disabled in repository
  settings and the active repository-owned `Protect-Main` ruleset.
- `Protect-Main` targets only `refs/heads/main`, requires pull requests, linear
  history, signed commits, and the exact strict GitHub-Actions-bound checks
  listed below; it denies force pushes and deletion and has no bypass actor or
  update restriction.
- Private vulnerability reporting, secret scanning, and secret-scanning push
  protection enabled.

The repository owner alone chooses squash or rebase and performs the merge. A
settings receipt grants no merge or settings-mutation authority.

## Two-token publication boundary

The token-created annotated Git tag does not trigger a recursive push workflow.
The successful-main orchestrator therefore dispatches `release-publisher.yml`
on protected `main`, never on the tag, and passes the exact source SHA and
authoritative successful PR-gate run ID. The publisher's read-only authorization
job rejects any foreign, failed, stale, incomplete, or unmerged run before a
privileged job can start.

Both workflows then perform the same authoritative settings recheck in a
structurally separate `immutable_settings` job before any tag, registry,
signing, attestation, or Release side effect. That job is gated by the
`platform-release` environment and mints a current-repository-only GitHub App
token with the full-SHA-pinned
`actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1`
action (`v3.2.0`) and only `permission-administration: read`.

The environment contract is exact:

- deployment branch policy: custom selected branches, exactly `main`;
- environment variable: `PLATFORM_RELEASE_APP_ID`;
- environment secret: `PLATFORM_RELEASE_APP_PRIVATE_KEY`.

The action output is passed only as the step-local
`IMMUTABLE_SETTINGS_TOKEN`, and only to the versioned settings GET. The settings
job exposes no output. It cannot reach the mutation jobs. The ordinary `GITHUB_TOKEN` is the sole credential
for tag, registry, signing/attestation, and Release mutations. Never provision placeholders, store either credential in
the repository, pass `GITHUB_TOKEN` to the administration recheck, or pass the
App token to a mutation step.

## Read-only authoritative preflight

The preflight uses `gh api --method GET` only, with GitHub REST API version
`2026-03-10`. It reads repository merge/security settings, immutable releases,
Actions policy, default workflow-token permissions, private vulnerability
reporting, the exhaustive ruleset inventory, and the one exact active
repository-owned `Protect-Main` ruleset. It does not create, update, or delete a
setting, ref, Release, package, or other resource. Authentication, duplicate
JSON members at any depth, a foreign field, or an inexact value is a denial.

Run it only after the repository owner has made an approved settings change.
Keep the value-only receipt outside the repository and remove it after recording
the bounded result on the pull request:

```bash
receipt="$(mktemp)"
trap 'rm -f -- "${receipt}"' EXIT
python3 -I -B scripts/ci/release_contract.py settings-preflight \
  --repository snaraj/lidersea.com > "${receipt}"
python3 -I -B scripts/ci/release_contract.py settings-receipt \
  --receipt "${receipt}" --repository snaraj/lidersea.com
sha256sum "${receipt}"
```

The first command emits no receipt unless every live value is exact. The second
revalidates the closed schema offline. Post only the canonical receipt and its
digest; never post API tokens, actor IDs, App identifiers, raw rule responses,
or secret/variable values.

The exact successful receipt is:

```json
{
  "actions_allowed": "all",
  "actions_enabled": true,
  "actions_sha_pinning": true,
  "allow_deletions": false,
  "allow_force_pushes": false,
  "branch": "main",
  "bypass_actors": [],
  "can_approve_pull_request_reviews": false,
  "code_coverage_max_drop": null,
  "code_coverage_minimum": 80,
  "code_quality_severity": "errors",
  "code_scanning_tools": [
    {"alerts_threshold": "errors", "security_alerts_threshold": "high_or_higher", "tool": "CodeQL"}
  ],
  "default_workflow_permissions": "read",
  "dismiss_stale_reviews_on_push": false,
  "immutable_releases": true,
  "merge_methods": ["rebase", "squash"],
  "private_vulnerability_reporting": true,
  "repository": "snaraj/lidersea.com",
  "require_linear_history": true,
  "require_code_owner_review": false,
  "require_last_push_approval": false,
  "require_pull_request": true,
  "require_signatures": true,
  "required_approving_review_count": 0,
  "required_review_thread_resolution": true,
  "required_reviewers": [],
  "required_status_checks": [
    {"context": "analyze (go, manual)", "integration_id": 15368},
    {"context": "analyze (javascript-typescript, none)", "integration_id": 15368},
    {"context": "application", "integration_id": 15368},
    {"context": "chart", "integration_id": 15368},
    {"context": "container", "integration_id": 15368},
    {"context": "dependency-review", "integration_id": 15368},
    {"context": "security", "integration_id": 15368}
  ],
  "restrict_updates": false,
  "secret_scanning": true,
  "secret_scanning_push_protection": true,
  "strict_status_checks": true
}
```

The corresponding exact `Protect-Main` rule-type set is `creation`, `deletion`,
`non_fast_forward`, `pull_request`, `required_linear_history`,
`required_signatures`, `required_status_checks`, `code_scanning`,
`code_quality`, and `code_coverage`. The pull-request rule allows exactly
`rebase` and `squash`, zero formal approvals, no stale-review dismissal, no
code-owner or last-push approval, no team reviewers, and requires resolution of
all review threads. The preview security rules retain the observed exact
CodeQL `high_or_higher`/`errors` thresholds, code-quality `errors` severity, and
coverage floor `80` with `max_coverage_drop: null`. Required checks use
`strict_required_status_checks_policy: true` and
`do_not_enforce_on_create: false`; every context above is bound to GitHub
Actions integration ID `15368`.

## Current external blockers

A coordinator-owned read-only observation on 2026-08-14 confirmed immutable
releases, private vulnerability reporting, and Actions full-SHA pinning enabled;
Actions remain enabled with the `all` policy, the default workflow token remains
read-only and unable to approve reviews, and secret scanning plus push
protection remain enabled. The `platform-release` environment exists with a
custom selected-branch policy containing exactly `main`.

The active ruleset is still the inexact `Only-Owner-Push` rule rather than the
closed `Protect-Main` matrix. The environment currently has no App ID variable
and no App private-key secret because provisioning authority is still pending.
Those are external Ready blockers, not invitations for a workflow, author, or
reviewer to create credentials or change settings. Until all blockers are
resolved, the App-backed recheck fails closed before publication side effects.

Missing, extra, duplicated, name-only, foreign-integration, inverted, stale, or
bypass-bearing state fails closed. A successful receipt is necessary but not
sufficient for Ready: exact-head CI, current base, issue/PR milestone parity,
resolved findings, the bounded Main Worker receipt, and a fresh independent
approval are still required. The coordinator alone changes Draft/Ready state,
and the repository owner alone merges.

## Immutable artifact identity and recurring audit

The sole machine identity attached to a new GitHub Release is the canonical
`release-manifest.json` asset. It is created with mode `0600`, uploaded while the
Release is Draft, and validated by exact name, count, size, SHA-256 digest,
canonical bytes, and closed image/chart content before publication. Release
title and notes are informational and are never identity evidence. After REST
reports the Release as immutable and exact, the publisher unconditionally ends
by rebinding both the tag ref and annotated tag object to the exact source SHA.

Image and chart registry version tags are mutable aliases. The immutable
identities are their recorded `sha256:` digests. Publication gates the final
image digest for HIGH/CRITICAL vulnerabilities before signing. The scheduled
read-only release-integrity audit downloads and validates the sole manifest,
rebinds the annotated Git tag, verifies both aliases still resolve to their
recorded digests, verifies image/chart signatures, the exact two-platform SBOM
and provenance set, the chart digest, and rescans the image by immutable digest.

GitHub documents the immutable-release control and its protected tag/asset
behavior in [Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
and documents strict required checks in the
[repository rulesets REST contract](https://docs.github.com/en/rest/repos/rules).
