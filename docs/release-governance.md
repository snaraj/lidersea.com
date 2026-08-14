# Release-control readiness receipt

Every protected-`main` integration must remain able to publish one release,
including a one-commit squash and a multi-commit linear rebase. Repository code
validates either topology, but code on a pull-request branch cannot make its own
checks mandatory, require the branch to contain the latest protected base, or
make a GitHub Release immutable. Those are server controls and are therefore a
separate readiness boundary.

The automatic-release pull request must remain Draft until the repository owner
has configured and observed all of these controls:

- GitHub immutable releases enabled before the first affected Release is
  published. Enabling the control later does not retrofit a release that was
  already published.
- Exactly squash and rebase enabled; merge commits disabled in both repository
  settings and the active `Protect-Main` ruleset.
- Pull requests and linear history required on `main`.
- Every required PR and CodeQL job bound to the GitHub Actions integration,
  with strict current-branch testing enabled.
- Force pushes and deletion denied.
- No ruleset bypass actor and no `update` restriction that would require the
  repository owner to bypass the rules merely to merge a passing pull request.

The repository owner remains the only person who chooses squash or rebase and
performs the merge. The settings receipt grants no merge authority.

## Publication authority

The token-created annotated tag does not trigger a recursive push workflow.
The successful-main orchestrator therefore dispatches `release-publisher.yml`
on protected `main`, never on the new tag, and passes both the exact source SHA
and the authoritative completed PR-gate run ID. The publisher first runs an
unprivileged authorization job with only Actions/content read access. That job
GETs the run by ID and requires the exact repository and head repository,
workflow name and path, `push` event, completed/success state, `main` branch,
and source SHA. Only its exact output can unlock the separate
contents-write/packages-write/OIDC publication job.

`workflow_dispatch` remains callable through GitHub's normal interfaces, but
callability is not publication authority: an unmerged branch, pull-request
run, foreign workflow or repository, failed or incomplete run, stale SHA, and
mismatched run ID all fail before a privileged job starts. The protected-main
workflow identity signs the resulting artifacts; the annotated tag and every
artifact statement independently bind the authorized source SHA.

## Read-only authoritative preflight

The preflight uses `gh api --method GET` only, with GitHub REST API version
`2026-03-10`. It reads the repository settings, immutable-release setting,
ruleset inventory, and the one active repository-owned `Protect-Main` ruleset.
It does not create, update, or delete a setting, ref, Release, package, or other
resource. An authentication or schema error is a denial.

Run it only after the repository owner has made the required settings change in
GitHub. Keep the value-only receipt outside the repository and remove it after
recording the result on the pull request:

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
command revalidates the closed schema offline. Post the canonical receipt and
its digest as the bounded observation; never post API tokens, actor IDs, or a
raw ruleset response.

The exact successful receipt is:

```json
{
  "allow_deletions": false,
  "allow_force_pushes": false,
  "branch": "main",
  "bypass_actors": [],
  "immutable_releases": true,
  "merge_methods": ["rebase", "squash"],
  "repository": "snaraj/lidersea.com",
  "require_linear_history": true,
  "require_pull_request": true,
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
  "strict_status_checks": true
}
```

A read-only observation on 2026-08-13 found immutable releases disabled and an
active owner-bypass ruleset without required pull requests, strict current-base
status checks, or the closed no-bypass shape above. That observed state is a
Ready blocker; this repository change does not grant itself permission to alter
server controls.

Missing, extra, duplicated, name-only, foreign-integration, inverted, stale, or
bypass-bearing state fails closed. A successful receipt is necessary but not
sufficient for Ready: exact-head CI, current base, resolved findings, and a
fresh independent approval are still required. The coordinator alone changes
the Draft/Ready state, and the repository owner alone merges.

GitHub documents the immutable-release control and its protected tag/asset
behavior in [Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
and documents strict required checks in the
[repository rulesets REST contract](https://docs.github.com/en/rest/repos/rules).

- 5.6 Sol
