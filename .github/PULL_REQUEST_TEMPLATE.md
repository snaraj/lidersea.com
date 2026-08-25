<!-- Agent-authored PRs open Draft. Delete no section; write "none" where empty. -->

## Summary

## Issue

Closes #<!-- same-repository issue number -->

- Issue milestone: `vX.Y.Z`
- PR milestone: `vX.Y.Z` (must equal the issue milestone and next patch)

## Exact identity and release consequence

- Protected base: `main` @ <!-- 40-hex sha -->
- Exact head: <!-- 40-hex sha; update after every author push -->
- Next patch release: `vX.Y.Z`
- numeric `VERSION`/chart/changelog `X.Y.Z` maps exactly to plain `vX.Y.Z`
  Git/image tags and numeric Helm OCI chart tag: yes/no
- Release publication is separate from deployment/promotion: confirm

## Scope and exclusions

- Files owned:
- Deliberately excluded:
- Predecessors / successors / collision paths: none

## Evidence

| Command or check | Result |
| --- | --- |
| Release transition and hostile event/state suite | |
| Successful-main run binding and manual/unmerged dispatch denial; exact PR-gate/CodeQL jobs | |
| Settings-token isolation and exact settings receipt | |
| Exact production packages and aliases; signed SBOMs; bot-owned manifest draft/upload/publish and terminal tag rebind | |
| Final-digest vulnerability gate and scheduled integrity audit | |
| Required CI, coverage, security, and quality checks | |

## Exact-head review

- `requires-review` applied only after author completion: pending/yes
- Independent normal-comment verdict bound to exact head: pending
- Base freshness and successful required checks re-verified before Ready: pending

Adversarial reviewer receipt (normal comment; findings/evidence may follow):

```text
HEAD: <40-lowercase-hex>
VERDICT: APPROVE | REQUEST-CHANGES
Mutation audit: <mutants attempted and killed, or explicit no-finding scope>
Claim audit: <SUPPORTED / OVERSTATED results for every material claim>
- <distinct context> (adversarial reviewer)
```

Any head change invalidates the receipt. The author applies `requires-review`
only after the exact head, body, commits, and evidence are author-complete; the
reviewer removes it when posting either verdict. Only the coordinator may change
Draft/Ready state after independent approval, exact-head CI, current-base
verification, and the external settings boundary are all exact.

## Residual risks

## Rollback
