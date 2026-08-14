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
| Successful-main run binding and manual/unmerged dispatch denial | |
| Settings-token isolation and exact settings receipt | |
| Manifest draft/upload/publish and terminal tag rebind | |
| Final-digest vulnerability gate and scheduled integrity audit | |
| Required CI, coverage, security, and quality checks | |

## Exact-head review

- `requires-review` applied only after author completion: pending/yes
- Independent normal-comment verdict bound to exact head: pending
- Main Worker bounded receipt bound to exact head: pending
- Base freshness and successful required checks re-verified before Ready: pending

Adversarial reviewer receipt (normal comment; findings/evidence may follow):

```text
HEAD: <40-lowercase-hex>
VERDICT: APPROVE | REQUEST-CHANGES
- <distinct context> (adversarial reviewer)
```

Main Worker receipt (normal comment; exact field values and order):

```text
HEAD: <40-lowercase-hex>
ROLE: MAIN-WORKER
VERDICT: PASS | BLOCK
SCOPE: architecture,merge-order,authority,settings,base-freshness,required-checks
- <distinct context> (Main Worker)
```

Any head change invalidates both receipts. Only the coordinator may apply
`requires-review` or change Draft/Ready state after author completion, exact-head
CI, current-base verification, and the external settings boundary are all exact.

## Residual risks

## Rollback
