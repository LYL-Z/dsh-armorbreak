# V2 Release Plan (M4-10)

**Status: NOT RELEASABLE.** Current branch `feature/armorbreak-v2`, latest base 1.2.0; no V2 tag/release exists.

## Prerequisites (all must be true)

1. `docs/v2/acceptance/release-gates.json` → `releasable=true`.
2. M4-03/04/06/07/10/11/12 status DONE (not REVIEW).
3. Signed bundle lock + SBOM + license audit attached to the release.
4. Migration preview on a copy of real v1.2 data; no automatic apply.
5. Real Windows Desktop E2E: install → select armorbreak preset → model tool call → report; screenshot/log/evidence hashes.

## Rollout stages (manual only)

| Stage | Audience | Entry | Rollback |
|---|---|---|---|
| 1% | internal test profile | all gates PASS | restore profile backup + previous active pointer |
| 10% | opt-in testers | 1% no P0 for 48h | same |
| 50% | opt-in users | 10% no P0 for 72h | same |
| 100% | general | 50% no P0 for 7d | revert tag + profile rollback |

## Automatic rollback rules

- L3 bypass, model self-authorization, installer execution before approval, evidence-chain break, or auth/origin bypass: immediate rollback and release block.
- Migration failure: prepared manifest recovery; never leave half-migrated tasks.
- Offline core rate <95%: block rollout.

## Current blockers

- M4-06 real Desktop/model E2E BLOCKED.
- M4-03/04/07/10/11/12 remain REVIEW; no signed release artifact.
- Performance regressions >10% (sast/workflow) unresolved.

## Commands

```powershell
node --test
node scripts/v2/core-benchmark.mjs
node scripts/v2/release-gates.mjs
node scripts/v2/build-bundle.mjs
node scripts/v2/build-sbom.mjs
```
