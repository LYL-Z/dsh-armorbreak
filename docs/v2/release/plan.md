# V2 Release Plan (M4-10)

**Status: RELEASED v2.0.0 (2026-10-21).** Tag `v2.0.0` points at merge commit `f96d03a`; GitHub Release `v2.0.0` contains bundle lock, SBOM, release gates, readiness, and evidence zip. All six gates PASS; no V1 tag was moved.

## Prerequisites (all must be true)

1. `docs/v2/acceptance/release-gates.json` → `localChecksPass=true`; this local
   consistency result is not release authorization. `releasable` remains false
   until the exact source commit and artifact have trusted provenance.
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

- **None for V2.0.0.** Real Desktop health + L0 E2E is recorded; all six legacy
  gates were PASS at v2.0.0.
- V2.0.1 evidence hardening is in progress on `feature/abu-universal`; this does
  not move the existing v2.0.0 tag.
- Performance regressions >10% (sast/workflow) unresolved is historical text;
  the latest comparison has no >10% regression. Verify with
  `performance-compare.json` before quoting this bullet.

## Commands

```powershell
node --test
node scripts/v2/core-benchmark.mjs
node scripts/v2/release-gates.mjs
node scripts/v2/build-bundle.mjs
node scripts/v2/build-sbom.mjs
```
