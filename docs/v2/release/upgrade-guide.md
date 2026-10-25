# V2 Upgrade / Rollback Guide (M4-11)

For the V2.2.0 Stable scope, obtain the portable archive and CycloneDX SBOM from the matching GitHub Release. Before extracting or installing, verify the published SHA-256 list and the GitHub attestation against the release's exact source commit and artifact digest. The release archive is not a substitute for a host-specific installation test; use only the hosts marked verified in the compatibility matrix.

## Before upgrade

1. Backup the DSH profile (`profile.json` + bundle directories).
2. Run read-only migration plan:
   `node scripts/v2/migrate.mjs --workspace <workspace>` (no `--apply`).
3. Inspect `docs/v2/acceptance/baseline.json` and the task schema version.
4. Confirm the current `armorbreak` preset and other bundles are recorded.

## Upgrade (test profile only until M4-10 gates pass)

1. `node scripts/v2/build-bundle.mjs`
2. Use the M2-12 profile adapter against an isolated test profile.
3. Verify other bundles/presets remain; run `node --test`.
4. Only after release gates: apply migration with explicit operator approval.

## Migration

- `--apply` writes backups and a `prepared` manifest before replacing task JSON.
- Crash/ENOSPC/EACCES/SIGKILL recovery: `recoverInterruptedMigrations`.
- `--rollback <manifest>` restores exact original bytes.
- On Linux, rollback fails closed if a migration path has a group/other-writable ancestor that another UID could rename, or a path component is owned by an unrelated non-root UID. WSL DrvFS mounts commonly report mode `0777`; move the workspace to a protected Linux filesystem before rollback if the command rejects that path. Keep the migration manifest and backups for recovery; do not manually delete them.

## Rollback

- Profile: restore backup profile.json; rerun bundle adapter if needed.
- Installer: `/armorbreak/actions` `install.rollback` or `TransactionalInstaller.rollback`.
- Migration: manifest rollback; never delete evidence/report bytes.

After updating, retain the previous package/archive and all profile, state, workspace, report, and migration backups until the new version completes the applicable host health check. If migration or install verification fails, use the matching installer rollback or migration manifest, then restore the backed-up profile/state only as documented by the host. Do not mix a backup with a different workspace or principal.

## Non-goals

- No automatic migration, no automatic install, no L3 restore on rollback.
