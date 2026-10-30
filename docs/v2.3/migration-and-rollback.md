# V2.3 migration and rollback plan

## Current data changes

The M1–M6 implementation adds analyzer manifests, result schemas, status metadata in discovery responses, and a fixed MCP `armorbreak_workflow` route. It does not change `CORE_VERSION`, protocol v1, existing task-store files, or an on-disk user-data schema. No automatic user-data migration is required or performed by this change. New analysis result payloads use versioned schemas under `docs/v2.3/schemas/`.

This conclusion is bounded to the inspected source at M6 SHA `965fbe4fa9abd2af73644865a56d8db64c8a6089`; the complete historical user-data compatibility matrix has not been run on external user stores.

## Upgrade procedure for a future owner-approved package

1. Record the current package/source version and verify the candidate's published SHA-256 and provenance.
2. Close ArmorBreak/DSH processes cleanly. Copy the DSH profile, ArmorBreak state root, workspace metadata, task reports, evidence, and user configuration to a separate backup location. Do not copy secrets into issue or CI artifacts.
3. Install the package side-by-side or into a new versioned directory first. Keep the prior package and backup unchanged.
4. Start with a copied test workspace and verify Core health, capability listing, old task/report reads, MCP initialization, and policy rejection paths before using a real workspace.
5. Switch the active package only after the copied-workspace checks pass; retain the backup until user acceptance.

No installer/package migration was built or exercised as part of this branch, so these are operational precautions, not a verified installer procedure.

## Rollback

1. Stop the candidate process and preserve its logs and task state for diagnosis.
2. Restore the previous package and its matching backed-up configuration/state as a set; do not load candidate-written state into the old package unless the owner has confirmed compatibility.
3. Reopen the previous workspace copy and verify old reports/evidence can be read.
4. Keep candidate output and migration records separately. Do not delete or rewrite historical evidence to make rollback appear clean.

No destructive in-place migration currently exists, and no restore/rollback drill has been executed for V2.3. The release gate remains `NOT_READY` until an owner-approved package has a real upgrade and rollback exercise.
