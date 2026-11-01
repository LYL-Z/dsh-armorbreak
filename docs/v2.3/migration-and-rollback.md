# V2.3 migration and rollback plan

## Data compatibility boundary

M1–M6 add analyzer manifests, result schemas, discovery status metadata, and a fixed MCP `armorbreak_workflow` route. They do not change `CORE_VERSION`, protocol v1, task-store layout, or the persisted user-data schema. No automatic user-data migration is implemented.

This claim is bounded to inspected source and the isolated candidate drill below. It is not a compatibility guarantee for arbitrary external profiles or historical data corpora.

## Real isolated candidate drill

`docs/v2.3/evidence/p0-h/real-package-upgrade-rollback.json` records a Windows x64 / Node 24.16.0 run using the read-only GitHub v2.2.0 asset (SHA-256 `5e5aca98da18d4f0cb17db71cf57c5577f8f8f64810a30844bd5237b4ed7b630`) and a reproducible V2.3 candidate from source `34b431931857e786b77ff28c90610857b8c8844c` (archive SHA-256 `f23b79948faf2d53164dddddeea37a00c0625c758eb02dee9542678cd0ce779d`). The synthetic V2.2 task/report and configuration were created only in an isolated temporary profile, not a real user profile or formal installation.

Observed checks passed: V2.2 backup/read; V2.3 archive extraction and CLI startup; old task/report reads; MCP initialization and foreign-session denial; host configuration doctor; current-user-only ACL on workspace/config; outside-workspace target rejection; candidate corruption rejected before candidate startup; V2.2 package remained usable; rollback reselected and restarted the preserved V2.2 package; task-tree, config, and report hashes matched before/after. The temporary workspace was removed. The captured evidence redacts local account and temp path names while retaining normalized ACL entries and output hashes.

This was a real package archive deployment in an isolated test directory, not a product updater or OS installer. Rollback exercised side-by-side package selection and configuration restoration. No second Windows user account was available for an impersonated ACL denial test. No real user data or formal V2.2 installation was touched.

## Future owner-approved installation

1. Record the installed version and verify candidate SHA-256, exact source, SBOM, and provenance.
2. Close ArmorBreak/DSH processes. Back up the DSH profile, ArmorBreak state root, workspace metadata, task/report/evidence trees, and user configuration to a separate protected location. Do not include secrets in issue/CI artifacts.
3. Install side-by-side or in a new versioned directory. Preserve the prior package and backup unchanged.
4. Start from a copied profile. Check health, capability listing, old task/report reads, MCP initialization, principal/session restrictions, ACLs, and policy denials.
5. Inject a pre-activation failure, confirm the previous package remains usable, then test rollback and compare hashes before any user-profile switch.
6. Switch only after all copied-profile checks pass; retain the backup until owner acceptance.

The procedure above is operational guidance. The real isolated drill does not certify a future OS-level installer, a second-account security boundary, or arbitrary external user-data compatibility. Release remains `NOT_READY` until all other required gates, independent review, exact CI and maintainer authorization are closed.
