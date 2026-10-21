# V2 SBOM / License Audit (M4-12)

- Core runtime dependencies: **0** (`package.json` has no `dependencies`/`devDependencies`).
- SBOM: `docs/v2/release/sbom.spdx.json` (SPDX 2.3; external tools listed as NOT BUNDLED).
- External tools (TShark/Ghidra/JADX/Syft/Semgrep/Trivy) are optional, separately installed, and not redistributed by this bundle. Their licenses must be reviewed at distribution time.
- Release readiness: evidence-driven gates are implemented in `scripts/v2/release-gates.mjs`; v2.0.0 was published with six gates PASS. V2.0.1 re-validates them from the current commit's `evidence-manifest.json` and raw `test-report.tap`.
- No signed release artifact is produced until all evidence-driven gates pass.

## Commands

```powershell
node scripts/v2/build-sbom.mjs
node scripts/v2/check-release.mjs
```
