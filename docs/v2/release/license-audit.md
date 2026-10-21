# V2 SBOM / License Audit (M4-12)

- Core runtime dependencies: **0** (`package.json` has no `dependencies`/`devDependencies`).
- SBOM: `docs/v2/release/sbom.spdx.json` (SPDX 2.3; external tools listed as NOT BUNDLED).
- External tools (TShark/Ghidra/JADX/Syft/Semgrep/Trivy) are optional, separately installed, and not redistributed by this bundle. Their licenses must be reviewed at distribution time.
- Release readiness: `node scripts/v2/check-release.mjs` — currently **NOT READY** because M4 gates/tasks remain incomplete.
- No signed release artifact is produced until all gates pass.

## Commands

```powershell
node scripts/v2/build-sbom.mjs
node scripts/v2/check-release.mjs
```
