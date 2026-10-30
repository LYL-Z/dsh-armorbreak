# V2.3.0 candidate license and redistribution inventory

Status: developer inventory for independent legal/license review. It is not legal advice, a complete notice audit, or approval to distribute. Final artifact and SBOM have not yet been built for this PR HEAD; package contents and hashes must be recorded from the exact candidate artifact before any release decision.

## Current repository/package declarations

| Component | Observed declaration / source | Intended package status | Required follow-up |
|---|---|---|---|
| ArmorBreak repository code | Root `package.json` declares MIT; `LICENSE` and `NOTICE` are present | First-party program/source intended for distribution | Verify notices/copyright headers and all nested package files against final package inventory |
| TypeScript | Root dependency and lockfile pin `5.9.3`; package metadata identifies Apache-2.0 | Build/test compiler dependency; not vendored by the deterministic portable builder (`node_modules` is excluded) | Confirm whether npm package installation treats TypeScript as install dependency; settle runtime/dev dependency classification and include Apache NOTICE if redistributed |
| Ghidra | Optional external analyzer, preliminary SBOM describes Apache-2.0 | Not bundled; user-installed external tool | Verify version-specific upstream license and bundled extension/scripts, if any; never infer license from the product name alone |
| Eclipse Temurin JDK 21 | Host runtime needed for Ghidra integration | Not bundled | Obtain exact distribution and version license texts; confirm GPL Classpath Exception and third-party notices for the selected archive |
| Zig | Used to build/derive native test fixtures | Toolchain not bundled in portable product; fixture inclusion must be read from actual artifact | Verify the exact Zig version/license and whether any generated fixture embeds runtime/library code |
| TShark / Wireshark | Optional external protocol analyzer; `build-sbom.mjs` currently lists GPL-2.0-or-later | Not bundled | Verify exact package license, plugins, and that no redistributed binary/library is present |
| JADX | Optional Android analyzer; current SBOM helper lists Apache-2.0 | Not bundled | Verify version and notices; inspect final package for bundled output or copied code |
| Syft | Optional SBOM tool; helper lists Apache-2.0 | Not bundled | Verify version and notices if a distribution ever bundles it |
| Semgrep | Optional static-analysis tool; helper currently lists LGPL-2.1 | Not bundled | Verify edition/version-specific license; do not rely on a generic project-level identifier |
| Trivy | Optional scanner; helper lists Apache-2.0 | Not bundled | Verify version and notices if a distribution ever bundles it |
| Binary test fixtures | `docs/v2.3/fixture-catalog.json` and M3/M5 evidence identify fixture provenance and hashes | The V2 portable builder excludes `fixtures/` and `tests/`; this must be confirmed from actual archive inventory | Reconcile every fixture SHA/source/license. Generated-from-source does not automatically establish permission to redistribute source-derived binary bytes |
| npm transitive dependencies | `package-lock.json` currently pins the lock graph; runtime `dependencies` lists TypeScript only | Installed through npm in development or host package manager; not vendored into the portable archive | Generate the exact dependency tree/SBOM for the final published format; inspect each package's declared license and bundled notices |

## Current packaging observations

- `scripts/v2/build-release.mjs` selects committed Git blobs and excludes `.git`, `node_modules`, `dist`, `.github`, `fixtures/`, `tests/`, `docs/v2.3/evidence/`, and selected historical readiness files.
- It currently emits a CycloneDX 1.5 SBOM with package/file inventories and the candidate archive digest. Its known external-tool list is not proof that those tools are installed or included.
- `npm pack --dry-run` is a different package format: root `package.json` has an npm `files` allowlist that includes `docs` and `scripts`, but does not intentionally describe the deterministic portable release format. The result must not be confused with the portable candidate.
- The current repository `package.json` and `package-lock.json` still need the V2.3 version transition committed before a V2.3 candidate can be named as such.
- The final reviewed record must enumerate actual files from the built archive and npm package separately, identify every bundled third-party component, link the exact upstream license text/revision, preserve required notices, and attach SHA-256 values for artifact and SBOM.

## Final reconciliation commands

After a candidate is produced from a committed exact SHA:

```powershell
node scripts/v2/build-release.mjs --out dist --evidence dist/release-build.json --no-portable-evidence
tar -tzf dist/armorbreak-portable-2.3.0.tar.gz
Get-FileHash dist/armorbreak-portable-2.3.0.tar.gz -Algorithm SHA256
npm pack --dry-run --json
```

Save command output and exact source SHA as an append-only review fixture. Compare the archive path inventory with the SBOM's included-file inventory; do not treat package manifest or a hand-written external-tool list as a complete bill of materials.
