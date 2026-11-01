# V2.3.0 candidate license and redistribution inventory

Status: developer-prepared package inventory for independent license review. This is not legal advice, complete notice clearance, or permission to distribute. It is not an independent audit. Formal release remains `NOT_READY`.

## Observed candidate artifact

The real package drill used an exact, reproducible candidate built on Windows x64 / Node 24.16.0 from source commit `34b431931857e786b77ff28c90610857b8c8844c`:

- Archive: `armorbreak-portable-2.3.0.tar.gz`; SHA-256 `f23b79948faf2d53164dddddeea37a00c0625c758eb02dee9542678cd0ce779d`.
- SBOM: `armorbreak-portable-2.3.0.tar.gz.sbom.cdx.json`; SHA-256 `2b589cdb4ea50ef3f2859f47a0598ccff57ebca9e62b1eecd1e8d6ebd23e7a7a`.
- Builder result: 550 committed files, reproducible `true`, clean-room extraction and CLI startup `PASS`, 53 registered capabilities. Production signature: absent. The builder's ephemeral test-key signature is not a publisher identity.
- This is the package used in the real V2.2-to-V2.3 isolated test; it is a candidate snapshot, not the final main/tag build. The final release artifact and its SBOM must be regenerated from the exact release commit and independently inspected.

## Contents and exclusions observed from the archive manifest

The actual archive inventory contains 550 files: first-party JS/MJS/TS/Java/Python sources, documentation, package manifests, schemas, and plugin metadata. It contains no `.exe`, `.dll`, `.so`, `.dylib`, `.jar`, `.class`, `.zip`, `.7z`, `.bin`, `.wasm`, `.pyc`, or wheel files. `tests/`, `fixtures/`, `node_modules/`, `.github/`, and `docs/v2.3/evidence/` are excluded by the builder. The archive includes JavaScript adapters for optional tools and `scripts/ghidra/ExportSummary.java`; it does not include Ghidra, JDK, Zig, TShark/Wireshark, JADX, Syft, Semgrep, or Trivy binaries.

The generated CycloneDX 1.5 SBOM has the application subject bound to the archive SHA-256 and lists 13 internal `@armorbreak/*` package manifests plus included-file inventories. These nested manifests omit their own `license` field; the repository root declares MIT and includes `LICENSE`/`NOTICE`. An independent reviewer must verify that the repository-level MIT grant covers every included first-party file and that all notices are complete.

The root `package.json` pins TypeScript `5.9.3` as a dependency and `package-lock.json` is included. `node_modules/typescript` is not in the portable archive, and the SBOM does not list TypeScript as a bundled component. A user installing through npm resolves this dependency separately; that installation path and its complete transitive notices require a distinct review. The archive clean-room test verifies CLI startup/capability listing, not that `source.symbols` can load TypeScript without dependency installation.

## Declarations and reviewer follow-up

| Component / scope | Observed package status | License source/status | Required independent follow-up |
|---|---|---|---|
| ArmorBreak root source | Included | Root `package.json`: MIT; `LICENSE` and `NOTICE` included | Check copyright provenance and whether root MIT grant covers all 13 nested packages and every included file |
| 13 internal `@armorbreak/*` packages | Package manifests and sources included; manifests omit `license` fields | Repository-level MIT is the only bundled declaration | Confirm rights, author provenance and required notices for each package |
| TypeScript 5.9.3 | Version and lock entry included; npm dependency; module bytes absent from archive | Upstream package declares Apache-2.0 | Review the npm install distribution path, lock tree and any required Apache NOTICE; verify runtime install instructions match actual behavior |
| Ghidra and `ExportSummary.java` | Java adapter source included; Ghidra application/binaries absent | Exact adapter source provenance and upstream Ghidra distribution version still need independent confirmation | Inspect source provenance and exact Ghidra/JDK license and third-party notices for the supported host setup |
| Temurin JDK 21 | Not bundled | Not applicable to archive; external runtime source not fixed by archive | Review the exact downloaded distribution and GPL Classpath Exception / third-party notices before recommending redistribution |
| Zig | No Zig toolchain or compiled fixture included in archive | Not bundled | Verify exact fixture-generation tool license and whether external derived bytes have any separate obligations; tests/fixtures are excluded |
| TShark / Wireshark | Adapter source included; binaries/libraries absent | External tool, not bundled | Review exact package and plugin licensing if a future installer bundles it |
| JADX, Syft, Semgrep, Trivy | Adapter source included; binaries/libraries absent | External tools, not bundled | Check exact versions/editions and notices if future packaging changes include them |
| Tests and binary fixtures | Excluded from observed portable archive | No fixture bytes redistributed in this archive | Review repository fixture provenance separately for test distribution or future inclusion |
| npm dependency graph | Root lockfile included, no `node_modules` or bundled npm dependencies | TypeScript is the only root runtime dependency declared in the observed manifest | Produce and review the exact installed npm dependency tree/SBOM and notices; do not infer it from portable archive contents |

## Reproduction and evidence boundary

The observed archive and SBOM hashes, exact source commit, package path inventory, and clean-room result are in the build output `dist/release-build.json` and were checked against the real Windows deployment record `docs/v2.3/evidence/p0-h/real-package-upgrade-rollback.json`. The build output folder is generated and not committed as release evidence. The committed drill evidence retains the archive hash and normalized findings; it does not substitute for an independent content/license review.

Useful reproduction commands from a committed source SHA:

```powershell
node scripts/v2/build-release.mjs --out dist --evidence dist/release-build.json --no-portable-evidence
tar -tzf dist/armorbreak-portable-2.3.0.tar.gz
Get-FileHash dist/armorbreak-portable-2.3.0.tar.gz -Algorithm SHA256
Get-FileHash dist/armorbreak-portable-2.3.0.tar.gz.sbom.cdx.json -Algorithm SHA256
npm pack --dry-run --json
```

No independent reviewer has confirmed license scope, copyrights, exception clauses, notices, or npm redistribution obligations. P0-3 therefore remains open.
