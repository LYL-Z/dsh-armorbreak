# V2.3.0 candidate license and redistribution inventory

Historical note: the initial package inventory was prepared for independent license review. It was not legal advice, complete notice clearance, or permission to distribute. The owner later authorized an `OWNER_APPROVED_SELF_REVIEW` policy; the exact S3 self-review and its limitations are recorded at the end of this file. Formal release remains `NOT_READY`.

## Observed candidate artifact

The archive details below describe the earlier 551-file deployment candidate and are retained as historical evidence. The current source packaging contract additionally requires installing production npm dependencies after extraction; see `portable-install.md`. A fresh exact-SHA archive and dependency installation record must be added after the new source commit.

The latest isolated real-package drill used an exact, reproducible candidate built on Windows x64 / Node 24.16.0 from source snapshot `7a78aef15e59f16f71b192089dcb82a81e811fb5`:

- Archive: local test candidate at `dist/armorbreak-portable-2.3.0.tar.gz`; 5,839,316 bytes; SHA-256 `cb9e9edef5fd677adbdee97e521f09a457505bee805db319719c206c579590fc`.
- Complete per-member manifest: 551 files, content-manifest SHA-256 `dacf07aa532495af0c4c49d1aaded5db13f379382cd8201a477774e112a16023`; committed snapshot at `evidence/p0-h/candidate-package-7a78aef.manifest.json`, file SHA-256 `46b607b92248c4bdab0bcadf25ed5c5b5f58223061eba36a5a34bde21ad7b981`.
- CycloneDX 1.5 SBOM SHA-256 `4579399cf0df2608106cad5ace01aad13e68399c9cc7e94e652bb3416966b886`; committed copy at `evidence/p0-h/candidate-package-7a78aef.sbom.cdx.json`.
- Builder result: reproducible `true`, clean-room extraction and CLI startup `PASS`, 53 registered capabilities. Production signature: absent. The valid Ed25519 signature uses a test key and is not a publisher identity.
- This is the package used in the latest real V2.2-to-V2.3 isolated test. It is a local unsigned test candidate, not the final main/tag build. The final release artifact/SBOM must be rebuilt from the actual release commit and independently inspected; no GitHub attestation exists.

## Contents and exclusions observed from the archive manifest

The actual archive inventory contains 551 files: first-party JS/MJS/TS/Java/Python sources, documentation, package manifests, schemas, plugin metadata and image assets. It contains no `.exe`, `.dll`, `.so`, `.dylib`, `.jar`, `.class`, `.zip`, `.7z`, `.bin`, `.wasm`, `.pyc`, or wheel files. `tests/`, `fixtures/`, `node_modules/`, `.github/`, and `docs/v2.3/evidence/` are excluded by the builder. The archive includes JavaScript adapters for optional tools and `scripts/ghidra/ExportSummary.java`; it does not include Ghidra, JDK, Zig, TShark/Wireshark, JADX, Syft, Semgrep, or Trivy binaries.

The generated CycloneDX 1.5 SBOM has the application subject bound to the archive SHA-256 and lists 13 internal `@armorbreak/*` package manifests plus included-file inventories. These nested manifests omit their own `license` field; the repository root declares MIT and includes `LICENSE`/`NOTICE`. An independent reviewer must verify that the repository-level MIT grant covers every included first-party file and that all notices are complete.

The root `package.json` pins TypeScript `5.9.3` as a runtime dependency and `package-lock.json` is included. `node_modules/typescript` is not bundled in the portable archive. The portable install contract now explicitly requires `npm install --omit=dev --ignore-scripts --no-audit --no-fund` after extraction; clean-room `source.symbols` JS/TS results are required to validate that route. The installed dependency graph and its complete transitive notices are a separate review scope from the archive.

The npm publication file allowlist includes project documentation but now excludes `docs/v2.3/evidence/m3/fixtures/**` through a scoped `.npmignore`. The current `npm pack --dry-run --json` after this rule reports 670 files, zero M3 fixture paths, zero `tests/` paths, and no `.exe`, `.elf`, `.macho`, or `.bin` paths. The original repository fixtures remain intact as test evidence; the revised package dry-run and exact file list must be captured against the committed source SHA.

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

The exact archive, per-member manifest and SBOM hashes, source commit, package path inventory, and clean-room result are recorded in `evidence/p0-h/candidate-package-7a78aef.json`, `candidate-package-7a78aef.manifest.json`, and `candidate-package-7a78aef.sbom.cdx.json`. The actual archive remains locally available at `dist/armorbreak-portable-2.3.0.tar.gz`; its SHA is recorded in both the build record and the real Windows deployment record `evidence/p0-h/real-package-upgrade-rollback.json`. The package is unsigned and no GitHub attestation was created. These developer-prepared inventories do not substitute for independent content/license review.

Useful reproduction commands from a committed source SHA:

```powershell
node scripts/v2/build-release.mjs --out dist --evidence dist/release-build.json --no-portable-evidence
tar -tzf dist/armorbreak-portable-2.3.0.tar.gz
Get-FileHash dist/armorbreak-portable-2.3.0.tar.gz -Algorithm SHA256
Get-FileHash dist/armorbreak-portable-2.3.0.tar.gz.sbom.cdx.json -Algorithm SHA256
npm pack --dry-run --json
```

At this historical capture, no independent reviewer had confirmed license scope, copyrights, exception clauses, notices, or npm redistribution obligations. The owner-authorized self-review path supersedes the independent-review requirement, while the residual chain-of-title and notice limitations remain disclosed below.

## Current exact-source owner-approved self-review inventory (S3)

The following is the actual S3 package capture and supersedes older package counts for this source snapshot. It remains an implementation-agent inventory, not independent legal approval.

- Reviewed source: `8f4bbb752f12310ce9accb3120f9c11ddc15d3ba`.
- Portable candidate: 5,904,345 bytes, SHA-256 `0b95d7f58dddd49a2f2e0ccc3a05606cd96a3b863dc59bedbac2523c991809f7`; per-member manifest and CycloneDX SBOM are `candidate-package-8f4bbb7.manifest.json` and `candidate-package-8f4bbb7.sbom.cdx.json`.
- Portable contents: 556 files, no `node_modules` directory and no third-party executable/library payload. The supported install procedure extracts the archive then installs the declared production dependency TypeScript 5.9.3. A real clean-room run installed it, parsed JS and TS, completed an L0 workflow, and read task/report evidence. The test-key Ed25519 signature in builder evidence verifies the local mechanism only; it is not a maintainer or production signature.
- npm dry-run: 663 files / 9,288,509 unpacked bytes. Exact path/size/mode inventory and exclusions are in `evidence/p0-h/npm-package-8f4bbb7.json`; it contains zero test paths, zero M3 binary fixture paths, zero executable/library/binary paths, and no self-inventory. The npm package is broader than the portable runtime archive and includes source-adjacent scripts and documentation.
- Dependency: TypeScript `5.9.3`, Apache-2.0, one root runtime dependency, lock integrity present. The lock URL is `https://registry.npmmirror.com/typescript/-/typescript-5.9.3.tgz`; the clean-room install requested `https://registry.npmjs.org`, but npm follows the lock URL. This difference is disclosed. `npm audit --registry=https://registry.npmjs.org` reported zero advisories at the recorded capture time; that result is not a legal conclusion.
- Optional Ghidra 12.1.4, JDK 21, Zig, TShark/Wireshark, JADX, Syft, Semgrep and Trivy binaries are not included in either tested distribution. The included adapter/source code does not grant rights to redistribute those external tools. The repository test fixtures remain in source control but are not in the npm package or portable artifact.
- Root `LICENSE` declares MIT and `NOTICE` is included. Internal `@armorbreak/*` manifests do not each declare an SPDX identifier. This review found no contradictory license declaration in the inspected package inventory, but cannot independently certify copyright provenance, author identity, or chain of title for every file. No legal opinion is claimed.

Exact S3 file/hash evidence: `candidate-package-8f4bbb7.json`, `candidate-package-8f4bbb7.manifest.json`, `candidate-package-8f4bbb7.sbom.cdx.json`, `portable-cleanroom-8f4bbb7.json`, and `npm-package-8f4bbb7.json`. The Windows deployment/rollback evidence is `evidence/p0-h/real-package-upgrade-rollback.json`. The owner-approved license self-review is `evidence/p0-h/license-review-final.json`; it records `IMPLEMENTER_AI_SELF_REVIEW` and `independentHumanReview=NOT_PERFORMED`.

### S4 exact-source refresh

The release-gate PR blocker wording changed in source S4, so the candidate package and npm file inventory were rebuilt and recaptured instead of reusing S3:

- Source: `73741e494f78e8eef49e9498e6528dbe6d8cf8ee`.
- Portable archive: 5,904,345 bytes, SHA-256 `238cf6d6e6be15c09fbad6029842e6c4d483150c0f4d29446d279f27a1545a08`.
- Manifest: `candidate-package-73741e4.manifest.json`, SHA-256 `01eb72b86a88baf295ce0b81975f253492a997f1e0425ae7f3d5c6d62c84d10e`.
- SBOM: `candidate-package-73741e4.sbom.cdx.json`, SHA-256 `0c97f4053abd7d5c3c617dc9c641b4cd55158360cb998fdc004b020997c75f16`.
- Clean-room and rollback evidence: `portable-cleanroom-73741e4.json` and `real-package-upgrade-rollback-73741e4.json`; each records the exact S4 source and package SHA. The real isolated drill verified the published v2.2.0 asset read-only against `5e5aca98da18d4f0cb17db71cf57c5577f8f8f64810a30844bd5237b4ed7b630`.
- npm dry-run: 663 files / 9,288,447 unpacked bytes; zero tests, M3 binary fixtures, or binary payloads; complete inventory `npm-package-73741e4.json`.

The lockfile still resolves TypeScript through `registry.npmmirror.com` with the lock integrity pinned, although the clean-room install passed `--registry=https://registry.npmjs.org`. This is transparent in the inventory, not silently treated as an official-registry download. The owner-approved license review is a developer self-review, not an independent legal opinion or chain-of-title certification.
