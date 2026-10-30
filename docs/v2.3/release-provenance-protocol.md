# V2.3.0 release provenance and authorization protocol

Status: design contract for the future release path. This document does not authorize a tag, merge, package publication, or release. The present candidate remains `NOT_READY`.

## Objects and order

| Object | Created when and where | Bound identity | Signature / trust boundary |
|---|---|---|---|
| Source commit `S` | PR source changes are committed on the V2.3 branch; all executable source, release gate, workflow, and security policy changes belong here | Full Git commit SHA; exact PR CI checks this SHA | Git commit identity is not sufficient approval; GitHub CI records the tested SHA |
| Evidence commit `E` | After `S`, append only reviewed evidence and final report/matrix/manifest files on the same PR branch | Full Git SHA; `S` must be an ancestor; `git diff S..E` must contain only paths accepted by `v23-provenance.mjs` | Evidence hashes in the manifest bind bytes; evidence commit cannot modify validators, workflows, or source |
| Main merge commit `M` | A maintainer merges the PR after the PR checks are complete. Use a merge commit that preserves `E` as an ancestor and has the same tree as `E` | Full Git SHA on `main`; require `E` ancestor of `M` and `tree(E) == tree(M)` | The PR remains Draft until an authorized maintainer changes its state; this step is outside the current task |
| Candidate package and SBOM | Trusted main-branch workflow checks out `M`, runs all required main checks, builds deterministic candidate package and SBOM into workflow artifacts | SHA-256 for each object; CycloneDX package subject digest equals the candidate archive digest; both list the same `M` | CI artifact storage is not by itself an attestation |
| GitHub build provenance attestation | Same trusted workflow signs the exact package after building from `M` | Attestation subject digest equals package SHA-256; source repository is this repository; source ref is `refs/heads/main`; source digest is `M` | Sigstore/GitHub-issued certificate and transparency timestamp are checked by `gh attestation verify`; signer workflow is pinned to `.github/workflows/v2.3-main-gate.yml` |
| Independent review claims | Reviewers finish security and license reviews after inspecting `S`, `E`, `M`, final package, and SBOM; their report files are already stored in the tree shared by `E` and `M` | Signed claims contain `S`, `E`, `M`, report paths, and report SHA-256 values | Separate reviewer Ed25519 keys are supplied out of band to the release gate as trusted public keys. A same-agent/AI review cannot be labeled `INDEPENDENT_HUMAN` |
| Rollback evidence | The real isolated candidate-package drill completes before `E` is finalized | Signed claims bind evidence path/hash, candidate package digest, rollback result, and OS permission observations | Evidence is accepted only after actual package extraction/installation/start/read/MCP/rollback, not a synthetic installer state machine |
| External authorization envelope | Created after candidate, SBOM, attestation, CI and independent reviews are complete; stored as a protected Actions secret/input, not in the Git tree | Canonical `claims` include repository, tag, `S`, `E`, `M`, package version/digests, SBOM digest, CI run ID, review hashes, rollback hash, and authorization identity | Detached Ed25519 signatures cover canonical JSON claims. Security reviewer, license reviewer, and maintainer keys are trusted out of band. The envelope is not committed, so it never needs to contain its own containing commit SHA |
| Annotated signed tag `v2.3.0` | Only after the preceding checks and explicit maintainer decision | Tag object peels to `M`; `E` is an ancestor of `M` and both commits have the same tree | Git tag signature identifies the tagger; the tag is still not a release by itself |
| Release verification run | Triggered by exact tag, checks out `M` and downloads the protected envelope/package artifacts | Requires `GITHUB_REF=refs/tags/v2.3.0`, `GITHUB_SHA=M`, `S` ancestor of `E`, `E` ancestor of `M`, identical `E/M` trees, and all signed claims to match | Recomputes every local digest, calls `gh run view` for successful exact-main CI, and calls `gh attestation verify` against the actual package path, pinned signer workflow, `refs/heads/main`, and source digest `M` |

## Why the authorization is external

`release-authorization.json` must not state that its own commit SHA equals the SHA of the commit containing it: changing the JSON changes the Git tree and therefore changes that commit SHA. The repository may contain review reports and a non-authoritative evidence index, but release authorization is a detached signed envelope created after `M` exists. The signed claims bind `S`, `E`, and `M`; the envelope file itself has its own SHA-256 and protected storage identity recorded by the release run. No future commit SHA is guessed, and an older envelope cannot validate for a new source/evidence/main tree because its signature binds all three full SHAs and all evidence hashes.

## Release gate verification contract

Before it can return `READY`, `scripts/v2/v23-release-gate.mjs --release` must:

1. Require P0-H `COMPLETE`, package version `2.3.0`, exact tag `v2.3.0`, exact full commit SHA, and a report declaring `READY` without `NOT_READY`.
2. Confirm the tag peels to `M`; verify `S..E` contains no source/workflow/validator/security-gate edits; verify `S` is ancestor of `E`, `E` is ancestor of `M`, `tree(E) == tree(M)`, and `S..M` contains no source/workflow/validator/security-gate edits.
3. Verify reviewer and maintainer Ed25519 signatures over canonical claims with public keys supplied outside the checkout (`V23_SECURITY_REVIEWER_PUBLIC_KEY`, `V23_LICENSE_REVIEWER_PUBLIC_KEY`, `V23_MAINTAINER_PUBLIC_KEY`). Missing keys fail closed.
4. Rehash review, license, drill, package and SBOM files. Reject paths outside the repository or any symlink in an evidence path. Require real package rollback and permission observations.
5. Query GitHub for the exact `main` push run, require success on `M`, and require all four Ubuntu/Windows × Node 22/24 jobs to pass.
6. Verify the actual package file with `gh attestation verify --repo LYL-Z/dsh-armorbreak --signer-workflow LYL-Z/dsh-armorbreak/.github/workflows/v2.3-main-gate.yml --source-ref refs/heads/main --source-digest M --format json`. A JSON field saying `PASS` is not a substitute for this verification.

## Harmless local protocol exercise

The unit test suite creates a disposable local Git repository with a source commit `S`, a later evidence-only commit `E`, a merge commit `M` whose tree matches `E`, a temporary test tag named `test-v2.3.0`, and ephemeral Ed25519 keys. It verifies ancestry, tree identity, detached signature binding, and rejection after changing the signed `E`. This proves the local protocol mechanics only. It does not produce a GitHub Actions attestation, independent review, production signature, official V2.3 tag, or release evidence.

Example final verification commands (run only after the external records actually exist):

```powershell
$env:GITHUB_REF = 'refs/tags/v2.3.0'
$env:GITHUB_SHA = '<full M commit SHA>'
$env:V23_AUTH_ENVELOPE_PATH = '<protected downloaded envelope path>'
$env:V23_SECURITY_REVIEWER_PUBLIC_KEY = '<trusted Ed25519 public key PEM>'
$env:V23_LICENSE_REVIEWER_PUBLIC_KEY = '<trusted Ed25519 public key PEM>'
$env:V23_MAINTAINER_PUBLIC_KEY = '<trusted Ed25519 public key PEM>'
node scripts/v2/v23-release-gate.mjs --release
```
