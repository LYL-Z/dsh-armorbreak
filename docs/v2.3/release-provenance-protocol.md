# V2.3.1 release provenance and authorization protocol

Status: V2.3 release contract, updated under the owner's explicit 2026-11-04 approval for `OWNER_APPROVED_SELF_REVIEW`. This is a policy change, not an independent audit or cryptographic owner signature. The candidate remains `NOT_READY` until exact-main and tag evidence exists.

## Objects and order

| Object | Created when and where | Bound identity | Signature / trust boundary |
|---|---|---|---|
| Source commit `S` | PR source changes are committed on the V2.3 branch; all executable source, release gate, workflow, and security policy changes belong here | Full Git commit SHA; exact PR CI checks this SHA | Git commit identity is not sufficient approval; GitHub CI records the tested SHA |
| Evidence commit `E` | After `S`, append only reviewed evidence and final report/matrix/manifest files on the same PR branch | Full Git SHA; `S` must be an ancestor; `git diff S..E` must contain only paths accepted by `v23-provenance.mjs` | Evidence hashes in the manifest bind bytes; evidence commit cannot modify validators, workflows, or source |
| Main merge commit `M` | The authorized maintainer merges the PR after required PR checks and review protection are satisfied. Use a merge commit that preserves `E` as an ancestor and has the same tree as `E` | Full Git SHA on `main`; require `E` ancestor of `M` and `tree(E) == tree(M)` | GitHub branch protection and recorded PR review/merge event; no admin bypass |
| Candidate package and SBOM | Trusted main-branch workflow checks out `M`, runs all required main checks, builds deterministic candidate package and SBOM into workflow artifacts | SHA-256 for each object; CycloneDX package subject digest equals the candidate archive digest; both list the same `M` | CI artifact storage is not by itself an attestation |
| GitHub build provenance attestation | Same trusted workflow signs the exact package after building from `M` | Attestation subject digest equals package SHA-256; source repository is this repository; source ref is `refs/heads/main`; source digest is `M` | Sigstore/GitHub-issued certificate and transparency timestamp are checked by `gh attestation verify`; signer workflow is pinned to `.github/workflows/v2.3-main-gate.yml` |
| Security and license self-review | The implementing AI performs an evidence-backed self-review on `S`, `E`, `M`, final package, and SBOM; it is explicitly labeled `IMPLEMENTER_AI_SELF_REVIEW` and `NOT_PERFORMED` for independent human review | Reports bind source/evidence SHAs, commands, tool versions, findings, severity, fixes/retests, license inventory, and unresolved boundaries | This is lower assurance than independent review. The owner accepts that risk; no reviewer key, human certification, or reviewer signature is fabricated |
| Rollback evidence | The real isolated candidate-package drill completes in the exact tag workflow against the exact-main package | Evidence path/hash, candidate package digest, rollback result, and observed OS permissions are included in the envelope | Evidence is accepted only after actual package extraction/installation/start/read/MCP/rollback, not a synthetic installer state machine |
| External authorization envelope | Created in the exact `v2.3.1` Tag workflow after exact-main CI, package/SBOM attestation, and a real Windows package rollback pass | Claims include repository, tag, `S`, `E`, `M`, package version/digests, SBOM digest, CI run ID, review/license/rollback hashes, release model, and owner event sender ID | GitHub OIDC/Sigstore attests the detached envelope from the exact tag ref and digest. The workflow accepts only the repository owner's GitHub actor ID. This proves platform event/workflow provenance, not a private-key owner signature or who physically operated the account |
| Tag `v2.3.1` | Only after PR checks, exact-main build/provenance, and the real Windows deployment/rollback job all pass | Tag peels to frozen main commit `M`; `E` is an ancestor of `M` and has the same tree | GitHub tag workflow and a separately confirmed v2.3.1 Tag ruleset are the trust boundaries; do not move or delete the tag after creation. The failed v2.3.0 Tag remains intact |
| Release verification run | Triggered by exact tag, checks out `M` and downloads the protected envelope/package artifacts | Requires `GITHUB_REF=refs/tags/v2.3.1`, `GITHUB_SHA=M`, `S` ancestor of `E`, `E` ancestor of `M`, identical `E/M` trees, and all signed claims to match | Recomputes every local digest, calls `gh run view` for successful exact-main CI, and calls `gh attestation verify` against the actual package path, pinned signer workflow, `refs/heads/main`, and source digest `M` |

## Why the authorization is external

`release-authorization.json` must not state that its own commit SHA equals the SHA of the commit containing it: changing the JSON changes the Git tree and therefore changes that commit SHA. The repository may contain review reports and a non-authoritative evidence index, but release authorization is a detached signed envelope created after `M` exists. The signed claims bind `S`, `E`, and `M`; the envelope file itself has its own SHA-256 and protected storage identity recorded by the release run. No future commit SHA is guessed, and an older envelope cannot validate for a new source/evidence/main tree because its signature binds all three full SHAs and all evidence hashes.

## Release gate verification contract

Before it can return `READY`, `scripts/v2/v23-release-gate.mjs --release` must:

1. Require P0-H `COMPLETE`, package version `2.3.1`, exact tag `v2.3.1`, and exact full commit SHA. The frozen source/matrix `releaseState` remains `NOT_READY`; final `READY` exists only in the detached, verified external envelope, so historical Markdown can retain old state records.
2. Confirm the tag peels to `M`; verify `S..E` contains no source/workflow/validator/security-gate edits; verify `S` is ancestor of `E`, `E` is ancestor of `M`, `tree(E) == tree(M)`, and `S..M` contains no source/workflow/validator/security-gate edits.
3. Verify the external envelope's GitHub OIDC attestation, exact signer workflow, `refs/tags/v2.3.1`, tag commit digest, owner actor ID, and `OWNER_APPROVED_SELF_REVIEW` claims. Security and license claims must say `IMPLEMENTER_AI_SELF_REVIEW`, `independentHumanReview=NOT_PERFORMED`, and `OWNER_ACCEPTED_RISK`; missing or inconsistent claims fail closed.
4. Rehash review, license, drill, package and SBOM files. Reject paths outside the repository or any symlink in an evidence path. Require real package rollback and permission observations.
5. Query GitHub for the exact `main` push run, require success on `M`, and require all four Ubuntu/Windows × Node 22/24 jobs to pass.
6. Verify the actual package file with `gh attestation verify --repo LYL-Z/dsh-armorbreak --signer-workflow LYL-Z/dsh-armorbreak/.github/workflows/v2.3-main-gate.yml --source-ref refs/heads/main --source-digest M --format json`. A JSON field saying `PASS` is not a substitute for this verification.

## Harmless local protocol exercise

The unit test suite exercises the PR → main candidate → release decision transition and fail-closed claims. GitHub Tag CI itself must create and verify the OIDC-attested envelope; no local simulation substitutes for that run. This does not create an independent review or human signature.

The tag workflow creates and verifies the final envelope. For a post-run independent reproduction, download the exact tagged envelope and package/SBOM artifacts, then run these checks from the tag checkout:

```powershell
$env:GITHUB_REF = 'refs/tags/v2.3.1'
$env:GITHUB_SHA = '<full M commit SHA>'
$env:V23_AUTH_ENVELOPE_PATH = '<downloaded tag-run authorization envelope path>'
node scripts/v2/v23-release-gate.mjs --release
```
