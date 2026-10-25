# Docs-only evidence reuse (proposal)

Status: **review required; not merged**. This document describes the proposed
change to the commit-bound evidence validator. It does not change GA status,
release gates, or acceptance evidence.

## Problem

A documentation-only PR changes files such as `README.md`, but the evidence
manifest is intentionally bound to a source/evidence baseline. Reusing the
baseline is safe only when the PR provably does **not** change source, build,
security, acceptance metadata, or evidence content.

## Rule

The validator supports three explicit modes:

- **docs-only:** `--allow-docs-only`, validated against a trusted target-branch
  base SHA (`EVIDENCE_BASE_SHA` from the pull-request event);
- **evidence-only:** `--allow-evidence-only`, validated against the manifest's
  source commit; `docs/v2/acceptance/**` may differ, and generated readiness
  metadata is accepted only with the explicit `--allow-readiness` option.
  V2.2 Stable writes `stable-readiness.json`; the historical Full GA
  `readiness.json` snapshot remains unchanged;
- **code/security change:** neither mode applies; evidence must match the code
  commit or be regenerated for it.

For pull requests the base is `github.event.pull_request.base.sha`; for pushes
it is `github.event.before` (guarded to the same branch). For docs-only mode the
validator:

1. checks that the base is an ancestor of HEAD and, with `--require-clean`,
   that the worktree is clean;
2. computes `git diff --name-only --no-renames -z <base>..HEAD`, rejecting
   backslash paths and non-regular blobs such as gitlinks;
3. accepts only README Markdown files and non-protected `docs/**/*.md` files;
4. verifies every file pinned by `evidence-manifest.json` still matches its
   SHA-256 and size, including the required test report and TAP;
5. verifies the TAP hash and requires the test-report commit to equal the
   manifest source commit when a baseline is reused;
6. disables the separate acceptance-only “evidence ancestor” exception while
   docs-only mode is active;
7. rejects Git replace refs and custom `GIT_REPLACE_REF_BASE`.

PR titles, labels, and commit messages are not consulted.

Docs-only reuse additionally requires the **target base** to be evidence-backed:
the path set from `manifest.commit..base` may contain only acceptance evidence,
generated readiness metadata, or previously merged docs-only Markdown. Any
source, CI, build, security, or other change in that range rejects the PR.

The release-gate step does not skip gate evaluation: for docs-only PRs it
computes the full gates at the target base and emits
`applicability: DOCS_ONLY_BASE_GATES`; `localChecksPass` is inherited from that
base report. A docs-only report never grants release authorization: `releasable`
stays false until the exact source commit and artifact have trusted provenance.
If the base local checks do not pass, the docs PR is blocked. Tags always
evaluate gates at the tag commit and are never treated as docs-only.

## Residual trust

The workflow runs validation code from the PR checkout. `--require-clean`,
`GITHUB_SHA == HEAD`, and `.github/CODEOWNERS` reduce accidental/dirty-tree
risk, but a repository with no enforced ruleset can still run a PR-modified
workflow. A protected branch/ruleset for `.github/workflows/**`,
`lib/release/**`, `scripts/v2/**` and acceptance evidence is required before CI
is treated as an external trust boundary.

Evidence files, including the manifest and TAP, are mutable by design in this
repository. Evidence-only review should be code-owner reviewed; signed or
append-only CI provenance would be a stronger future control.

## Never eligible for docs-only reuse

- `.github/**`, `package.json`, lockfiles, build configs;
- `lib/**`, `packages/**`, `scripts/**`, `tools.js`, production source;
- `SECURITY.md`, security model/threat-model documents;
- `docs/v2/acceptance/**`, `docs/v2/tasks/**`, `docs/v2/generated/**`;
- `docs/v2/release/**` except `docs/v2/release/user-guide.md`;
- any evidence JSON/TAP, SBOM, tag, or release metadata.

The current source/evidence baseline still controls code PRs. A code or safety
configuration PR must carry evidence bound to that code; it cannot inherit an
older report.

## Negative tests

`tests/evidence-docs-only.test.mjs` covers:

- genuine docs-only diff accepted even with a misleading commit message;
- `SECURITY.md` rejected;
- production source rejected;
- release-gate script rejected;
- evidence TAP rejected;
- `.github/workflows/ci.yml` rejected;
- generated acceptance metadata rejected;
- Git replace refs rejected;
- evidence-only append accepted after a fixed source baseline;
- source change followed by evidence still rejected;
- validator rejects a protected diff and requires a target base.

## Residual risk

`EVIDENCE_BASE_SHA` is trusted CI input. The workflow that supplies it must be
protected by branch/ruleset review. Local callers can supply any base argument;
local validation is not a security boundary. CI remains authoritative.

## Validation

```powershell
node --test tests/evidence-validator.test.mjs tests/evidence-docs-only.test.mjs
node scripts/v2/validate-evidence.mjs --allow-docs-only --base <base-sha>
```

No commercial API, external service, or evidence mutation is used.
