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
  source commit; only `docs/v2/acceptance/**` may differ; `readiness.json` is
  not accepted as an evidence-only path;
- **code/security change:** neither mode applies; evidence must match the code
  commit or be regenerated for it.

For docs-only mode the validator:

1. checks that the base is an ancestor of HEAD;
2. computes `git diff --name-only --no-renames <base>..HEAD`;
3. accepts only README Markdown files and non-protected `docs/**/*.md` files;
4. verifies every file pinned by `evidence-manifest.json` still matches its
   SHA-256 and size;
5. verifies the TAP hash and permits the baseline test-report commit only in
   the path-verified docs-only mode;
6. disables the separate acceptance-only “evidence ancestor” exception while
   docs-only mode is active;
7. rejects Git replace refs and custom `GIT_REPLACE_REF_BASE`.

PR titles, labels, and commit messages are not consulted.

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
