# SECURITY.md support matrix — review proposal

Status: **proposal only; requires maintainer and security-policy approval before
editing `SECURITY.md`.** This document does not change the current security
policy, does not promise a maintenance window, and does not declare any version
end-of-life.

## Why this exists

`SECURITY.md` currently lists only `1.0.x` in Supported versions. The repository
has since published `v2.2.0` Stable. Updating a support table is a maintenance
commitment, not a formatting change, so it must be reviewed separately from the
Documentation V4 README PR.

## Facts to use in review

- Current stable package/tag: `2.2.0` / `v2.2.0`.
- Release source: `94d606ed934d7d288c2946ae7d9d25582d8204a4`.
- Stable scope: Verified Core / Experimental Provider Integrations.
- Historical Full GA remains `gaReady:false` with 18 blockers; Stable does not
  satisfy or waive Full GA.
- Current `SECURITY.md` private reporting channel and disclosure expectations
  should be preserved unless the owner explicitly changes them.

## Proposed review options

The owner must choose one row; this is not a self-approved policy.

| Version line | Option A (narrow) | Option B (broader) | Needed decision |
|---|---|---|---|
| `2.2.x` Stable | Security fixes for reported vulnerabilities, subject to maintainer capacity | Same, with a stated minimum support window | Owner must explicitly approve wording and any window |
| `2.0.x` | Status **to be confirmed**; no EOL claim | Status **to be confirmed**; no EOL claim | Owner decides |
| `1.0.x` | Keep current security-fix statement | Keep current security-fix statement | Existing policy |
| `< 1.0.0` | Not published | Not published | Existing record |

Do **not** automatically mark `2.0.x` or `1.x` EOL. Do not claim a maintenance
window that the owner has not approved.

## Suggested wording (only after approval)

If Option A is approved, the Supported versions table could say:

```markdown
| Version | Supported |
|---|---|
| 2.2.x (Stable) | Security fixes for reported vulnerabilities, subject to maintainer capacity |
| 1.0.x | Security fixes (existing policy) |
| < 1.0.0 | Not published |
```

This example intentionally does not set a calendar support window. If the owner
wants one, add it explicitly with a start/end date and a review date.

## Boundaries to preserve

- The private GitHub Security Advisory channel and maintainer email remain the
  reporting paths; do not publish exploit details in a normal PR.
- AI-assisted review is not human certification.
- Stable is not Full GA; `gaReady:false` and the 18 historical blockers remain.
- OIDC/Sigstore attestation is build provenance, not a production code
  signature or a security certification.
- This proposal does not modify `SECURITY.md`; a maintainer must authorize and
  review the actual policy change.

## Required follow-up

1. Owner selects Option A or B and confirms the exact wording.
2. A separate PR changes `SECURITY.md` under the protected-file review path.
3. Run the full required CI and retain the result.
4. Do not merge this proposal as if it were an approved support commitment.
