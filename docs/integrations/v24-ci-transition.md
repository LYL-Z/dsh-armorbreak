# Post-release CI transition for V2.4 development

Status: **DEVELOPMENT WORKFLOW TRANSITION, NOT A NEW RELEASE**.

ArmorBreak v2.3.1 has already shipped from exact commit
`cfb984b7178bb8b1dca9728325fdbe599b5430a3`. The historical V2.3 PR
contract enforces an evidence-only post-source allowlist, so unrelated new
feature source correctly fails the frozen check. The inherited V2.2 evidence
contract in generic CI similarly cannot certify source changes made after
the released manifest. Applying both contracts to every future PR makes
normal development impossible while producing misleading red statuses.

This transition separates **historical release verification** from
**post-release development validation**:

1. V2.3 PR matrix and Windows V2.2→V2.3 package drill still run for
   `feature/v2.3*` and `fix/v2.3*` maintenance branches. This includes the
   outstanding published-docs PR #31.
2. Frozen V2.3 exact-main build, attestation, and rollback jobs are restricted
   to the one published source SHA. Later main commits are not V2.3 release
   candidates. The V2.3.1 protected Tag event and verifier are unchanged.
3. The V2.4 development workflow now has an exact-candidate Node 22/24 ×
   Linux/Windows matrix, a separately executed L0 offline boundary job, and a
   real Docker L1 job. A stable aggregate gate uses `always()` and fails unless
   all three jobs report `success`; a skipped or failed prerequisite cannot
   produce a green aggregate.
4. Historical V2.2/V2.3 release-evidence job only runs on version Tag pushes
   or the frozen V2.3.1 main source. Future V2.4 release candidates must have
   a **new, separately reviewed release Gate** before publishing.

This is not a declaration that V2.4 is release-ready. It does not weaken
ArmorBreak's runtime L0–L3 policy, mutate the protected `v2.3.1` tag, change
release artifacts, or create a bypass for the frozen Tag verification job.

## Verification

- `node --test tests/v24-postrelease-workflows.test.mjs` validates the exact
  scoping and checks that the protected Tag job remains present.
- Full `npm test`, `npm run typecheck`, and GitHub Linux/Windows CI must pass.
- V2.3 maintenance PR #31 should still run its exact-head and Windows
  package drills; general V2.4 development PRs should not be misclassified as
  V2.3 release candidates.

The aggregate V2.4 gate is a real executed check, but it is **not yet proven
required by the current main branch-protection configuration**. The inherited
required `Release evidence checks (commit-bound)` context was skipped on the
previous PR run and GitHub may count a skipped required job as satisfied.
Therefore this transition remains blocked for merge until an authorized
maintainer reviews the exact required-check names and approves any needed
protection update. No protection setting is changed by this PR.

The V2.3.1 historical Tag Gate, exact-main provenance, protected tag, release
and rollback evidence remain unchanged. A successful V2.4 development gate is
not a V2.4 release authorization.
