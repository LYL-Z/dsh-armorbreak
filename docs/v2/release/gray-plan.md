# Gray rollout plan

Stages: 5% → 25% → 100% of eligible local installs.

Before every stage:

1. `node scripts/v2/validate-evidence.mjs`
2. `node scripts/v2/release-gates.mjs`
3. `node scripts/v2/v2-readiness.mjs --require-ga`
4. installer/rollback drill pass
5. L3 denial test pass

Automatic rollback triggers:

- any release gate FAIL;
- evidence manifest/TAP mismatch;
- L3 not denied or an approval is issued by a model;
- installer/rollback not byte-exact;
- error rate > 1% or a security regression.

Rollback target: last published `v2.0.0` (tag immutable). The owner-waiver
pre-release is separate and is not evidence for GA.

The machine-readable decision helper is `lib/release/gray.js`, tested by
`tests/gray-rollback.test.mjs`.
