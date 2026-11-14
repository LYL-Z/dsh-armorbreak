# Synthetic maintenance transactions (Draft, not real host writes)

Trusted host entry: `createSyntheticMaintenance(runtime, {operator, sessionId, seeds})`
and `reopenSyntheticMaintenance(runtime, root, {operator, sessionId})`, exported from
`packages/core/index.js`. The runtime is the existing ArmorBreak Core. A fresh,
random temporary root is mandatory: callers cannot select an existing host root.
Only up to 16 newly seeded, bounded `.txt` files are supported. No user DSH install
or configuration is touched. No shell/npm/plugin execution occurs.

```js
const lab = await createSyntheticMaintenance(core.runtime, {
  operator: 'host-owned-identity', sessionId: 'host-owned-session',
  seeds: { 'example.txt': 'synthetic before' }
})
const plan = await lab.plan([{ name: 'example.txt', content: 'synthetic after' }])
await lab.apply(plan.planId, trustedHostApprovalProvider)
await lab.rollback(plan.planId, trustedHostApprovalProvider)
```

The provider is a trusted host object, not a request field. Only `allowed-once`
permits the Core ApprovalAuthority to mint an exact plan/operation/operator/session
bound token, record it in ScopePolicy and atomically consume its nonce. No provider
means refusal. This API is not exposed in CLI/MCP/Workbench as a self-approving write
capability. Tests simulate the provider decision but execute real Core token handling,
filesystem writes, fsync, object readback, child termination and recovery.

Plans/backups are HMAC-sealed using the existing host-local Core authority, stored
privately below the fresh root. They contain plaintext synthetic bytes and are not
public evidence. Public audit events contain state, random plan/approval IDs and
counts, not original names, content or guessable content hashes. A lock is created
exclusively. Successful/exceptional lease releases retain history; abrupt termination
leaves the lock intact. Recovery never expires/deletes it automatically: an explicit
trusted operation verifies the signed PID, proves the process exited, then archives
the lease. A separate, newly approved rollback restores exact original bytes.

States: PLANNED -> APPLYING -> WRITE_INTENT -> WROTE -> COMMITTED;
explicit ROLLING_BACK -> RESTORE_INTENT -> RESTORED -> ROLLED_BACK.
Each target is an existing seeded single-link file; directory and file identity,
members and content are checked. Writes/truncate/fsync/readback use one opened file
handle. Links, junctions, replaced objects, unknown bytes, corrupt records or locked
transactions fail closed. A partial/unknown write is retained for diagnosis, not
optimistically marked recovered. Unresolved data loss is not hidden.

## Verification limits

This is the synthetic first step toward transactional maintenance, not a production
host executor. It does not establish OS identity for callbacks, resist a malicious
same-user process, restore Windows ACLs, survive power loss, install/update plugins
or replace an arbitrary real DSH config. Windows Node lacks directory fsync, explicitly
reported as unverified. Linux directory sync is implemented but power loss is untested.
No Windows second-principal ACL certification, real DSH approval integration or
production authorization is claimed. A whole-root/ancestor replacement race beyond
the held-object/revalidation checks needs native production path/handle integration.

Behavior research: fixed Community source `lib/restore-backup.js`, `lib/atomic-files.js`
and maintenance lifecycle concepts; no upstream executable source imported. Existing
Core approval authority, ScopePolicy and AuditLog are reused. Verify precise source
mapping in the authoritative migration ledger; this subset remains PARTIAL.

Run `node --test tests/synthetic-maintenance.test.mjs`.
