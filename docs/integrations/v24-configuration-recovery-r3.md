# Configuration write faults and explicit recovery boundaries

The trusted synthetic executor now exposes `lab.recoveryStatus(planId)`, also surfaced by the scoped `config status` CLI. This is an advisory byte/journal snapshot, never a grant or automatic repair. A later rollback repeats all sealed-plan, context, object, journal, lease and byte checks under its own approval.

| Observed condition | Classification | Supported response |
|---|---|---|
| PLANNED, all original bytes | PLAN_UNAPPLIED | Apply requires its own trusted approval |
| Valid in-progress/committed journal, every file exactly original or candidate | SAFE_FOR_SEPARATELY_APPROVED_ROLLBACK | A dead lease must first be explicitly released by PID check; a new rollback approval is required |
| ROLLED_BACK and exact originals | ALREADY_RESTORED | No repeated apply/rollback permitted |
| Any bytes match neither sealed original nor candidate, including truncate/partial write | MANUAL_REVIEW_REQUIRED | Preserve the private original snapshot and current bytes; executor refuses automatic rollback |
| Corrupt/tampered journal, plan, identity, unexpected members or links | Error/refusal | No safe-recovery claim and no writes; independent manual evidence/object review is required |

The private original snapshot remains recoverable base64 protected by an integrity seal, not encrypted. Manual diagnosis must check the exact target identity, intact backup and journal provenance, application state and restore authority; this change does not provide an override/force repair endpoint. Configuration values and their low-entropy digests are not emitted by `recoveryStatus`; it returns only classification and aggregate file-state counts.

Trusted test/host instrumentation may supply a fourth argument `{maxWriteBytes, onWritePhase}` to `lab.apply/rollback`. The callback observes TRUNCATED, PARTIAL_WRITE, FULL_WRITE and FILE_SYNCED without plaintext bytes. These function-valued hooks are not accepted in CLI/configuration JSON, MCP or Workbench requests. Normal operation uses normal writes with no injected hooks. A zero-byte write is refused rather than looping forever.

`tests/configuration-recovery-r3.test.mjs` injects truncate and partial-write exceptions, tampers with a journal and kills actual child processes at three write phases. Tests prove unknown partial bytes stay unchanged after refusal; a fully synchronized known candidate can be restored byte-for-byte (including CRLF) after dead-lease release and separate approval. The corruption fixture can resume only after the test itself restores its preserved original journal, not through a product journal-repair API. This is process-crash testing, not power-loss or real DSH acceptance. Production credentials, real host writes and Windows ACL changes remain unavailable.
