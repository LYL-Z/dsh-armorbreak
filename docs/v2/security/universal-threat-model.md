# Universal Agent Threat Model (ABU-109)

Status: design + current P1 boundary. This document binds every entry point to
the trusted principal, workspace, policy and audit rules. It is not a claim of
third-party security certification.

## Assets

- existing `.armorbreak` task/evidence/log data;
- authorization records and approval tokens;
- API keys and host credentials (must never enter evidence envelopes/logs);
- capability execution and network targets;
- release tags, bundles, SBOM and evidence manifests.

## Trust boundaries and entry bindings

| Entry | Trusted identity source | Workspace source | Required control |
|---|---|---|---|
| DSH Cordis | host session + operator UI | host session binding | legacy PolicyGateway; model is never operator |
| MCP stdio | host-launched process + local principal | explicit invocation workspace | authenticate every tool call, ACL, approval token |
| MCP HTTP | authenticated connection, not JSON `operator` | authenticated connection binding | TLS/Origin/Host, session, CSRF, rate limit |
| CLI | OS user + explicit `--principal` | explicit path, realpath checked | local approval flow; no model text approval |
| TypeScript SDK | caller-supplied trusted principal only from host config | invocation context | same Engine ACL, bounded inputs |
| Pi/native plugin | host-native identity | host workspace | no direct analyzer access; Engine API only |

## Threats and controls

- **Model self-authorization / forged operator**: principal comes from host
  configuration, never from tool arguments. Verified by
  `tests/engine-node.test.mjs` (operator mismatch, unknown principal).
- **Cross-workspace data access**: every task get/list/cancel checks the
  configured workspace set. Verified by the same tests.
- **Replay / duplicate side effects**: requestId + payload hash; same payload
  returns the same task, different payload is rejected.
- **Secret exfiltration through evidence**: evidence/event envelopes redact
  sensitive keys and keep only a SHA-256 of the sanitized payload. Verified by
  `tests/evidence-envelope.test.mjs`.
- **Malformed envelope / oversize input**: protocol validation, length bounds,
  nesting and payload caps; fail closed.
- **Approval replay/expiry**: existing ApprovalAuthority remains the authority;
  P1 Engine must not synthesize approvals from model text. Expiry/replay tests
  remain required before ABU-105 is DONE.
- **Installer/package execution**: no package scripts execute in installer;
  signature/license/hash gates remain release blockers.
- **Telemetry**: no secret/API key or raw target content in logs; only IDs,
  hashes, states and bounded summaries.
- **Remote host identity**: remote principals require an authenticated
  connection and explicit workspace binding; a loopback request is not identity.

## Residual risks / not yet verified

- MCP/HTTP transports and cross-host identity are not implemented yet.
- The Engine facade still delegates to the legacy `lib/core` implementation.
- Approval token expiry/replay is not yet wired into Engine's task creation.
- No third-party multi-tenant service or remote deployment is claimed.

## API-to-test binding

| API | Negative test |
|---|---|
| `TrustedEngine.createTask` | forged operator, unknown principal |
| `TrustedEngine.getTask/listTasks/cancelTask` | cross-workspace denial |
| requestId replay | different payload rejection |
| `createEvidenceEnvelope` | secret redaction, invalid target hash |
| protocol schemas | invocation/evidence validation |
