# Configuration lifecycle: scoped synthetic apply and restore

This increment composes the existing data-only converters, private profile/overlay resolver and sealed Core synthetic transaction executor. JSON, YAML, Cordis and paired Purge preset/agent inputs can now reach the same approved apply/restore lifecycle. No existing installation path is accepted.

## Callable entries

`node packages/cli/index.js config stage --bundle <workspace/request.json> --json`

The request is UTF-8 JSON (at most 1 MiB) with exactly these supported members:

```json
{
  "schema": "armorbreak.configuration-lab-request/v1",
  "configuration": {
    "schema": "armorbreak.configuration-import/v1",
    "format": "yaml",
    "source": "example: old\nunknown: false\n"
  },
  "profiles": [{ "id": "example", "values": { "example": "new" } }],
  "selectedProfile": "example",
  "conflictPolicy": "last-wins"
}
```

The existing `ARMORBREAK_STATE_ROOT`, `ARMORBREAK_WORKSPACE` and `ARMORBREAK_PRINCIPAL_ID` configure the runtime. Input must pass Core workspace scope and bounded object-identity reads. The result contains an opaque plan ID, fresh lab path and redacted preview. The input file is read only. There is no destination option.

`config status --lab <absolute-lab-path> --json` reads the sealed journal with the same operator/session binding. `config apply --lab ... --plan ... --json` and `config revert --lab ... --plan ... --json` require trusted in-process host composition:

```js
import { runCli } from './packages/cli/index.js'
await runCli(['config', 'stage', '--bundle', requestPath, '--json'], {
  env, sessionId, agent, callId, approvalProvider
})
// Capture the plan/lab result. A later host call uses the same session and state root.
await runCli(['config', 'apply', '--lab', labPath, '--plan', planId, '--json'], {
  env, sessionId, agent, callId, approvalProvider
})
```

The provider and host identifiers are dependencies supplied by the trusted application, never CLI flags, configuration fields, terminal text, HTTP or MCP parameters. Only an actual provider result `allowed-once` can reach the existing Core one-use approval authority. A standalone CLI process cannot self-approve; `--yes` is rejected. Each restore requests separate approval. This module does not ship an OS-authenticated client/provider or add one to Workbench. Host integration remains a separate acceptance requirement.

The lower-level trusted module is `planSyntheticConfiguration(runtime, request)` in `packages/core/src/syntheticConfiguration.js`. It returns `{lab, plan, preview}`. Cordis overlays address a private `composition` array; Purge overlays address `{metadata, composition}`. Purge writes `preset.txt` then `agent.txt` in the fresh lab. Restore runs the reverse order. Content remains inert and no plugin loads or executable probes run.

## Private data and recovery

Public plan/preview output has no input field names, profile identifiers, configuration values or per-value hashes. Candidate and original raw bytes live in the local sealed transaction records. These records contain recoverable private configuration; the seal protects integrity, not encryption or OS identity. This synthetic lab is unsuitable for production secrets. This does not change the previously disclosed Windows storage or panel authentication boundary.

Unknown data fields survive conversion; selected replacement of arrays is intentional. Candidate serialization need not preserve YAML comments, key ordering or line endings. Restore compares the exact original bytes, including CRLF, for every file. Existing Core identity checks, fixed membership, no links/hardlinks, bounded files, journal, exclusive lease and one-use approval are reused. Any unknown content drift is refused. A half-written byte stream that matches neither snapshot still needs manual diagnosis; Windows directory fsync/power-loss recovery is not established.

## Evidence and feature status

`node --test tests/configuration-apply-r2.test.mjs tests/configuration-maintenance-flow.test.mjs`

Tests cover all four formats, profile selection and preservation, missing approval, standalone CLI denial, unexpected approval flags, session mismatch, denied host approval, workspace scope, separate restore authorization, a failure between the two Purge files and exact original-byte restore. Existing synthetic crash/reopen tests remain applicable to the unchanged executor. No real DSH writes, production secrets, ACL changes, service stops or host reboots occur.

This extends the tested subsets of `PO-PROMPT-002` and `PC-TRANSACTION-007`. Neither becomes `INTEGRATED_VERIFIED`. It does not implement the upstream host patching `--apply`/`--revert` commands merely by sharing their names. Real host schema migration, comments/layout preservation, installation compatibility, independent client authentication and full upstream behavior equivalence remain unverified.
