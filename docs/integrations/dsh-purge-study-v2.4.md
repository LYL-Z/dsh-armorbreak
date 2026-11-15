# ArmorBreak V2.4 research: dsh-purge lineage and selective integration

Status: **PHASE 0 / NOT SHIPPED**. This document records an architectural and
provenance assessment, not an assertion that all listed features were imported.
The v2.3.1 Stable tag, attested package and release files must remain immutable.

## Source inventory (pinned)

| Source | Inspected commit | Role | Reported version |
| --- | --- | --- | --- |
| [mmparko/dsh-purge](https://github.com/mmparko/dsh-purge) | `033e6bd1e0f101352b39075ecd0d758ffef26b76` | Mirror of YuJunZhiXue/dsh-purge | 1.1.71 |
| [kingcharleslzy-ai/dsh-purge](https://github.com/kingcharleslzy-ai/dsh-purge) | `411f98c676e5ff5f400df78316c9bd056416a46d` | Independently maintained community fork | 1.6.84 |
| [LYL-Z/dsh-armorbreak](https://github.com/LYL-Z/dsh-armorbreak) | `cfb984b7178bb8b1dca9728325fdbe599b5430a3` | Integration target, released baseline | 2.3.1 |

The two Purge repositories share a common ancestor and **must not** be treated
as two independent implementations to concatenate. The mirror explicitly
documents original author **小杨 / YuJunZhiXue** and preservation of the upstream
repository, while the community fork records subsequent contributors and
third-party materials. Those sources are untrusted input; do not run their
installers, setup scripts, examples, or test payloads during assessment.

## Licensing and provenance gate

Both repositories contain an MIT `LICENSE` naming the original copyright owner.
The mirror's README separately demands attribution and purports to prohibit
commercial resale; the mirror notice repeats that demand. Those statements
need legal clarification if code or substantial creative material is reused:
the MIT license text and the README's additional restrictions do not read as
the same permission grant. Do not make a definitive legal conclusion from a
repository badge. The community fork's `NOTICE.md` identifies upstream code,
red-team code from Jueze-2019, and a DeepSeek Harness test fixture. Each copied
file needs its own provenance, applicable license and copyright audit.

1. **No plagiarism camouflage.** Rewriting JavaScript as Python, Rust, or
   another language does not by itself make copied expression independent or
   eliminate attribution obligations.
2. **Default path: independent implementation from public functional
   requirements**, using ArmorBreak's existing Core contracts and original
   tests. Credit the conceptual sources in the design record.
3. **Where code is actually reused:** retain required MIT notices, identify
   original authors and upstream repository, document modifications, audit
   transitive licenses, and obtain permission/clarification if needed.
4. **Do not relicense third-party source as solely LYL-Z work** or silently
   remove historical attribution. Keep an auditable file-by-file origin ledger.

This is a technical and licensing-risk checklist, not legal advice.

## Capability and gap matrix

| Area observed in Purge | ArmorBreak baseline | V2.4 disposition | Acceptance boundary |
| --- | --- | --- | --- |
| Explicit host/profile discovery | Core health and DSH adapter exist | **Begin:** read-only inspector | No implicit instance selection, no config disclosure |
| Layered selfcheck and drift diagnostics | `doctor`, host compatibility evidence | Extend separately | Distinguish absent, unknown, failed, verified |
| Runtime injection probe | DSH adaptation and L0 smoke coverage | Optional synthetic probe | No secret transcript capture, no unsafe prompt rewriting |
| Installation/update source verification | Transactional artifact installer and signed release evidence | Improve host installer lifecycle | Pinned source, TLS, SHA-256, no unverified mirror fallback |
| Snapshot, restore and maintenance lock | Installer rollback and workspace evidence | Add profile-safe backup manager | Content hashes, no blind lock deletion, no unrelated config overwrite |
| Windows/macOS/Linux host variants | Limited separately evidenced DSH paths | Independent compatibility matrix | One tested host/version/principal per claim |
| Cordis/ASAR host patch reanchoring | Native DSH bundle and guarded adapter | Quarantined compatibility module only | Exact targets, explicit approval, rollback, host-version gate |
| Per-preset rules and prompt isolation | Scoped mode and skills already exist | Add versioned overlay settings | Preserve explicit false, empty values and unknown user fields |
| Native settings panel / sidebar | ArmorBreak Web status / Workbench | New UI designed for ArmorBreak | Avoid bundling upstream generated client blob |
| Marketplace distribution | Signed release and host adapters | Separate optional market manifest | No mutation of official installation by default |
| Network/proxy/update credentials | Core network scope policy | Reuse existing policy gateway | No token leakage or implicit proxy changes |
| Red-team evidence and reports | Stronger existing L0–L3 evidence chain | Map only missing **authorized** evaluation features | Do not duplicate findings/schedulers; L3 remains denied |
| Refusal retry / unrestricted prompt mutation | Explicit approval and policy model | **Do not port bypass semantics** | No policy deactivation or autonomous guardrail removal |
| Credential attacks, tunnelling, lateral movement, web shells | Not generic default feature set | **Excluded from default distribution** | Separate threat model; no auto-execution or weakening L3 |

## Work packages and suggested PR boundaries

1. **P0 — provenance and safe discovery (this branch):** source map, one
   read-only explicit-profile inspector, synthetic tests. No host writes.
2. **P1 — diagnostics:** stable JSON health contract; layered compatibility and
   anchor drift evidence; CLI + user-visible documentation; Windows/macOS/Linux
   fixture tests. Read-only by default.
3. **P2 — transactional maintenance:** a separate host maintenance plan with
   dry-run, explicit target, backup manifest, bounded cleanup, anti-symlink
   checks, secret redaction, external human/platform approval and rollback.
   Verify one real Windows principal before any broad compatibility claim.
4. **P3 — settings and UI:** independent native panel, profile-scoped overlays,
   no unknown-field loss, never auto-restart the host. E2E for Web and Desktop.
5. **P4 — distribution and lifecycle:** pinned releases, signed provenance,
   offline package verification, migration of legacy package aliases and
   fail-closed update channels. Run the protected Windows rollback Gate.
6. **P5 — authorized assessment extensions:** gap-by-gap evaluation against
   ArmorBreak's capabilities, model/Python/Node integrations behind current
   policy boundaries. No mass import of attack skills or model guardrail bypass.

Each PR must identify source inspiration, code provenance, changed files,
expected host mutations, threat model, exact SHA, rollback strategy, tests,
and independently reviewable evidence. **Do not merge all six phases as one PR.**

## Phase 0 implemented surface

`lib/integrations/dshHostInspector.js` is an original, dependency-free,
read-only inventory of an **explicit** `$DSH_HOME/profiles/<profile>` directory.
It deliberately checks only a bounded `package.json` and textual mentions in
`cordis.patch.yml`; it does not claim that declared dependencies are installed,
enabled, patched or loaded. It never returns prompt bodies, credentials or
other configuration values. File symlinks are not followed. Directories that
cannot be safely inspected produce `INCOMPLETE` rather than a guessed result.

Example (no ArmorBreak engine state variables required):

```sh
node packages/cli/index.js host inspect --home /absolute/path/to/dsh-home --profile web --json
```

The output is JSON schema `armorbreak.dsh-host-inspection/v1`. The command
does **not** modify files, install a plugin, remove conflicting entries, apply
patches or restart the host. No actual DSH instance is verified in Phase 0.

## P1 incremental implementation: anchor drift diagnostics

`lib/integrations/dshAnchorDiagnostic.js` provides an independent read-only
literal anchor counter. The caller specifies one exact host file and one
bounded JSON anchor specification; it reports missing, ambiguous, mismatched
or expected occurrence counts without copying host source, prompts, snippets
or anchor literals into the output. It will not modify or reanchor the host.

Example anchor specification (synthetic, not copied from an upstream patch):

```json
{
  "schemaVersion": "armorbreak.anchor-spec/v1",
  "anchors": [{ "id": "example-entry", "literal": "example-host-anchor", "expectedCount": 1 }]
}
```

```sh
node packages/cli/index.js host diagnose --target /absolute/host/file.js --spec /absolute/anchors.json --json
```

This is only the first part of P1. Automated host-version discovery, runtime
injection probe and tested Windows/macOS/Linux host compatibility remain
**NOT IMPLEMENTED / NOT VERIFIED**.

## Regression and release gates

- `node --test tests/dsh-host-inspector.test.mjs`: synthetic success,
  sensitive-field redaction, path rejection, symlink handling and CLI no-write.
- Entire Core, installer, migration, Windows update/rollback and release-gate
  suites must continue to pass on the target head; failures must be reported.
- Treat P1–P5 and real host compatibility as **NOT TESTED** until specifically
  proven. Existing v2.3.1 release status is not inherited by this branch.
