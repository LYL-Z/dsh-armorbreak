# Independent review evidence pack

This pack is for a real human independent reviewer. It is **not** a signature and
does **not** make `gaReady` true. Owner approval is not independent review.

## Release under review

- Version: `2.2.0-rc.1` (not GA; no `v2.2.0` tag)
- `v2.0.0` remains `f96d03acad441b4b5a4b9d141dd553e3224c3745`
- `v2.2.0-owner-waiver` remains `c8685031b52f6546b695fc3af7cfe50ee183ec28`
- Source/artifact/evidence commit relationship must be re-checked after the final
  evidence commit; use `docs/v2/acceptance/v2.2-readiness.json` and
  `release-build.json` as the authoritative pointers.

## Reproduce

```powershell
$env:TEMP='D:\dsh-ABM\temp'; $env:TMP='D:\dsh-ABM\temp'; $env:TMPDIR='D:\dsh-ABM\temp'
npm ci --no-audit --no-fund
node --test --test-concurrency=1
node scripts/v2/validate-evidence.mjs
node scripts/v2/check-blocker-map.mjs
node scripts/v2/release-gates.mjs
node scripts/v2/release-smoke.mjs
node scripts/v2/v2-readiness.mjs --require-ga
node scripts/v2/old-data-drill.mjs
node scripts/v2/rollback-drill.mjs
node scripts/v2/retest-real.mjs --host all
node scripts/v2/retest-real.mjs --provider all
node workbench/server.mjs --port 8787
```

`--require-ga` is expected to exit 1 until all external conditions are verified.
`retest-real.mjs` is a preparation check by default and never makes a model request;
add `--run` only after local authentication/credentials exist.

## Artifact verification

```powershell
Get-FileHash D:\dsh-ABM\dist\armorbreak-portable-2.2.0-rc.1.tar.gz -Algorithm SHA256
tar -tzf D:\dsh-ABM\dist\armorbreak-portable-2.2.0-rc.1.tar.gz
gh attestation verify D:\dsh-ABM\dist\armorbreak-portable-2.2.0-rc.1.tar.gz `
  --repo LYL-Z/dsh-armorbreak
```

Required correspondence:

- artifact SHA-256 == `release-build.json.sha256` == `portable-artifact.json.sha256`;
- attestation subject digest == same SHA-256;
- attestation workflow commit == artifact source commit (or the evidence explicitly
  states the source/evidence commit difference);
- `test-report.json.commit` == `evidence-manifest.json.commit`;
- `v2.2-readiness.json` points at the final main commit, not a stale branch commit.

## What was implemented

- TypeScript SDK contract generation and `tsc --noEmit`.
- OpenAI Chat / OpenAI Responses / Anthropic Messages / Gemini native protocols,
  streaming, tool calls and usage normalization.
- Secret Vault (Windows DPAPI), redaction, egress allowlist, budget and approved
  fallback.
- Workbench Hosts/Providers/Skills/Tasks/Evidence/Diagnostics UI and loopback API.
- Old V2 read-only drill, copy migration, fault injection, rollback, gray plan.
- Deterministic artifact, CycloneDX SBOM, SHA-256 and GitHub OIDC/Sigstore
  build provenance.
- Pi native TypeScript extension and real package install/uninstall.
- `preReleaseReady` vs `gaReady`; owner waivers cannot satisfy GA.

## Verified in this repository

| Area | Evidence |
|---|---|
| 46 capabilities / 9 workflows / Universal Core | `capabilities`, tests |
| MCP stdio / HTTP / HTTPS / SSE | MCP test suites |
| Provider protocol mock/golden | `provider-protocols`, `provider-golden` |
| Local Ollama real chat/tool loop | `provider-live-ollama.json` |
| Windows DPAPI vault | `provider-vault-policy.test.mjs` |
| Old data read-only/migration/fault/rollback | `old-data-readonly-drill.json` |
| Workbench real render | `workbench.png`, `workbench-rendered.html` |
| Deterministic build/SBOM | `release-build.json` |
| GitHub OIDC attestation | `github-attestation.json` |
| Real host L0 (6/9 third-party) | `compatibility-matrix.json` |

## Not verified / external scope

- Claude Code model call: 401, no real Claude L0.
- Antigravity/Gemini model call: 401.
- ZCode model call: 429 / provider 1113.
- Real paid OpenAI Chat/Responses, Anthropic Messages, Gemini native endpoints.
- Independent human review signature.

The 13 acceptance blockers collapse to **7 independent root causes**:
Claude auth, Antigravity auth, ZCode balance, OpenAI endpoint, Anthropic endpoint,
Gemini endpoint, independent review. `ABU-403` and `ABU-318` are derived aggregates.
See `blocker-map.json`.

## Security boundaries to review

- L3 is always denied; model output is never an approval authority.
- L1/L2 require independent human/platform approval tokens bound to task/plan.
- Cross-workspace task read/cancel/approval must return `POLICY_DENIED`.
- Workbench is loopback-only, same-origin, GET/HEAD read-only for state; create
  routes require the local UI header.
- No plaintext secret in repo, UI, logs, reports or evidence.
- Provider keys come from local environment/DPAPI vault, never from tool arguments.

## Reviewer checklist

- [ ] Re-run the commands above; tests green and evidence hashes PASS.
- [ ] Verify artifact SHA and GitHub attestation subject/commit.
- [ ] Confirm test report and manifest commit correspondence.
- [ ] Review L3/approval/workspace-isolation tests and security boundary code.
- [ ] Review secret handling and provider egress/budget policy.
- [ ] Review Workbench route protections and screenshot.
- [ ] Review migration/fault/rollback evidence.
- [ ] Confirm the 7 root causes and that no owner waiver is used for GA.
- [ ] Record PASS/FAIL per item with file/line references.
- [ ] State residual P0/P1 findings and whether they block GA.
- [ ] Sign as an independent human reviewer; include identity and date.

## Signature

```text
Reviewer name:
Independent reviewer (yes/no):
Date:
Artifact SHA-256 reviewed:
Attestation run reviewed:
Decision: PASS / PASS WITH FINDINGS / FAIL
Findings:
```

Until this section is completed by a real independent reviewer and all `gaBlockers`
are zero, the release remains a pre-release.
