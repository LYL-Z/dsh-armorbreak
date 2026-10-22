# Independent review evidence pack

This pack is for a real human independent reviewer. It is **not** a signature and
does not make `gaReady` true.

## Reproduce

```powershell
$env:TEMP='D:\dsh-ABM\temp'; $env:TMP='D:\dsh-ABM\temp'
npm ci --no-audit --no-fund
node --test
node scripts/v2/validate-evidence.mjs
node scripts/v2/release-gates.mjs
node scripts/v2/v2-readiness.mjs --require-ga
node scripts/v2/old-data-drill.mjs
node workbench/server.mjs --port 8787
```

## Review scope

- 46 capabilities / 9 workflows / Universal Core / MCP stdio+HTTP+HTTPS.
- Host matrix: real L0 for DSH, Codex, Hermes, Cursor, WorkBuddy, TRAE.
- External gaps: Claude model login, ZCode model L0, Antigravity/Pi installation,
  paid OpenAI/Anthropic/Gemini endpoints, production signing key.
- Security: L3 always denied; model is never an approval principal; Origin/Host/Bearer
  checks; session identity isolation; secret vault/redaction/egress/budget/fallback.

## Evidence files

- `docs/v2/acceptance/compatibility-matrix.json`
- `docs/v2/acceptance/host-model-e2e-2026-10-22.json`
- `docs/v2/acceptance/provider-live-ollama.json`
- `docs/v2/acceptance/old-data-readonly-drill.json`
- `docs/v2/acceptance/v2.2-readiness.json`
- `docs/v2/acceptance/test-report.json` + `test-report.tap`
- `docs/v2/acceptance/evidence-manifest.json`
- `docs/v2/acceptance/workbench-rendered.html` + `workbench.png`
- `docs/v2/release/waivers.json` (pre-release exceptions, not GA)

## Required reviewer output

- Independent identity/signature and date.
- PASS/FAIL per checklist item with file/line references.
- Residual P0/P1 findings and whether they block GA.
- Separate statement that owner approval is not independent review.

Until this file has a real independent signature and all `gaBlockers` are zero,
the release must remain a pre-release.
