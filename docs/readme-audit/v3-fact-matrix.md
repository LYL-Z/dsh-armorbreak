# README V3 — fact matrix

- Date: 2026-10-23
- Repository baseline: `3370a9ab9fb70a1ccb9e67514184ab55c33516f6`
- Package: `2.2.0-rc.1`
- Core internal contract: `0.1.0-p1`

| Claim | Value / status | Source |
|---|---|---|
| Root package version | `2.2.0-rc.1` | `package.json` |
| Node requirement | `>=22` | `package.json` |
| Core internal version | `0.1.0-p1` | `packages/core/index.js` |
| Capabilities | 46 | Core registry / `docs/readme-audit/fact-check.md` |
| Domains | 8 | Core registry |
| Risk profile | 44 L0 / 1 L1 / 1 L2; L3 denied | Core policy |
| Workflows | 9 | `packages/core/src/workflows.js` |
| DSH Skills | 7 | `skills.js` |
| DSH model-facing tools | 10 | `tools.js` |
| MCP server tools | 7 | `packages/mcp-server/index.js` |
| Host matrix | 12 entries / 10 L0 / 9 third-party L0 | `docs/v2/acceptance/compatibility-matrix.json` |
| Mock Golden | `MOCK_GOLDEN_PASS` | `docs/v2/acceptance/golden-status.json` |
| Local Ollama loop | `LOCAL_MODEL_PASS` | `docs/v2/acceptance/provider-live-ollama.json` |
| Official Provider Live | `EXTERNAL_UNVERIFIED` | same |
| Recorded tests | 400 / 399 pass / 0 fail / 1 skipped at `970d1f5` | `docs/v2/acceptance/test-report.json` |
| Full V2.2 GA | `gaReady: false` | readiness/evidence |
| GA blockers | 6 | `docs/v2/acceptance/blocker-map.json` |
| Owner waivers | 0 | release status |
| Human security certification | not obtained | release/security status |

## Version semantics

- `2.2.0-rc.1` is the **root package/release identifier**.
- `0.1.0-p1` is the **Core component contract version**; it is not a second package release.
- DSH tools, MCP tools, Skills, and capabilities are different interfaces and must not be summed.

## Visual assets

- `icon.svg` is the project’s own shield icon and is safe to reference.
- The existing Desktop screenshot contains local account/workspace labels. It was intentionally **not embedded** in README; the documented L0 evidence table links to the original evidence instead of publishing personal labels.
- `workbench.png` was not used because its recorded readiness/waiver state is historical and would conflict with the current release status.

## Security wording

The README distinguishes:

- design goals;
- automated tests;
- four AI-assisted review rounds (initial, findings not all closed);
- pending remediation/retest;
- absence of independent human security certification.

`SECURITY.md` still lists 1.0.x in Supported Versions. That security-policy update is intentionally out of scope of this docs-only PR and requires separate authorization.
