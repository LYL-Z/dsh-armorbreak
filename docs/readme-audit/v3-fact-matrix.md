# README V3 — fact matrix

- Snapshot date: 2026-10-25
- Main baseline after PR #18: `82a77b8ceb60d7c10a2d0ff92f7faaea45298e68`
- README PR source branch: `docs/readme-v3-editorial` (latest main baseline included by a merge commit)
- Package version: `2.2.0`
- Core internal contract: `0.1.0-p1`
- Stable scope: `ArmorBreak V2.2 Stable — Verified Core / Experimental Provider Integrations`
- Stable publication state: requires the exact-main Stable Gate; PR #18 merge is not a release.

| Claim | Value / status | Source |
|---|---|---|
| Root package version | `2.2.0` | `package.json` |
| Stable scope | Verified Core / Experimental Provider Integrations | `docs/v2/release/v2.2-stable-scope-v1.json` |
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
| Official commercial Provider Live | `LIVE_UNVERIFIED` | `docs/v2/release/v2.2-stable-scope-v1.json` |
| PR #18 CI | Run `40203187699`, PR HEAD `6ad35b0121b546edc6d71efe6691b67eba7505d8`, 5/5 jobs success; Windows 529/529 and Ubuntu 531/531, 0 fail/skip | GitHub Actions run; PR HEAD only, not exact-main release authorization |
| Current main Stable release | PR #19 is refreshing evidence after the squash merge; its exact-HEAD CI and the resulting main attestation must pass before Stable Gate evaluation | PR #19 / `docs/v2/release/v2.2-stable-policy-v1.md` |
| Historical Full V2.2 GA | `gaReady: false`; 18 blockers | `docs/v2/acceptance/v2.2-readiness.json` |
| AI-assisted review | Accepted by policy; evidence remains SHA-specific; not human certification | `docs/v2/release/v2.2-stable-policy-v1.md` |
| Independent human security certification | Not obtained and not a V2.2 Stable prerequisite | Stable policy / release records |

## Version semantics

- `2.2.0` is the root package version and the version named by the Stable contract. A package version does not itself prove that the GitHub Stable release has been published.
- `0.1.0-p1` is the Core component contract version; it is not a second package release.
- DSH tools, MCP tools, Skills, and capabilities are different interfaces and must not be summed.

## Visual assets

- `icon.svg` is the project’s own shield icon and is safe to reference.
- The existing Desktop screenshot contains local account/workspace labels. It was intentionally **not embedded** in README; the documented L0 evidence table links to the original evidence instead of publishing personal labels.
- `workbench.png` was not used because its recorded readiness/waiver state is historical and could conflict with the current release status.

## Security wording

The README distinguishes:

- Stable release scope from the historical Full GA contract;
- AI-assisted security review from human certification;
- exact-SHA test results from results that would need to be regenerated for a later SHA;
- experimental commercial Provider integrations from verified Core functionality;
- OIDC/Sigstore build provenance from software safety certification and production code signing.

`SECURITY.md` still lists 1.0.x in Supported Versions. That security-policy update is intentionally out of scope of this docs-only PR and requires separate authorization.
