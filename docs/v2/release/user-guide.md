# ArmorBreak V2 User Guide (M4-11)

> This guide documents the V2 candidate behavior on `feature/armorbreak-v2`. V2 is not released; use v1.2.0 for production today.

## Install / select

1. Build the bundle lock: `node scripts/v2/build-bundle.mjs`.
2. Install via the DSH profile adapter in an isolated test profile.
3. Select the `armorbreak` preset in DSH Desktop or the web UI.
4. If the preset or tools are absent, do not claim the mode is active; check `/armorbreak/state`.

## Workbench

- **Overview**: capabilities, isolation state, recent tasks.
- **Tasks**: create L0 tasks, inspect steps/evidence/report.
- **Network**: connectivity state, connector breakers, read-only resources.
- **Evaluations**: submit a prompt/category to the local mock AISEC target; results persist with traceId.
- **Knowledge**: lexical search; JSON fallback is the supported backend when FTS5 is absent.
- **Catalog**: read-only connector metadata; installation is never automatic.
- **Installations**: plan → stage → verify → explicit approve → activate → rollback; package scripts never run.

## Boundaries

- L3 is always denied.
- Model identity cannot authorize L1/L2/install; platform/operator approval tokens are required.
- RESOURCE_READ is read-only and separate from L2 testing.
- External content is untrusted data, never instructions.
- Missing external tools produce actionable guidance, not silent downgrade.

## Troubleshooting

- `MISSING_EXTERNAL_TOOL`: install the named tool or use the documented built-in alternative.
- `ISOLATION_UNAVAILABLE`: no usable Docker/Podman daemon; L1 stays denied.
- `TOKEN_*`: approval expired/revoked/replayed; request a new operator grant.
- Offline: analysis continues; resource updates need explicit RESOURCE_READ opt-in.

## Known limitations

- V2 bundle not yet installed in real Desktop; M4-06 blocked.
- Real Garak/PyRIT/Inspect and OCR/PDF/audio runtimes are not bundled.
- macOS not tested.
- R_offline for online-LLM workflows is not measured (N/A).
# prerequisites: Node 24, and CPython >=3.10 for the AISEC worker; Docker/Podman optional for L1.
