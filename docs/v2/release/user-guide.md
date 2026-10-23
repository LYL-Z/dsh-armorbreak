# ArmorBreak V2 User Guide (M4-11)

> **Historical scope:** This guide documents the V2.0.0 user flow. For the current V2.2 release gate and host evidence, use
> `docs/v2/generated/release-status.md` and `docs/v2/generated/host-matrix.md`.
>
> Install it into an isolated test profile first; the V2.0.0 evidence is in `docs/releases/v2.0.0.md`.

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

- **Historical V2.0 limitation:** the bundle was not yet installed in real Desktop at that time; M4-06 was blocked.
  This is superseded for DSH Desktop by `docs/v2/acceptance/desktop-e2e.md` (2026-10-21), which records real Desktop
  `armorbreak_health` and L0 `forensics.hash`; it is not evidence for macOS.
- Real Garak/PyRIT/Inspect and OCR/PDF/audio runtimes are not bundled.
- macOS not tested.
- R_offline for online-LLM workflows is not measured (N/A).
> Prerequisites: Node 24, and CPython >=3.10 for the AISEC worker; Docker/Podman optional for L1.
