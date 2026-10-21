# M4-06 real Desktop E2E evidence

Date: 2026-10-21 (America/Los_Angeles)
Host: DSH Desktop `0.2.1-rc.2`, win32/x64, Node `v24.21.0`
Preset: `armorbreak` ("破甲模式")
Model: DeepSeek-V4.1-Flash (1017)

## Tool calls observed in the real GUI

1. `armorbreak_health` — completed in ~7 s; returned 46 capabilities, 6 historical tasks, 5/25 external tools, isolation unavailable, 0 active approvals.
2. `armorbreak_analyze` (L0 `forensics.hash`) — task `task_mvi33mq6_00e28f71`, state `COMPLETED`, 2 evidence records, markdown report.

## L0 report

- Target: `D:\dsh-ABM\armorbreak\docs\v2\benchmark\core-scenarios.json`
- Input SHA-256: `50eea274f68780a501df2f79aea32fd6785dcc2a2f87a1e198e6f5b7c79e1fc8`
- Report SHA-256: `bb07c8acb8fb8f247ef936fd4a9588daa49a41dcfc68af9040f4483298365296`
- Report bytes: 8270
- Committed byte copy: `docs/v2/acceptance/desktop-l0-report.md`
- Evidence chain:
  - `ev_mvi33nx8_c55674ff` (`forensics.hash execution`) hash `371bb7e8…`
  - `ev_mvi33nxf_3566fb8c` (`文件哈希`) hash `fbb4918d…`

## Screenshots

- `desktop-health.webp` — SHA-256 `ea9e5ce3ec9ac93122789258426bd523155f423c1f86a5bda10de4877b89b396`
- `desktop-health-detail.webp` — SHA-256 `986c3df3df27152e27382978a2dffc2633b6641367a5580115d48104c5d576f9`
- `desktop-analysis.webp` — SHA-256 `71c3e4e4a348b68ca2966207303b46bb8487b6d618ededa92a0c6bb998a61287`

## Limitations

- Isolation provider unavailable; no L1/L2 execution.
- Approval prompts disabled; no authorization was claimed.
- PDF export unavailable (LibreOffice absent).
- Only 5/25 external tools installed; L0 capabilities that do not need them were used.
