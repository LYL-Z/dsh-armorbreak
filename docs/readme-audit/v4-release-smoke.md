# README V4 — release L0 smoke

- Date: 2026-10-26
- Release: `v2.2.0` (`94d606ed934d7d288c2946ae7d9d25582d8204a4`)
- Input: downloaded `armorbreak-portable-2.2.0.tar.gz`
- Archive SHA-256: `5e5aca98da18d4f0cb17db71cf57c5577f8f8f64810a30844bd5237b4ed7b630`
- Workspace: `D:\ArmorBreak-Docs-V4\release-extracted`
- Shell: Windows PowerShell 5.1
- Node: `v24.16.0`
- Credentials: none; no commercial Provider key
- Network target: none

## Commands

```powershell
$demo = 'D:\ArmorBreak-Docs-V4\release-smoke'
# isolated state/workspace created; release README copied into workspace

node packages/cli/index.js capabilities --json
node packages/cli/index.js analyze --capability forensics.hash `
  --target "$demo\workspace\README.md" --json
node packages/cli/index.js task list --json
node packages/cli/index.js report <task-id> --json
```

## Results

| Step | Exit | Observed |
|---|---:|---|
| capabilities | 0 | 46 capabilities |
| analyze | 0 | `task_mvp9aqd2_874325ae`, `COMPLETED`, 2 evidence records |
| task list | 0 | 1 task |
| report | 0 | Markdown report readable |

Recorded values:

- Target SHA-256: `0359d16bac413f5d9efb20dba2569c3d19f38dba83026f9511a041982d21ec85`
- Report SHA-256: `0acfac1bc9360362e592f3c8094fc62697135958099acf5e2cbf1e9b5125e16b`

The downloaded archive and all five entries in `SHA256SUMS.txt` were hash-verified locally. `gh attestation verify` succeeded for source `94d606e…`.

## Limits

- Windows only; no fresh macOS/Linux smoke in this docs QA.
- This proves a local L0 `forensics.hash` path, not every capability or Provider.
- This release smoke is bound to the published `v2.2.0` archive, not to any newer main checkout.
