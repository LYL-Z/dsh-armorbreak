# README V3 — first-run L0 smoke

- Date: 2026-10-23
- Workspace: `D:\ArmorBreak-Docs-V3\first-run-final`
- Repository baseline: `3370a9ab9fb70a1ccb9e67514184ab55c33516f6`
- Shell: Windows PowerShell 5.1 (the README recommends PowerShell 7+; syntax was exercised here on 5.1)
- Node: `v24.16.0`
- Credentials: none; no commercial Provider key
- Network target: none

## Commands executed

```powershell
New-Item -ItemType Directory -Force -Path "$demo/state", "$demo/workspace" | Out-Null
Copy-Item ./README.md "$demo/workspace/README.md"
$env:ARMORBREAK_STATE_ROOT = "$demo/state"
$env:ARMORBREAK_WORKSPACE = "$demo/workspace"
$env:ARMORBREAK_PRINCIPAL_ID = 'first-run-user'

node packages/cli/index.js capabilities --json
node packages/cli/index.js analyze --capability forensics.hash `
  --target "$demo/workspace/README.md" --json
node packages/cli/index.js task list --json
node packages/cli/index.js report <task-id> --json
```

## Results (final candidate README)

| Step | Exit | Observed |
|---|---:|---|
| `capabilities --json` | 0 | 46 capabilities |
| `analyze --capability forensics.hash` | 0 | `task_mvl59yx7_6e81a0f5`, `COMPLETED`, 2 evidence records |
| `task list --json` | 0 | 1 task in the isolated workspace |
| `report <task-id> --json` | 0 | Markdown report generated and readable |

Recorded task values:

- Target SHA-256: `bbda5f1d76c8365acb8471ff3ea26522903d876e3c48c98b06740ae79f30cbfc`
- Report SHA-256: `04cf7a709d2c659a76bfcd6d373e3ff5f2a09a0c72abf351fa78c1296e8ab36b`
- Task evidence directory: `...\workspace\.armorbreak\tasks\task_mvl59yx7_6e81a0f5`

## What this proves

The shortest offline L0 path executed against the recorded baseline tree.
- The task is workspace-scoped and is not a public-network test.
- The report and evidence are real output from this run; hashes are not hard-coded into the README.

## Limits

- This is a Windows run; macOS/Linux were not exercised.
- It proves `forensics.hash` only, not every capability or external analyzer.
- The original Desktop screenshot has local account/workspace labels and was not embedded in README; evidence is linked textually.



- This smoke is historical evidence for the baseline SHA above; it does not certify the later 82a77b8 main commit or the final edited README text.
