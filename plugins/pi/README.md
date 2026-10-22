# Pi native extension

Pi does not ship an MCP client. This extension registers ArmorBreak tools directly
against the Universal Core, so no MCP bridge is required.

## Tools

- `armorbreak_health`
- `armorbreak_analyze` (`capability`, workspace-bounded `target`)
- `armorbreak_report` (`taskId`)

## Run

```powershell
$env:PI_CODING_AGENT_DIR='D:\dsh-ABM\pi-home\agent'
$env:PI_CODING_AGENT_SESSION_DIR='D:\dsh-ABM\pi-home\sessions'
$env:NODE_PATH='D:\dsh-ABM\pi\node_modules'
$env:ARMORBREAK_STATE_ROOT='D:\dsh-ABM\host-evidence\pi\state'
$env:ARMORBREAK_WORKSPACE='D:\dsh-ABM\armorbreak'
$env:ARMORBREAK_PRINCIPAL_ID='pi-host'

D:\dsh-ABM\pi\node_modules\.bin\pi.cmd -p `
  "Call armorbreak_analyze with capability forensics.hash and target D:\dsh-ABM\armorbreak\README.md, then armorbreak_report." `
  --provider ollama --model qwen3.5:4b `
  -e D:\dsh-ABM\armorbreak\plugins\pi\index.ts `
  --no-builtin-tools
```

The extension rejects targets outside `ARMORBREAK_WORKSPACE`; Core still enforces
its own principal/workspace policy. `--no-builtin-tools` is recommended for the
tool-only L0 drill so the model cannot bypass ArmorBreak with shell/file tools.
