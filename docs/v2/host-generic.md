# Generic MCP host adapter

This adapter is for any host whose configuration is a JSON object with an
`mcpServers` map (Claude-style, Cursor-style, TRAE-style). It never guesses a
host path and never executes host code.

## Install

```powershell
node packages/cli/index.js agent install `
  --target generic `
  --config D:\path\to\mcp.json `
  --scope user `
  --state-root D:\armorbreak\state `
  --workspace D:\path\to\workspace `
  --principal generic-host `
  --apply --json
```

The installer creates a `.armorbreak.bak` backup and preserves every other
server. Without `--apply` it only prints the planned before/after diff.

## Diagnose

```powershell
node packages/cli/index.js agent doctor --config D:\path\to\mcp.json --json
```

Checks that `mcpServers.armorbreak` exists, has a command/url, and declares
`ARMORBREAK_STATE_ROOT`, `ARMORBREAK_WORKSPACE` and
`ARMORBREAK_PRINCIPAL_ID`. It exits 1 with `status: "FAIL"` when the entry is
absent or incomplete.

## Uninstall

```powershell
node packages/cli/index.js agent install `
  --target generic --config D:\path\to\mcp.json --scope user --uninstall --json
```

The same adapter is exercised by real Cursor/TRAE JSON-shaped configs. ZCode's
`mcp.servers` shape is recognized by `agent doctor` but is not rewritten by this
generic installer; use the host's own editor for that shape.
