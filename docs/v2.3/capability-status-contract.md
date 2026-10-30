# Capability status contract and M6 entry points

## Discovery status

The seven implemented Universal Program Intelligence capabilities expose `supportedLevels`, `engine`, `backendVersion`, `status`, `reason`, and `limitations` through Core/Engine capability listing, CLI `capabilities --json`, MCP `armorbreak_capabilities`, and the loopback-only Workbench tools state.

`status: REGISTERED_NOT_EXECUTED` means only that the capability is loaded in the registry. `backendVersion: null` means discovery did not probe or pin a per-run external backend version. The accompanying reason says that target-specific support, backend availability, errors, and truncation are reported by the analysis result. This status is not an analysis pass or backend readiness claim. `PARTIAL_LOCAL_TESTED` is reserved for exact-SHA evidence in the compatibility matrix.

| Capability | Support level | Declared boundary |
|---|---|---|
| `artifact.identify` | S1 | Candidate format classification is not provenance or safety proof. |
| `artifact.inventory` | S1 | Bounded archive indexing; no execution or disk extraction. |
| `source.symbols` | S2 | Language and syntax coverage follow the parser result. |
| `binary.program_ir` | S3 | Bounded static analysis; Ghidra detail depends on backend availability and per-run status. |
| `security.correlate` | S4 | Correlates imported evidence; does not confirm vulnerabilities or fetch advisories. |
| `rebuild.contract` | S5 | Organizes caller-supplied observations; does not infer a complete source contract. |
| `rebuild.compare` | S5 | Compares pre-generated finite JSON outcomes; does not execute implementations. |

## CLI and MCP

CLI keeps the existing `capabilities`, `analyze`, `workflow list`, `task`, and `report` commands. `capabilities --json` now carries the support status fields. `analyze` uses the existing Engine and trusted workspace policy.

The stdio MCP server preserves its seven prior tools and adds the fixed `armorbreak_workflow` tool. `action=list` returns registered workflows. `action=start` accepts only a registered workflow, obtains its steps from the shipped workflow definition, and refuses the request unless every step is a registered L0 capability. The caller cannot supply workflow steps, a principal, an approval token, or a command. Target reads still pass through the Core runner and configured workspace scope. L1/L2 workflows require another trusted host path and are refused here.

## Verification boundary

Integration tests exercise CLI discovery and `rebuild.contract` execution, MCP capability discovery, `rebuild.contract` execution, fixed L0 workflow execution, workflow listing, and rejection of unknown workflows. Workbench API tests read the status fields from a real runtime. The Workbench web page is a separate host/provider evidence dashboard; its visual UI has not been changed or accepted as an ArmorBreak analysis interface.
