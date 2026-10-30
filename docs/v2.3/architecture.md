# ArmorBreak V2.3 Universal Program Intelligence architecture

## Status and scope

This document describes the code at M6 source commit `965fbe4fa9abd2af73644865a56d8db64c8a6089`. It is a bounded extension of the V2.2 Core/Engine/PolicyGateway architecture, not a replacement engine and not a claim of universal language understanding. Current local validation and unimplemented boundaries are listed in [acceptance-report.md](acceptance-report.md) and [compatibility-matrix.json](compatibility-matrix.json).

## Request and evidence path

1. CLI, DSH tools, MCP, or a workflow requests a registered capability. M6 adds capability support metadata and a fixed MCP workflow discovery/start route; it does not accept caller-authored commands or steps.
2. Core builds bounded input from a scoped workspace and routes work through the existing Engine/Runner and PolicyGateway. Existing risk policy remains authoritative: static L0 work is read-only; L1 requires verified isolation and approval; L2 requires scoped authorization and approval; L3 is refused.
3. Registered analyzer manifests implement bounded operations. M1 identifies and inventories artifacts; M2 builds a limited JavaScript/TypeScript source symbol IR; M3 parses PE/ELF/Mach-O and optionally invokes Ghidra on a complete bounded copy; M4 correlates supplied offline evidence; M5 normalizes supplied behavior observations and compares supplied JSON results.
4. Results retain explicit support level, status, limitations, evidence references, and truncation/partial conditions. Registry presence is `REGISTERED_NOT_EXECUTED`; it does not mean an analysis has run.
5. Core persists task events, findings, and evidence through existing stores and renders reports through existing JSON/Markdown/HTML/SARIF paths. New schemas are under `docs/v2.3/schemas/`.

## Data flow and trust boundaries

```text
CLI / DSH / MCP / workflow
          |
          v
Core -> Engine/Runner -> PolicyGateway -> scoped input + budgets
                                          |
                                          v
                           registered capability adapter
                                          |
                                          v
                     bounded IR / offline comparison result
                                          |
                                          v
                       evidence store -> report renderer
```

Analyzer input, archive names, source comments, tool output, caller-supplied evidence, and behavior observations are untrusted data. They are never instructions or approval. The source symbol, native program, security-correlation, behavior-contract, and behavior-comparison records are bounded data contracts; they do not grant additional authority.

## Implemented representations

| Representation | Entry point | Evidence boundary |
|---|---|---|
| Artifact identity and inventory | `artifact.identify`, `artifact.inventory` | Candidate format and bounded archive index; no extraction or execution |
| Source symbols | `source.symbols` | TypeScript parser for JS/TS syntax and local symbol/reference records; no inter-file taint claim |
| Native program IR | `binary.program_ir` | PE/ELF/Mach-O structures and bounded optional Ghidra records; output is static, partial, and backend dependent |
| Security evidence | `security.correlate` | Correlates precomputed local records; vulnerability state remains `not_tested` |
| Behavior contract | `rebuild.contract` | Normalizes caller-supplied observations; references and certainty are not independently authenticated |
| Finite behavior comparison | `rebuild.compare` | Compares caller-supplied complete JSON result pairs; ArmorBreak does not execute either implementation |

## Resource and failure behavior

Adapters use explicit file, record, depth, output, and time bounds documented in their implementation notes and schemas. Invalid or incomplete inputs, missing tools, budget exhaustion, unsupported formats, and unavailable evidence must remain structured `PARTIAL`, `UNSUPPORTED`, or `INCONCLUSIVE` results. Ghidra output caps can truncate arrays; a cap sentinel is not an exact count. A finite fixture match is not global equivalence.

## Compatibility

V2.3 adds registry entries and one MCP tool while preserving the existing Core and protocol contracts, CLI command families, DSH tools, reports, task stores, approvals, and evidence chain. The observed M6 registry is 53 capabilities, 12 domains, 14 workflows, 10 DSH tools, 8 MCP tools, and 7 skills; see the exact-SHA M6 record. No schema migration is claimed for this implementation.
