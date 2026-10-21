# ADR 0001 — V2 stack boundaries (AB2-M1-12)

**Status:** Accepted · 2026-10-20
**Context:** Baseline v1.2.0 is a Cordis/Node bundle with zero runtime npm dependencies, 46 capabilities, 9 workflows, and real adapters for Ghidra/JADX/TShark/Syft/Semgrep/Trivy.

## Decision

1. Keep **Node.js/Cordis** as the Host control plane, policy gateway, runner, task queue, UI connection and evidence writer. No microservice split before profiling proves a bottleneck.
2. Keep **JavaScript analyzers** in-process for L0. CPU-heavy or untrusted tools run out-of-process with argv arrays and bounded output; Docker/Podman remain L1 providers.
3. Use **Python isolated workers** only for future AI evaluation adapters (Garak/PyRIT/Inspect); they must be dependency-locked, env-allowlisted and never receive Host secrets.
4. Use **SQLite** for the future catalog/knowledge index only after M1/M2 contracts are stable; no native module is added to the Host before an auditable binding is chosen.
5. Optional **Rust** only for a profiled high-throughput stream parser; not a rewrite plan.
6. Java remains for Ghidra/JADX; JDK/JRE are external dependencies, reported as separate install states, never as "offline-free".

## Consequences

- V2 can incrementally add modules without breaking preset ID `armorbreak`, tool names, workflow IDs or historical `.armorbreak` data.
- Performance claims require same-machine comparison; no claim of universal speedups.
- A future real air-gapped VM run is still required for the Gate-Offline claim; the static boundary test is only a pre-gate.

## Rejected alternatives

- Full Rust/microservice rewrite: no profile evidence, high regression cost.
- Bundling every external tool into Core: license/runtime/disk and supply-chain risk.
- Trusting `PATH` tool versions as proof of capability: version strings are metadata, not execution permission.
