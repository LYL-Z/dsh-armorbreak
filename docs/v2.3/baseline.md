# ArmorBreak V2.3 implementation baseline

## Frozen source and workspace

- Repository: `LYL-Z/dsh-armorbreak`, remote `origin/main`.
- Baseline commit: `66ec0017af4b9d636f09e45f7cf55eed060512ac` (`2026-10-26`, security documentation merge).
- Working branch: `feature/v2.3-universal-program-intelligence`, created from that exact commit in an isolated worktree.
- The primary checkout's `main` was left untouched. Other existing audit worktrees were not modified.
- Release line observed from GitHub on 2026-10-26: latest stable `v2.2.0`; no `v2.3.0` release/tag exists.
- OS/runtime: Windows 11 build 26300, Node.js `v24.16.0`, npm `11.13.0`; package requires Node `>=22`. `package-lock.json` is lockfile v3 and pins TypeScript `5.9.3` as the only dev dependency.
- Core contract: `CORE_VERSION=0.1.0-p1`, protocol `1.0.0`; `createCore` exposes capabilities, health and close. Runtime read limits include 32 MiB input, 4 MiB per file, 300 items, 256 KiB result and 60 s timeout.

## Baseline commands and evidence

Raw logs are retained under `docs/v2.3/evidence/m0/` in the local worktree. They are ignored by Git because `*.log` is ignored and contain host-local paths from test diagnostics; sanitized results are recorded in `evidence/m0/test-results.json`.

| Command | Result | Notes |
|---|---:|---|
| `npm ci` | PASS, exit 0 | Clean install from the lockfile. |
| `npm test` with default Windows TEMP on C: and worktree on D: | 524/530, exit 1 | Six environment-dependent failures: Windows safe-file tests rejected the cross-volume temporary root, and a hard-link fixture failed with `EXDEV`. No assertions were relaxed. |
| Targeted rerun of the six affected tests with TEMP/TMP inside the D: worktree | 14/14, exit 0 | Confirms affected tests pass when source and temp are on the same volume. |
| `npm run typecheck` | PASS, exit 0 | TypeScript project check. |
| `npm run bench` | PASS, exit 0 | Rewrote the tracked benchmark result with a machine-local path; that generated file was restored to its baseline blob before the canonical full run. Do not commit benchmark output. |
| Full `npm test` after setting TEMP/TMP to an ignored same-volume runtime directory and restoring generated benchmark output | 530/530, exit 0 | Canonical baseline suite; 0 skipped. Runtime 136.7 s. |

The cross-volume behavior is a test-environment constraint rather than a source change. The default-environment failure is retained as evidence and is not hidden by the same-volume rerun.

## Runtime registry and adapters

The actual runtime registry snapshot is in `evidence/m0/current-registry.json`. At this SHA it contains 46 capabilities in 8 domains (44 L0, 1 L1, 1 L2), 9 workflows, 10 DSH model tools, 7 MCP tools and 7 skills. Registry diagnostics are empty.

Six external analysis tools were probed directly and are classified only as `DETECTED`; no target-analysis E2E was run for them. Existing adapter unit tests use injected executors or canned parser output and therefore remain `MOCK_ONLY` evidence for tool invocation. The HealthService version probe does not work for some Windows `.cmd` shims, so the matrix records direct PowerShell probes separately. Ghidra's version is inferred from its installation directory; its help output was observed, but no binary was analyzed.

| Tool | Direct status/version | Real sample analysis | Adapter tests |
|---|---|---|---|
| Ghidra | DETECTED; installation directory `12.1.4_PUBLIC`; help output available | NOT RUN | MOCK ONLY |
| JADX | DETECTED; `1.5.6` | NOT RUN | MOCK ONLY |
| Semgrep | DETECTED; `1.181.0` | NOT RUN | MOCK ONLY |
| Trivy | DETECTED; `0.76.0`; local DB present | NOT RUN | MOCK ONLY |
| Syft | DETECTED; `1.54.1` | NOT RUN | MOCK ONLY |
| TShark | DETECTED; `4.6.9` | NOT RUN | MOCK ONLY |

`binary.ghidra`, `android.jadx`, `sast.syft` and `network.tshark` do not declare their external tool in the capability manifest. Docker CLI `29.8.1` is present, but the Linux engine is unavailable; L1 isolation is therefore BLOCKED and has not been verified.

## Existing system shape and compatibility constraints

- The only current capability router is `CapabilityRegistry`, which discovers `lib/analyzers/<domain>/manifest.js`. Execution is mediated by the existing Core/runner and PolicyGateway.
- The existing SAST scanner is bounded, line-oriented rule matching for a limited language set; it is not AST parsing or cross-file taint analysis.
- Native analysis already identifies PE/ELF/Mach-O and provides structural heuristics. `binary.ghidra` is an external adapter; its presence is not proof of call-graph coverage.
- Current offline workflows are listed in the registry snapshot. Existing CLI, MCP, DSH, evidence-chain, approval, scope and policy contracts must remain compatible.
- Old task data and reports remain governed by their existing schemas. The v2.3 work must not weaken L0/L1/L2/L3 policy or expose arbitrary shell access.

## Initial v2.3 status

No v2.3 implementation was present at baseline. The Universal Artifact Pipeline, normalized program IR, source symbol navigation, native/bytecode IR, evidence correlator, and rebuild contract/compare are all `NOT_IMPLEMENTED` at this frozen SHA. The machine-readable compatibility/status table is `compatibility-matrix.json`; status changes must be backed by code and positive, negative, and adversarial tests.

Benchmark reference values from this machine are preserved in `evidence/m0/test-results.json`; peak memory was not measured. They are comparison points only and are not cross-machine performance claims.

## Environment change after the frozen baseline

After the M0 snapshot was recorded, the user started Docker Desktop. A fresh ArmorBreak isolation probe reported `DaemonReady` on Docker client/server `29.8.1`; the locally available digest-pinned BusyBox image then passed the built-in harmless isolation self-test with `--pull=never`, `--network=none`, `--read-only`, non-root UID/GID, dropped capabilities, and bounded process/memory/CPU settings. The result is recorded separately in `evidence/m0/post-baseline-environment.json`.

This verifies the isolation container configuration for that test-local state root. It did not run a target sample, grant an L1 approval, or change the frozen baseline snapshot. Any real L1 capability remains subject to the active runtime's state, scope, isolation gate, and per-target approval.
