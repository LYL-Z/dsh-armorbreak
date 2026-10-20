# Benchmarks — ArmorBreak v1.0.3

> All numbers in this document are **measured on the reference machine below**
> by [`benchmarks/bench.mjs`](../benchmarks/bench.mjs), not estimated. The raw
> machine-readable output is committed as
> [`benchmarks/results.json`](../benchmarks/results.json). Numbers are specific
> to this host and dataset; treat them as an upper-bound reference for the pure
> JavaScript implementations, not as a service SLA.

## 1. Test environment

| Item | Value |
|---|---|
| Host | Windows 11 (win32, x64) |
| CPU | Intel® Core™ Ultra 9 290HX Plus — 24 cores / 24 logical processors, 2.70 GHz |
| RAM | 63.68 GiB |
| Runtime | Node.js v24.16.0 |
| Harness | DeepSeek Harness Desktop 0.2.1-rc.2 (not required for the benchmark: core runtime is host-independent) |
| ArmorBreak | v1.0.3, 39 capabilities / 8 domains |
| Benchmark tool | `benchmarks/bench.mjs` (zero dependencies, `performance.now()`) |
| Iterations | 1–80 per row after one warm-up pass |
| Sample | `notepad.exe` — 360,448 bytes, PE32+ x86-64 |
| PCAP dataset | synthetic classic PCAP, 5,000 packets / 700,024 bytes |
| SAST dataset | synthetic JavaScript project, 200 files (`eval`, SQL concatenation, fake AWS key) |
| Report dataset | 1 task with 50 findings + 100 evidence records |

Reproduce:

```bash
node benchmarks/bench.mjs \
  --sample /path/to/notepad.exe \
  --out benchmarks/results.json
```

## 2. Measured results

### 2.1 Capability parsing (pure `capability.run`, prepared bounded input)

| Capability | Mean | p50 | p95 | Throughput | Derived unit cost |
|---|---:|---:|---:|---:|---|
| `forensics.hash` (360 KiB) | 0.865 ms | 0.842 ms | 0.956 ms | 1,156.7 ops/s | ≈ 417 MB/s SHA-256+MD5+SHA-1/SHA-512 |
| `binary.identify` (360 KiB PE) | 1.836 ms | 1.718 ms | 2.349 ms | 544.7 ops/s | ≈ 210 MB/s |
| `binary.strings` (360 KiB PE) | 1.758 ms | 1.631 ms | 2.309 ms | 568.9 ops/s | ≈ 221 MB/s |
| `binary.entropy` (360 KiB PE) | 2.592 ms | 2.558 ms | 2.878 ms | 385.8 ops/s | ≈ 139 MB/s |
| `network.pcap_overview` (5,000 pkts) | 8.268 ms | 7.770 ms | 10.605 ms | 121.0 ops/s | ≈ 643k packets/s |
| `network.flows` (5,000 pkts) | 9.268 ms | 9.592 ms | 11.201 ms | 107.9 ops/s | ≈ 540k packets/s |
| `sast.scan` (200 files) | 93.594 ms | 88.020 ms | 123.599 ms | 10.7 ops/s | ≈ 2,272 files/s |

### 2.2 End-to-end invocation (through the policy runner + evidence/audit persistence)

| Path | Mean | p50 | p95 | Throughput |
|---|---:|---:|---:|---:|
| `forensics.hash` through runner | 36.780 ms | 36.379 ms | 40.448 ms | 27.2 ops/s |
| `BinaryStaticAnalysis` workflow (7 steps) | 481.309 ms | 483.186 ms | 492.990 ms | 2.1 workflows/s |
| Registry cold start (39 capabilities, contract validation) | 62.83 ms | — | — | 15.9 starts/s |

### 2.3 Report generation (50 findings + 100 evidence)

| Format | Mean | p50 | p95 | Throughput |
|---|---:|---:|---:|---:|
| Markdown | 4.287 ms | 4.118 ms | 5.173 ms | 233 ops/s |
| HTML | 4.322 ms | 4.046 ms | 4.806 ms | 231 ops/s |
| SARIF 2.1.0 | 3.847 ms | 3.749 ms | 4.873 ms | 260 ops/s |

### 2.4 Process memory (after the full run)

| Metric | Value |
|---|---:|
| RSS | 257.3 MiB |
| Heap used | 26.3 MiB |

## 3. Reading the numbers

1. **Parsing is cheap; durable evidence is the cost.** A 360 KiB PE hash costs
   < 1 ms of CPU, while one full runner invocation costs ≈ 36 ms. The difference
   is dominated by durable writes: task state transitions (`task.json`), evidence
   JSONL append + hash chain, audit JSONL append, and `findings.json` rewriting.
   This is an intentional trade-off: every tool call must be replayable.
2. **The workflow path is 7 × runner overhead.** 481 ms / 7 ≈ 69 ms per step,
   consistent with persistence cost plus report generation. For bulk batch
   analysis (hundreds of samples), driver-level loops should reuse one task per
   batch and emit findings without per-sample task churn — a roadmap item.
3. **Directory scanning is I/O-bound.** 200 tiny files at ≈ 2,272 files/s; real
   repositories (10k+ files) are bounded by configurable `maxFiles`/`maxBytes`
   caps and by filesystem metadata cost, not regex CPU.
4. **PCAP parsing** reaches ≈ 0.5–0.6M packets/s on a synthetic Ethernet/IPv4/UDP
   capture; TLS/DNS dissection adds per-packet fields but stays linear.
5. **Memory is flat.** The runtime keeps no document model: inputs are bounded
   buffers, outputs are capped at 256 KiB, and per-task state is small. RSS is
   dominated by the Node process and the host's loaded Harness modules.

## 4. Complexity and bounds (why these numbers scale)

| Capability | Algorithmic shape | Hard bounds |
|---|---|---|
| `forensics.hash` | O(n) streaming over the bounded buffer | 32 MiB input cap |
| `binary.*` | O(n) header/section/string scan, O(n log n) string sort | 32 MiB input, `maxStrings` 1,000 |
| `network.*` | O(packets), flow table O(flows) | `maxItems` 300, packet caps |
| `sast.scan` | O(files × rules) with 59 line rules | `maxFiles` 2,000 (core), per-file 4 MiB |
| reports | O(findings + evidence) | 200 findings / 300 evidence per invocation |
| JSONL chains | O(1) append (read-tail is bounded to the last line) | in-process mutex per file |

## 5. Horizontal comparison (qualitative, no fabricated numbers)

External scanners were **not installed on this host**, so this table compares
architecture and operational properties rather than seconds.

| Dimension | ArmorBreak (this repo) | Ghidra / IDA headless | Semgrep / CodeQL | TShark / Zeek | MobSF / JADX |
|---|---|---|---|---|---|
| Runtime dependency | **zero** (Node builtins only) | JVM + multi-GB install | Python/Node + rule packs | native + libs | JVM/Android SDK |
| Offline by default | ✅ all L0 | ✅ | ✅ | ✅ | partial |
| Portable inside DSH preset | ✅ native tools | via wrappers | via wrappers | via wrappers | via wrappers |
| Deep decompilation / dataflow | ❌ (by design, v1) | ✅ | ✅ | n/a | ✅ |
| Evidence chain + audit | ✅ built-in | ❌ | partial | ❌ | partial |
| Policy L0–L3 + approvals | ✅ built-in | ❌ | ❌ | ❌ | ❌ |
| 360 KiB PE static overview | ≈ 1–3 ms | seconds–minutes | n/a | n/a | n/a |

The intended architecture is **complementary**: ArmorBreak owns orchestration,
scope/approval, evidence and reporting; external tools remain optional adapters
(see roadmap). Benchmarks for those adapters will be added when they land, with
the tool version pinned and the measurement method committed.

## 6. Vertical comparison across versions

| Version | Tests | Core line coverage | Notable performance-relevant change |
|---|---:|---:|---|
| v1.0.0 | 128 | 84.9% | baseline runner/evidence pipeline |
| v1.0.1 | 132 | 85.0% | lossless-JSON sanitizer + session-workspace resolution |
| v1.0.2 | **145** | **85.6%** | per-file mutex serialization (adds lock acquisition ~µs), realpath checks, directory-target routing; `runner.js` 88.55% → 93.65% |
| v1.0.3 | **146** | **85.6%** | optional `excludePaths` for SAST file enumeration (no effect on parser hot paths) |

The v1.0.2 concurrency and realpath hardening add negligible cost relative to
file I/O: lock acquisition happens once per append, on a promise queue.

## 7. Reproduce & verify

```bash
# 1. Full functional suite
node --test

# 2. Coverage (Node built-in)
node --test --experimental-test-coverage

# 3. Benchmarks
node benchmarks/bench.mjs --sample <path-to-PE> --out benchmarks/results.json

# Expected shape of the output: one JSON object with `environment`, `results[]`,
# `memory`; every row has mean/p50/p95/p99 and opsPerSec.
```

CI runs the same benchmark command on `ubuntu-latest` (see
`.github/workflows/ci.yml`); its `benchmarks/results.ci.json` is machine-specific
and not used as a release gate.
