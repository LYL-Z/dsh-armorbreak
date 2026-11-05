# V2.3 performance measurements

## Measurement method

The M0 baseline used the repository's `node benchmarks/bench.mjs` workload on Windows 11/Node `v24.16.0`, npm `11.13.0`, source SHA `66ec0017af4b9d636f09e45f7cf55eed060512ac`. The candidate reran the same script and same 360,448-byte local fixture at M6 source SHA `965fbe4fa9abd2af73644865a56d8db64c8a6089`; its SHA-256 is `468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e`. The fixture is from the primary checkout outside this worktree; its absolute path is redacted. Candidate environment was Node `v24.16.0`, Windows x64, 24 logical CPUs, Intel Core Ultra 9 290HX Plus. It measured parser paths, report generation, and the seven-step `BinaryStaticAnalysis` workflow. The sanitized raw candidate result is `evidence/p0-h/benchmark-results.json`.

Each row uses that script's warm-up then fixed sample count and nearest-rank p50/p95. The M0 record does not include CPU model or peak-memory measurement, so same-machine CPU equivalence is not proven. These are descriptive local measurements, not a controlled performance experiment or cross-host claim.

## Baseline and candidate

| Workload | M0 p50 / p95 ms | M6 p50 / p95 ms | Candidate samples |
|---|---:|---:|---:|
| Registry cold start | 92.7 / 92.7 | 102.70 / 102.70 | 1 |
| `binary.identify` | 1.812 / 2.572 | 1.625 / 2.242 | 60 |
| `binary.strings` | 1.779 / 3.088 | 1.746 / 2.892 | 60 |
| `forensics.hash` parser | 0.953 / 1.067 | 0.814 / 0.942 | 80 |
| `binary.entropy` | 2.961 / 3.328 | 2.503 / 2.723 | 60 |
| `forensics.hash` through Runner | 110.86 / 117.24 | 87.323 / 97.155 | 20 |
| `network.pcap_overview` (5,000 packets) | 8.179 / 14.068 | 7.781 / 12.641 | 30 |
| `network.flows` (5,000 packets) | 10.123 / 11.515 | 10.943 / 14.196 | 30 |
| `sast.scan` (200 generated JS files) | 380.38 / 425.469 | 524.107 / 554.438 | 10 |
| Markdown report (50 findings / 100 evidence) | 13.824 / 15.034 | 14.153 / 15.955 | 20 |
| HTML report (50 findings / 100 evidence) | 13.49 / 19.794 | 15.289 / 18.219 | 20 |
| SARIF report (50 findings / 100 evidence) | 14.186 / 15.622 | 14.263 / 15.579 | 20 |
| `BinaryStaticAnalysis` workflow | 1,276.771 / 1,331.449 | 1,267.052 / 1,322.097 | 5 |

## Interpretation and limits

The current run shows a higher registry cold-start sample, a higher `network.flows` and SAST sample, and modestly lower seven-step workflow samples than the baseline. A second uncommitted diagnostic run on the same host produced SAST p50/p95 of 340.515/358.462 ms, demonstrating substantial run-to-run variation; only the explicit-input rerun above is retained as evidence. Small fixed samples, unrecorded M0 CPU identity, and no randomized paired runs prevent causal attribution. No performance regression budget was specified, and no increase is characterized as acceptable without owner review.

The candidate benchmark script reports end-of-process RSS `322.9 MiB` and heap `49.2 MiB`; it does not measure peak memory, and the M0 baseline explicitly says peak memory was not measured. Therefore memory change is **NOT_COMPARABLE**. No 100-run timeout/cancel soak or concurrency/peak-load test was executed. Large-input streaming throughput and cancellation latency remain unverified.

Reproduce from the repository root:

```powershell
$env:TEMP = Join-Path $PWD '.runtime\tmp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force $env:TEMP | Out-Null
node benchmarks/bench.mjs --sample fixtures/notepad.exe --out .runtime/p0-h-benchmark.json
```

Do not interpret these local microbenchmarks as product-wide performance acceptance.
