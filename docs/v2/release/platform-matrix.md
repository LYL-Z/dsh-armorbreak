# Platform / Compatibility Matrix (M4-07)

| Platform | Node | Status | Evidence |
|---|---|---|---|
| Windows 11 x64 | 24.16.0 | PASS (unit/offline/perf local) | CI windows-latest + local runs |
| Ubuntu 24.04 x64 (GHA) | 24 | PASS (unit/offline/benchmark) | CI ubuntu-latest |
| Linux container `node:24-alpine` | 24 | PASS (network-none: 3/3 static, 62/62 benchmark) | `airgap-container.json` |
| macOS | — | **N/A — not tested** | no host |
| Windows DSH Desktop real GUI + model | — | **BLOCKED** | `desktop-e2e.json` |

No cross-platform PASS is claimed for macOS or for a real desktop V2 install. Optional external tools (Tshark/Ghidra/JADX/Syft/Semgrep/Trivy) are separate dependencies with their own licenses and are not bundled.
