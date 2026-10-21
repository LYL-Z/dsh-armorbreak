# ArmorBreak v1.2.0 验收记录（2026-10-20）

- 测试 190/190；46 capabilities / 8 domains / 0 diagnostics。
- Gate B：TShark 4.6.9、Syft 1.54.1、JADX 1.5.6、Ghidra 12.1.4（notepad.exe 853 函数，247s）；证据 docs/acceptance/adapter-v2-real.json。
- L1 Docker 自检 + approved container COMPLETED（l1-provider.json）；L2 loopback 200（l2-loopback.json）。
- 真实模型 GUI BinaryStaticAnalysis COMPLETED、21 证据、6 发现、报告哈希（model-e2e-v12.json）。
- v1.2.0 Web/CDP：46 能力/6 任务/DaemonReady；环境视图；证据筛选；Markdown/HTML（gui-v12-verification.json）。
- 残余见 known-issues。

## V2 baseline re-run (2026-10-20)

V2 M1-01 在 eature/armorbreak-v2 上真实重跑：190 tests / 189 pass / 0 fail / **1 skipped**（missing external tool produces actionable guidance，外部工具可见性依赖本机环境）。此前记录的 190/190 是仓库历史，不作为 V2 新运行结果。
