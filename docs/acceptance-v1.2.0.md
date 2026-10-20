# ArmorBreak v1.2.0 验收记录（2026-10-20）

- 测试 190/190；46 capabilities / 8 domains / 0 diagnostics。
- Gate B：TShark 4.6.9、Syft 1.54.1、JADX 1.5.6、Ghidra 12.1.4（notepad.exe 853 函数，247s）；证据 docs/acceptance/adapter-v2-real.json。
- L1 Docker 自检 + approved container COMPLETED（l1-provider.json）；L2 loopback 200（l2-loopback.json）。
- 真实模型 GUI BinaryStaticAnalysis COMPLETED、21 证据、6 发现、报告哈希（model-e2e-v12.json）。
- v1.2.0 Web/CDP：46 能力/6 任务/DaemonReady；环境视图；证据筛选；Markdown/HTML（gui-v12-verification.json）。
- 残余见 known-issues。
