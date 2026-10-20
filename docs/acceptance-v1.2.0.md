# ArmorBreak v1.2.0-alpha.1 验收记录

**日期:** 2026-10-20
**结论:** 第一增量通过；v1.2.0 未完成，不得按完整版发布。

## 自动化

- `node --test`：**182 / 182**。
- Registry：**42 capabilities / 8 domains / 0 diagnostics**。
- 新测试：`tests/environment.test.mjs`（隔离状态机/自检/WSL2 语义/安装指引）、`binary.behavior`（敏感 API 聚合、hypothesis、确定性、空输入拒绝）。

## 手动/真实环境

- 运行中的 v1.1.1 GUI 已确认状态卡/工具页/真实模型调用（见 `docs/acceptance/screenshots/`）；v1.2.0 代码尚未加载到运行中的 Desktop。
- Docker 29.8.1 可用，但 provider manager 尚未接入 runner 的 L1 门；本增量不改变 L1 执行边界。

## 待完成（v1.2.0）

隔离门接线、Ghidra/JADX/TShark/Syft、UI 环境页/证据筛选/报告格式、完整多步桌面 E2E、R2/R3 余项。
