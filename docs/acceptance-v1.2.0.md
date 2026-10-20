# ArmorBreak v1.2.0-alpha.1 验收记录

**日期:** 2026-10-20
**结论:** 第一增量通过；v1.2.0 未完成，不得按完整版发布。

## 自动化

- `node --test`：**182 / 182**。
- Registry：**42 capabilities / 8 domains / 0 diagnostics**。
- 新测试：`tests/environment.test.mjs`（隔离状态机/自检/WSL2 语义/安装指引）、`binary.behavior`（敏感 API 聚合、hypothesis、确定性、空输入拒绝）。
- 工作台 API：`/armorbreak/environment` 只读诊断；`ui-api` 覆盖环境路由的 loopback/GET/workspace 拒绝与“DaemonReady ≠ IsolationVerified”语义。
- 工作台 UI：工具页环境视图、证据按严重度/验证级别筛选、报告 Markdown/HTML 格式选择（client.js 语法检查通过；真实桌面视觉验证留到重启后）。

## 手动/真实环境

- 运行中的 v1.1.1 GUI 已确认状态卡/工具页/真实模型调用（见 `docs/acceptance/screenshots/`）；v1.2.0 代码尚未加载到运行中的 Desktop。
- Docker 29.8.1 可用，但 provider manager 尚未接入 runner 的 L1 门；本增量不改变 L1 执行边界。

## 待完成（v1.2.0）

隔离门接线、Ghidra/JADX/TShark/Syft、完整多步桌面 E2E、R2/R3 余项。
