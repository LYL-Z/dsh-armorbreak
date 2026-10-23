# README 技术事实审计

- 基线：`9172f7b50352bbe152a0bd001678cfd271fd65bb`
- 日期：2026-10-23
- 范围：README/README.zh-CN、安装/使用/兼容性文档、旧 README 归档
- 原则：事实优先于营销；无法验证的内容标 `NOT_VERIFIED` 或 `EXTERNAL_UNVERIFIED`

## 1. 对照表

| 公开表述 | 事实值 | 源码 / 证据 | 结论 |
|---|---|---|---|
| 包版本 | `2.2.0-rc.1` | `package.json` | PASS |
| Node 要求 | `>=22` | `package.json` `engines.node` | PASS |
| 运行时第三方依赖 | 0 | `package.json` 无 `dependencies`；仅 1 个 `devDependencies` | PASS |
| 能力总数 | 46 | `CapabilityRegistry.load()` 输出 | PASS |
| 能力域 | 8 | 同上：android/binary/ctf/forensics/live/network/sast/web | PASS |
| 风险分布 | 44 L0、1 L1、1 L2；L3 永远拒绝 | capability registry + policy docs | PASS |
| 工作流 | 9 | `packages/core/src/workflows.js` | PASS |
| DSH Skills | 7 | `skills.js` | PASS |
| DSH 模型工具 | 10 | `tools.js` 中 10 个 `armorbreak_*` 工具 | PASS |
| MCP Server 工具 | 7 | `packages/mcp-server/index.js` 的 `TOOLS` | PASS |
| 测试记录 | 400 tests / 399 pass / 0 fail / 1 skipped | `docs/v2/acceptance/test-report.json` | PASS（基线记录） |
| Host 矩阵 | 12 入口 / 10 L0 / 9 第三方 L0 | `docs/v2/acceptance/compatibility-matrix.json` | PASS |
| Offline Golden | PASS | `docs/v2/acceptance/golden-status.json` | PASS |
| 本地模型闭环 | PASS | `provider-live-ollama.json` + Pi L0 | PASS |
| 官方 Provider Live | EXTERNAL_UNVERIFIED | `provider-matrix.md`、`golden-status.json` | PASS（如实标注） |
| Full V2.2 GA | false | `v2.2-readiness.json` | PASS（如实标注） |
| 独立安全审查 | 未完整签署 | `release-status.md`、waivers | PASS（如实标注） |
| Desktop L0 | 已有真实 E2E | `docs/v2/acceptance/desktop-e2e.md` | PASS（历史证据） |
| 安全审查状态 | 四轮 AI 辅助审查完成初审；部分发现未修复；无独立人类认证 | 用户提供的四轮审计状态 + 发布门禁 | PASS（如实标注，不披露细节） |

## 2. 纠正的旧口径

| 旧文档位置 | 旧内容 | 修正 |
|---|---|---|
| `docs/compatibility-matrix.md` | 39 个能力 / 9 个模型工具 | 46 个能力 / 10 个 DSH 工具；MCP 另为 7 个 |
| `docs/usage.md` | 14 个内置工具（8 个 ArmorBreak） | 10 个 DSH 模型工具 + 宿主标准工具；7 个 Skills |
| `docs/installation.md` | 硬编码 `D:\dsh-ABM\armorbreak` | `<BUNDLE_PATH>` / `<REPO_PATH>` 占位符 |
| `docs/v2/release/user-guide.md` | “V2 Desktop 尚未安装，M4-06 blocked” | 标为历史限制，并指向 2026-10-21 的真实 Desktop E2E |
| 旧 README 覆盖率徽章 | 85.82%（v1.1 历史） | 新 README 不再展示为当前覆盖率 |
| 旧 README Roadmap | 当前 v1.1 | 移除首页路线图，指向 Release Status |

## 3. 未修改的安全政策事项

`SECURITY.md` 的支持版本表仍停在 `1.0.x`。按任务书要求，本轮**不擅自修改安全承诺**，只记录为待安全审计/维护者审核事项。建议后续安全政策 PR 单独处理。

## 4. 未验证声明

- DeepSeek Harness 原生安装路径本轮未重新执行（`NOT_VERIFIED`，依据现有 Desktop E2E 证据）。
- macOS/Linux 桌面未在本轮实测。
- 官方 OpenAI/Anthropic/Gemini 真实端点未测试；没有购买或请求新凭据。
- Mermaid 图的 GitHub 渲染需在 PR 页面人工确认；本轮用结构检查替代本地渲染器。

## 5. 结论

README 与相关文档中的关键数字、状态和命令均有源码或证据依据。没有把 Mock Golden 写成 Live Golden，也没有把本地 Ollama 写成官方 Provider 认证。
