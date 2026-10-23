# 文档修改对照

- 分支：`docs/readme-v22-developer-experience`
- 基线：`8df5bf98b059139707cc048dcb97f8dea380873e`
- 范围：README、文档信息架构、安装/使用/兼容性/用户指南、旧 README 归档
- 非范围：生产代码、权限策略、Release Gate、测试断言、审计证据 JSON、SBOM、Tag/Release

| 文件 | 修改 | 原因 |
|---|---|---|
| `README.md` | 完全重写为英文主入口 | 首屏定位、三条接入路径、Quick Start、状态与文档导航；新增安全保证状态（设计目标/自动化测试/AI 辅助审查/待修复/无人类认证） |
| `README.zh-CN.md` | 新增完整中文镜像 | 国际化与中文用户入口；安全声明与英文版一致 |
| `docs/readme-archive-v2.2.md` | 新增旧 README 归档 | 保留原算法/ADR/benchmark 内容，避免首页密度 |
| `docs/installation.md` | 去除本机绝对路径；补 MCP/Core 指针 | 可移植性与入口一致性 |
| `docs/usage.md` | 8→10 个 DSH 工具；区分 MCP 7 工具 | 修正过期工具数 |
| `docs/compatibility-matrix.md` | 39→46 能力、9→10 工具、域分布更新；增加版本范围说明 | 修正旧口径，保留历史记录标识 |
| `docs/v2/release/user-guide.md` | 标注 V2.0 历史范围；Desktop 限制标为历史并指向 E2E | 避免把旧限制当成当前状态 |
| `docs/readme-audit/fact-check.md` | 新增 | 技术事实审计 |
| `docs/readme-audit/dx-review.md` | 新增 | Quick Start/DX 验证记录 |
| `docs/readme-audit/link-validation.md` | 新增 | 链接检查结果 |

## 未修改

- `SECURITY.md` 支持版本表仍为 1.0.x；按任务书作为安全政策待审项，不改安全承诺。
- 历史验收证据与任务 JSON（`docs/v2/acceptance/**`、`docs/v2/tasks/**`）不改写。
- 旧 README 归档中的历史数字保留，作为历史快照。
- 核心代码、权限策略、Release Gate、SBOM、Tag 均未修改。

## 兼容性说明

- 新旧 README 的核心事实一致；旧首页不再作为“当前状态”来源。
- 生成文档仍由 `scripts/v2/generate-docs.mjs` 生成；本轮只改其面向用户的入口与旧文档。
