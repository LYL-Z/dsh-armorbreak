# README / DX 验证记录

- 日期：2026-10-23
- 工作区：`D:\ArmorBreak-Docs\armorbreak-docs`（独立 clone，未进入其他审计工作树）
- 基线：`8df5bf98b059139707cc048dcb97f8dea380873e`

## 1. 首屏信息设计

新 README 首屏在 10–20 秒内回答：

1. 项目是什么：面向 AI Agent 的授权安全研究工具包；
2. 有什么不同：宿主中立 Core、证据链、模型不是审批主体；
3. 怎么开始：DSH / 通用 MCP / 独立 Core 三条入口；
4. 哪些已验证：Offline Golden、本地模型、12 入口/10 L0/9 第三方；
5. 哪些未完成：官方 Provider Live、独立审查、Full V2.2 GA。

旧 README 的 1000+ 行算法、ADR、benchmark 内容保留在 `docs/readme-archive-v2.2.md`，新首页通过文档表导航，不直接删除。

## 2. Quick Start 验证状态

| 路径 | 状态 | 证据 / 说明 |
|---|---|---|
| A. DSH 原生 | **NOT_VERIFIED（本轮）** | 未重新操作 DSH profile；引用已有 `docs/v2/acceptance/desktop-e2e.md` 真实 Desktop L0 |
| B. 通用 MCP | **PASS** | 在 `D:\ArmorBreak-Docs\dx-mcp-test` 隔离目录实测 dry-run → apply → doctor → uninstall |
| C. 独立 Core | **PASS** | 隔离目录运行 `createCore`，返回 `version: 0.1.0-p1`、`capabilities: 46` |
| CLI L0 analyze/report | **PASS** | `forensics.hash` 任务 `task_mvkp40uv_a74fb45e`，报告 SHA-256 `6c1f3a00bf5c1ab517388a0e244360124056c86b14470d4386c9d945af0c8f72` |

### B 路径关键输出

- Dry-run：`status: DRY_RUN`，`changed: true`，未写入文件；
- Apply：`status: INSTALLED`，生成 `mcp.json.armorbreak.bak`；
- Doctor：`status: OK`，`serverNames: ["armorbreak"]`，`problems: []`；
- Uninstall：`status: UNINSTALLED`，配置恢复为 `{"mcpServers":{}}`；
- 卸载后任务证据仍保留在 `<workspace>/.armorbreak/tasks/task_mvkp40uv_a74fb45e/`。

### C 路径关键输出

```json
{
  "version": "0.1.0-p1",
  "capabilities": 46,
  "workspace": "D:\\ArmorBreak-Docs\\dx-core-test\\workspace"
}
```

## 3. Offline Golden

运行：

```powershell
node --test tests/provider-golden.test.mjs tests/provider-protocols.test.mjs tests/provider-client.test.mjs tests/provider-golden-advanced.test.mjs
```

结果：**12 tests / 12 pass / 0 fail**。

覆盖：四协议 text/tool/SSE/error、Token/usage、参数转换、无效参数、多轮工具循环、预算、异常 SSE、截断流。

## 4. 文档检查

- `node scripts/v2/check-docs-consistency.mjs`：PASS
- `node scripts/v2/generate-docs.mjs --check`：PASS
- `node --test tests/docs-consistency.test.mjs tests/generated-docs.test.mjs tests/hardening.test.mjs`：7 pass
- 本地链接检查：72 个相对链接，0 broken（检查 README、README.zh-CN、installation、usage、compatibility、user-guide）
- 外部徽章 HEAD：4/4 HTTP 200
- 全量测试：**388 tests / 387 pass / 0 fail / 1 skipped**（安装 devDependency `typescript@5.9.3` 后；依赖来自 `package.json`，未提交 `node_modules`）

## 5. 已知问题 / 未解决项

1. DSH 原生 Quick Start 本轮未重新执行，只保留历史真实证据。
2. `SECURITY.md` 支持版本表仍为 1.0.x，按任务书未修改，待安全审计/维护者处理。
3. GitHub PR 上的 Mermaid/排版渲染需在 PR 页面人工复核；本轮仅验证源码结构。
4. macOS/Linux 未实测，README 已保留限制。
