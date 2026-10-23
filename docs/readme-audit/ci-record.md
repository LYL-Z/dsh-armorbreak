# CI 与预览记录

- PR：[#15](https://github.com/LYL-Z/dsh-armorbreak/pull/15)
- 分支：`docs/readme-v22-developer-experience`
- 基线：`8df5bf98b059139707cc048dcb97f8dea380873e`
- 首轮 CI：`39928989956`（merge commit `ef67bf99…`）

## 1. CI 结果

| Job | 结果 | 说明 |
|---|---|---|
| L0 offline boundary (static gate) | **success** | 文档变更未破坏静态边界 |
| L1 Docker integration (real daemon) | **success** | 真实 Docker 集成通过 |
| Node 24 on ubuntu-latest | **success** | 全量测试 |
| Node 24 on windows-latest | **success** | 全量测试 |
| Release evidence checks (commit-bound) | **failure** | 预期限制：证据 manifest 绑定基线 `e952e5de…`，PR merge commit 为 `ef67bf99…`；按任务书未修改审计证据 JSON |

失败日志：

```text
manifest commit e952e5de3f7b8ee63629f6566475936ba7bf5c14 does not match ef67bf99cc2c205bd21bfb6d6763a9ab20591169
test report commit is stale
```

这是 commit-bound 证据契约与 docs-only PR 的结构性冲突，不是文档内容或测试失败。没有通过修改 README 或跳过检查来掩盖。

## 2. 本地验证

- `npm test`：**388 tests / 387 pass / 0 fail / 1 skipped**
- `node scripts/v2/check-docs-consistency.mjs`：PASS
- `node scripts/v2/generate-docs.mjs --check`：PASS
- 相关 docs/hardening tests：7 pass
- Offline Golden 四协议测试：12 pass
- 本地链接：72 checked / 0 broken
- 外部徽章：4/4 HTTP 200
- Markdown 结构：单 H1、代码块闭合、无尾随空格、内部锚点存在

## 3. GitHub 渲染预览

浏览器扩展未连接，无法截图。使用 GitHub 官方 Markdown API 对 `README.md` 做真实 GFM 渲染：

- 输出 HTML：约 30,778 bytes
- H1：1；H2：11
- 表格：4
- 代码块：6
- Mermaid：保留为 `language-mermaid` 代码块，需在 GitHub 页面最终目视确认

渲染产物保存在工作区外部：`D:\ArmorBreak-Docs\readme-render-utf8.html`（不作为仓库交付）。

## 4. 未解决

- commit-bound 证据检查需维护者在「接受 docs-only PR」与「刷新证据 manifest」之间选择；本 PR 不擅自改证据 JSON。
- Mermaid/排版需在 PR 页面人工目视确认。
- DSH 原生 Quick Start 本轮未重跑，见历史 Desktop E2E。
