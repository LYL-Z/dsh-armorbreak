# 升级与回滚：v1.0.3 → v1.0.4（Stage A 安全维护）

> v1.1.0 的 B–E 阶段（外部工具适配器、DAG 任务、研究工作台 UI）尚未实现；本分支先以 **v1.0.4 安全维护版**交付 Stage A。

## 1. 兼容性影响

| 变更 | 影响 | 迁移动作 |
|---|---|---|
| preset 不再挂载 `tool-fs` / `tool-fs-search` / `tool-pwsh` / `tool-bash` / `tool-web` / `tool-jobs` | 依赖通用 shell/read/web 的旧会话提示词需要调整 | 使用 `armorbreak_files` 读文件/报告；联网研究走 `armorbreak_analyze` 的 L2 能力 |
| `armorbreak_scope` 移除 `action=authorize` | 旧调用报错并给出提示 | `action=request` → 用户确认 → `action=activate` |
| `/armorbreak/state?workspace=...` 返回 403 | 任何依赖该参数的脚本失效 | 该路由只返回 MRU 工作区；需要指定工作区请用工具层的 `workspace` 参数 |
| `live.http_probe` 结果新增 `pinnedIp` / `bodyTruncated` / `redirectsFollowed` | 只增量字段 | 无需迁移 |
| `live.container_exec` 镜像必须 digest-pinned + allowlist | 旧调用传 `alpine:3.20` 会失败 | 改用 `alpine@sha256:<digest>`，并预先 `docker pull`（禁止自动拉取） |
| 新增 `armorbreak_files` 工具（第 9 个） | 工具清单增长 | 无需迁移 |
| 版本号 1.0.3 → 1.0.4 | 状态接口/健康工具版本变化 | 重装或重开 Harness |

## 2. 升级步骤（Desktop，link: 安装）

1. 备份：`Copy-Item -Recurse <workspace>\.armorbreak <backup>`（任务/证据/报告属用户资产）。
2. 更新源码到本分支（或安装新版本 bundle）；`package.json` 版本为 1.0.4。
3. 完全退出并重开 DeepSeek Harness（源码 link 安装需要新模块代际）。
4. 新会话选择「破甲模式」，调用 `armorbreak_health`：应看到 `version: "1.0.4"`、9 个工具、隔离状态与授权计数。
5. 跑 `node --test`：应 153/153。
6. 旧任务数据无需迁移（JSON schema 未变，v1.0.4 只新增可选字段/工具）。

## 3. 回滚

```powershell
git checkout v1.0.3            # 或在 bundle 管理中重装 v1.0.3
# 完全重启 Harness 后，旧工具面与旧 scope 参数恢复
```

- 回滚不会删除 v1.0.4 写入的任何任务/证据（字段向后兼容）。
- 若曾用 v1.0.4 创建授权：回滚后这些记录仍在 `policy.json`，v1.0.3 的 `armorbreak_scope list` 可读（多余字段被忽略）；需要清理时删除对应记录或重建策略文件。
- 旧状态卡请求 `?workspace=` 恢复可用，但**不建议**回滚到具有已知 P0 绕行面的版本。

## 4. 数据迁移说明

- `policy.json`：新增 `authorizationRequests` 数组；旧文件缺失该键时按空数组加载；`version: 1` 保持不变。
- 任务/证据/报告：结构未变；`armorbreak_files` 与 http_probe 新字段为增量。
- 没有自动迁移脚本，因为没有不兼容的数据结构变更；若未来引入 schemaVersion，将提供 `migrate` 命令与备份/校验/回滚流程。
