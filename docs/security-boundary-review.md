# Security Boundary Review — v1.1.0 / Stage A (delivered as v1.0.4)

基线：`97d0628`（v1.0.3）。本文件记录对「权限覆盖、授权模型、网络探测、L1 执行、文件系统、状态接口」的审计结论与修复结果。**只写实际实现并测试过的内容**；无法在本机验证的部分明确标注。

## 1. 审计方法

- 阅读 `cordis.patch.yml`、`tools.js`、`index.js`、`lib/core/{scope,runner,tasks,evidence,health}.js`、`lib/analyzers/live/manifest.js`、`tests/**`。
- 对照 `docs/security-model.md`、`docs/known-issues.md`、`docs/acceptance.md` 与真实会话记录（源码目录审计、目录型工作流重跑）。
- 在 Windows / Node 24.16 上运行全部测试与针对性负向测试；未向任何第三方公网目标发包。

## 2. 已验证问题与处置

| ID | 问题 | 风险 | 处置 | 证据 |
|---|---|---|---|---|
| SB-1 | 破甲 preset 挂载了通用 `tool-fs`/`tool-fs-search`/`tool-pwsh`/`tool-bash`/`tool-web`，这些工具不经过 ArmorBreak ScopePolicy，模型可借它们读任意文件、执行命令或联网，绕过 L0–L3 | P0 / 高 | 从 preset 移除全部通用文件/命令/Web/jobs 工具；新增 `armorbreak_files`（策略网关内的有界 list/read/stat/search，不提供写/执行）；测试断言 preset 不再包含这些包 | `cordis.patch.yml`、`lib/core/files.js`、`tools.js`、`tests/security-boundary.test.mjs` |
| SB-2 | `armorbreak_scope action=authorize` 允许模型直接创建有效授权；`operator/purpose` 是模型自填文本，不是身份验证 | P0 / 高 | 拆成 `action=request`（仅登记 pending，不授权）与 `action=activate`（必须调用平台审批服务并得到 `allowed-once`，审批来源/审批 id 写入记录）；`action=authorize` 被移除并返回迁移提示；内部 `ScopePolicy.authorize` 仅供测试/历史数据，不暴露给模型 | `tools.js`、`lib/core/scope.js`、`tests/security-boundary.test.mjs`、`tests/tools-integration.test.mjs` |
| SB-3 | `live.http_probe` 用 `fetch` + `arrayBuffer()`：先整包加载再截断；不校验连接 IP；DNS 可重绑定；无 DNS/IP 授权关联 | P0 / 高 | 改为 `node:http(s).request`：策略阶段解析并记录 IP，执行阶段用 pinned `lookup` 只连已解析地址；流式读取并在超限时立即销毁连接；不跟随重定向；请求/总超时与 AbortSignal 传导；敏感响应头脱敏；拒绝云元数据地址（`169.254.169.254` 等） | `lib/analyzers/live/manifest.js`、`lib/core/scope.js`、`tests/security-boundary.test.mjs` |
| SB-4 | `live.container_exec` 接受任意镜像/标签，无镜像白名单与 digest 固定；`--user` 未指定；超时后容器可能残留 | P0 / 高 | 镜像必须 `repository@sha256:<64hex>` 且名称在 allowlist；增加 `--pull never`、`--user 65534:65534`、`--tmpfs /tmp:...,noexec,nosuid`、`--cpus`、唯一 `--name`/label；超时后 best-effort `docker rm -f`；命令 argv 长度上限；镜像/命令校验有测试；**真实容器成功路径仍未验证（本机 Docker daemon 不可用）** | `lib/analyzers/live/manifest.js`、`tests/security-boundary.test.mjs` |
| SB-5 | 路径校验缺少 UNC/设备路径/NUL 拒绝；目录内链接已 realpath 校验但入口路径形式未归一 | P0 / 中高 | `ScopePolicy.checkFile` 与 `armorbreak_files` 统一拒绝 `\\?\`、`\\.\`、`\\server\share`、`//server/share`、NUL；继续 realpath 双向校验与敏感路径拒绝 | `lib/core/scope.js`、`lib/core/files.js`、测试 |
| SB-6 | `/armorbreak/state` 接受任意 `?workspace=` 并返回该目录任务，等于无鉴权的目录枚举接口；未限制非 loopback | P0 / 中高 | 路由仅接受 GET/HEAD、仅 loopback peer、拒绝 `workspace` 查询参数（固定返回进程 MRU 工作区），增加 `no-store`/`nosniff`/`no-referrer`；导出 `createStateHandler` 供测试 | `index.js`、测试 |

## 3. 权限覆盖矩阵（v1.0.4）

| 入口 | 是否经过 ArmorBreak Policy | 说明 |
|---|---|---|
| armorbreak_analyze / workflow（L0） | ✅ 是 | 路径/敏感目录/工作区校验（`ScopePolicy.checkFile`） |
| armorbreak_analyze（L1） | ✅ 是 | 隔离可用性 + 平台审批 + 样本路径校验 |
| armorbreak_analyze（L2） | ✅ 是 | 授权 + 平台审批 + 目标匹配 + 限速 + DNS/IP 固定 |
| armorbreak_files（list/read/stat/search） | ✅ 是 | 同一 `checkFile`；只读、有界、无写/执行 |
| armorbreak_scope request/activate | ✅ 分离 | 模型只能申请；激活依赖平台审批 |
| 通用 fs/shell/web/jobs 工具 | ⛔ 不挂载 | 严格研究模式不再暴露；它们仍受 Harness 全局沙箱约束，但**不属于** L0–L3 |
| Host `/armorbreak/state` | ✅ loopback + 无参数 | 只读脱敏快照；不提供执行 |
| `present` / `todo` / `ask-user` / `skill` | ➖ 非执行 | 不访问目标文件系统/网络（present 仅声明已存在文件） |

> 结论边界：L0–L3 只对 **ArmorBreak 工具**成立。未挂载的通用工具不在此模式下可用；若未来重新挂载，必须接入等效权限网关并有测试，否则不得声称“所有工具受 L0–L3 控制”。

## 4. 仍存在的限制（未解决/未验证）

1. **L1 成功路径未验证**：本机 Docker daemon 不可用，无法证明容器实际启动、非 root 生效、超时清理成功；仅验证拒绝分支、参数/镜像校验与 argv 构造。
2. **模型驱动 GUI E2E 未验证**：无桌面模型凭据；`armorbreak_files` 与新授权流程尚未在真实 GUI 会话中由模型调用。
3. **TOCTOU**：realpath 校验与 `open` 之间仍存在极窄竞态；Node 未暴露 `O_NOFOLLOW`/重解析点标志，未完全消除（在 Windows 上尤其如此）。
4. **授权激活的“人”身份**：`approvedBy` 目前固定记录为 `platform-approval`，依赖 Harness 审批 UI 的真实用户交互；未接入独立身份源/签名。
5. **状态接口**：loopback-only + 无参数枚举，但同机其他进程仍可读取状态快照（本机威胁模型内接受；非 loopback 部署被拒绝）。
6. **容器镜像 allowlist 仅按名称**，未做签名验证（cosign 等）。

## 5. 复现

```powershell
node --test                                   # 153/153
node --test tests/security-boundary.test.mjs  # 7 个边界测试
git diff 97d0628 -- cordis.patch.yml tools.js lib/core/scope.js lib/core/files.js index.js lib/analyzers/live/manifest.js
```
