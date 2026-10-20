# 验收报告 — v1.1.0 Stage A + Stage B（首批）

- 基线：v1.0.3（`97d0628`），146 测试
- 本次：Stage A 安全维护（v1.0.4，已合并 main）+ Stage B 首批外部适配器（**已合并 main**，merge `8d3a8d5`）
- **Gate B（真实外部工具）：通过** —— 本机安装 Semgrep 1.181.0 / Trivy 0.76.0 并真实扫描本地示例项目，见 §2.2
- 测试：`node --test` → **160 用例，159 通过、0 失败、1 跳过**（跳过项为“工具缺失”路径：工具已安装时按设计 skip）
- v1.1.0 的 C–E 阶段未实现：DAG/异步任务、证据数据迁移、研究工作台 UI

## 1. 交付物状态

| 任务书章节 | 状态 | 证据 |
|---|---|---|
| P0 1.1 通用工具权限绕行 | ✅ 已修复 | preset 移除 fs/shell/web/jobs；新增策略内 `armorbreak_files`；`tests/security-boundary.test.mjs` |
| P0 1.2 授权与模型分离 | ✅ 已修复 | `request` → 平台审批 → `activate`；审批来源写入记录；旧 `authorize` 移除 |
| P0 1.3 网络探测边界 | ✅ 主要修复 | 流式有界读取、pinned IP、不跟随重定向、超时/Abort、脱敏、元数据地址拒绝；DNS 解析在策略期完成 |
| P0 1.4 L1 容器执行 | ✅ 本机验证 | 镜像 digest/allowlist、非 root、--pull never、唯一名称、超时清理；`scripts/verify-l1.mjs` 真机通过（busybox digest，uid=65534、只读 /sample、无 eth） |
| P0 1.5 文件/工作区安全 | ✅ 部分 | UNC/设备/NUL 拒绝、realpath、敏感路径、目录读取有界；**TOCTOU 未彻底消除** |
| P0 1.6 状态接口 | ✅ 已修复 | loopback-only、GET/HEAD、拒绝 workspace 枚举 |
| P1 外部工具适配器 | ✅ Gate B 通过（真实 CLI） | Semgrep 1.181.0 / Trivy 0.76.0 真实扫描：capability 层 6 + 67 findings，runner 层任务 COMPLETED、证据链 verified；见 §2.2 与 `docs/acceptance/gate-b-*` |
| P1 任务系统 v2 | ❌ 未实现 | 仅设计文档 `docs/workflow-engine-v2.md` |
| P1 Windows 隔离管理 | ❌ 未实现 | 设计 `docs/isolation-providers.md`；L1 仍不可用 |
| P1 证据/任务数据体系 | ❌ 未实现 | 未做 schemaVersion/迁移；`armorbreak_files` 已记录 hashScope |
| P1 研究工作台 UI | ❌ 未实现 | 仍为状态卡 |
| P2 分析深度/智能流程 | ❌ 未实现 | 任务书允许后续版本 |

## 2. 实际执行的测试

```text
node --test
ℹ tests 160
ℹ pass 159
ℹ fail 0
ℹ skipped 1
```

跳过的 1 个用例是 `tests/external-adapters.test.mjs` 中“缺失工具返回安装指引”的检查：Semgrep 安装后该路径按设计 `skip`（安装前为 160/160 通过）。

Stage B 新增 7 个适配器测试：Semgrep/Trivy 正常 JSON 归一化、severity/confidence/verification 分离、位置/规则/证据、畸形/错误 schema 拒绝、输出上限与确定性、注入执行器的 capability 路径、缺失工具 fail-closed。

## 2.1 Stage B 真实运行记录

- **L1 Docker 成功路径（真实）**：`node scripts/verify-l1.mjs` → `ok: true`，状态 COMPLETED，exit=0，`uid=65534(nobody)`，`touch /sample/... → Read-only file system`，容器内仅 `lo` 网络；证据 2 条、报告生成。JSON：`docs/acceptance/l1-docker-verification.json`。
- **Semgrep/Trivy（Gate B，真实 CLI）**：本机安装 Semgrep 1.181.0 / Trivy 0.76.0（D:），通过 `node scripts/verify-gate-b.mjs` 真实执行：capability 层 6 + 67 findings，runner 层任务 COMPLETED、证据链 verified（150 条），详见 §2.2。

新增 7 个边界测试（`tests/security-boundary.test.mjs`）：
1. strict preset 不挂载通用工具、注册 armorbreak_files、移除 authorize；
2. 授权申请不生效、无平台审批不能激活、审批后签名记录、撤销；
3. UNC/设备/NUL 路径拒绝；
4. 受控文件读取（工作区、越界拒绝、截断/hashScope、搜索、stat）；
5. HTTP 探测：pinned IP、302 不跟随、响应体流式截断、敏感头脱敏；
6. 容器镜像 digest/allowlist 与硬化 argv；
7. 状态路由 loopback-only、拒绝 workspace 枚举、方法限制。

未执行（环境原因，明确不伪造）：
- Docker 真实容器成功路径/超时清理（本机 daemon 不可用）。
- 模型驱动桌面 GUI E2E、授权弹窗交互（无桌面模型凭据/浏览器控制）。
- 第三方公网 SSRF/DNS 重绑定真实网络测试（明确禁止向公网目标测试；仅本地回环 + 注入解析测试）。
- macOS/Linux 真机安装验证（CI 已跑 Ubuntu 测试，但非真实桌面集成）。

## 2.2 Gate B 真实执行（外部工具适配器）

验证目标：`sast.semgrep` / `sast.trivy` 不再只靠固定 JSON 夹具，而是调用本机真实 CLI，并跑通 runner 的策略校验、证据链、审计与报告。

**环境与安装位置（C: 空间紧张，工具装在 D:）**

| 工具 | 版本 | 路径 | 安装方式 |
|---|---|---|---|
| Semgrep | 1.181.0 | `D:\dsh-tools\semgrep-venv\Scripts\semgrep.exe` | Python 3.11 venv + `pip install semgrep` |
| Trivy | 0.76.0 | `D:\dsh-tools\trivy\trivy.exe` | GitHub release `windows-64bit.zip` |
| Trivy 漏洞库 | schema 2（2026-10-20 更新） | `D:\dsh-tools\trivy-cache\db\trivy.db`（约 1.56 GB） | `trivy fs --download-db-only` |

两个工具目录已加入用户 `PATH`；`%LOCALAPPDATA%\trivy` 是指向 `D:\dsh-tools\trivy-cache` 的 junction，使适配器默认缓存路径也不占 C:。

**样本与规则（全部本地，不联网拉规则/库）**

- 示例项目：`fixtures/gate-b-sample/`（8 个已知漏洞 npm 依赖 + 4 个旧 Python 依赖 + eval/命令拼接/SQL 拼接/MD5/假凭据样本；假凭据仅为随机占位符）。
- 本地规则：`fixtures/gate-b-rules/armorbreak-local.yml`（5 条，`semgrep --validate` 通过）。
- 执行入口：`node scripts/verify-gate-b.mjs`（新增；分 capability 层与 runner 层，任一检查失败即非零退出）。

**真实执行结果（2026-10-20）**

| 检查 | 结果 |
|---|---|
| `semgrep --version` | 1.181.0 |
| `trivy --version` | Version: 0.76.0 |
| capability 层 Semgrep | 6 findings / 5 条规则（critical 2、high 4），全部 hypothesis，`toolVersion=1.181.0` |
| capability 层 Trivy | 67 findings（依赖 65 + 密钥 2；high 53、critical 14），`offlineDb=true`、`dbDownloadAllowed=false` |
| runner 层任务 | L0 目录任务 `COMPLETED`，2/2 步 DONE，步耗时 3.3s / 1.1s |
| 证据链 | `verified`（150 条记录；73 findings 落库） |
| 报告 | 已生成并归档为 `docs/acceptance/gate-b-report.md` |

**Gate B 暴露并修复的两个真实问题**

1. `lib/analyzers/external/adapters.js` 的子进程环境白名单缺少 `LOCALAPPDATA`/`APPDATA`：Trivy 在适配器内无法定位默认缓存目录，即使漏洞库已下载也报 `--skip-db-update cannot be specified on the first run`。修复：白名单补入这两个 Windows 缓存目录变量（仍不转发全量环境）。
2. `lib/core/health.js` 的版本探测统一使用 1.5s 超时，Semgrep（Python）冷启动约 2.4s，导致 `armorbreak_health` 误报版本错误。修复：新增独立 `versionTimeoutMs`（默认 5s），仅放宽版本探测，普通探活仍是 1.5s。

**产物**：`docs/acceptance/gate-b-summary.json`（版本/路径/计数/哈希/断言）、`gate-b-findings.json`（capability 层完整归一化 findings + 证据）、`gate-b-task.json`（runner 任务快照）、`gate-b-report.md`（报告）。

**边界与说明**

- Semgrep 会为本地 `--config` 规则加 config 命名空间前缀（随 cwd 相对路径变化），验收按规则 ID 后缀核对；不影响归一化与证据。
- `gate-b-report.md` 头部的“任务状态：REPORTING”是生成时点快照（finalize 在 REPORTING 阶段先生成报告再转 COMPLETED）；任务最终状态以 `gate-b-task.json` / `gate-b-summary.json` 的 `COMPLETED` 为准。
- Trivy secret scanner 对 AWS 官方文档示例值（`AKIAIOSFODNN7EXAMPLE`）有 allowlist，样本改用随机假值触发正例；`.env` 中仍保留示例值用于说明该行为。
- 本轮只覆盖 Windows 本机真实执行；Linux/macOS 真实安装仍未验证（CI 仅跑测试）。

## 3. 覆盖率

见 `docs/acceptance.md` 当前数值（v1.0.3 基线：行 85.60%）。v1.0.4 实测（`node --test --experimental-test-coverage`）：

| 范围 | 行覆盖 | 分支 | 函数 |
|---|---:|---:|---:|
| 全部文件 | **85.69%** | 62.75% | 85.76% |
| `lib/core/files.js`（新增） | 90.37% | 53.13% | 64.29% |
| `lib/core/scope.js` | 86.19% | 78.97% | 90.00% |
| `lib/core/runner.js` | 93.76% | 74.56% | 88.89% |

## 4. 升级/回滚

见 `docs/migration-v1.0.3-to-v1.1.0.md`。

## 5. 分支与发布

- 分支：`feature/armorbreak-v1.1.0-stage-b` → **已合并 main**（merge commit `8d3a8d5`，2026-10-20）；分支保留用于 B–E 后续迭代。
- 未推送 main、未创建 GitHub Release（任务书要求）；本地 main 领先 `origin/main`。
- Gate B 本轮新增/修改：`scripts/verify-gate-b.mjs`、`fixtures/gate-b-sample/`、`fixtures/gate-b-rules/armorbreak-local.yml`、`docs/acceptance/gate-b-{summary,findings,task}.json` + `gate-b-report.md`；修复 `lib/analyzers/external/adapters.js`（子进程环境白名单）与 `lib/core/health.js`（版本探测超时）。
- 合并后回归：main 上 `node --test` → 160 用例，159 通过、0 失败、1 跳过。
- 后续：B–E 阶段继续在分支/新分支迭代。
