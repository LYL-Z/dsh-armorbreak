# 验收报告 — v1.1.0 Stage A（交付为 v1.0.4）

- 基线：v1.0.3（`97d0628`），146 测试
- 本次：Stage A 安全维护，**153 测试通过**
- 目标版本 v1.1.0 的 B–E 阶段未实现：外部工具适配器、DAG/异步任务、研究工作台 UI

## 1. 交付物状态

| 任务书章节 | 状态 | 证据 |
|---|---|---|
| P0 1.1 通用工具权限绕行 | ✅ 已修复 | preset 移除 fs/shell/web/jobs；新增策略内 `armorbreak_files`；`tests/security-boundary.test.mjs` |
| P0 1.2 授权与模型分离 | ✅ 已修复 | `request` → 平台审批 → `activate`；审批来源写入记录；旧 `authorize` 移除 |
| P0 1.3 网络探测边界 | ✅ 主要修复 | 流式有界读取、pinned IP、不跟随重定向、超时/Abort、脱敏、元数据地址拒绝；DNS 解析在策略期完成 |
| P0 1.4 L1 容器执行 | ⚠️ 部分 | 镜像 digest/allowlist、非 root、--pull never、唯一名称、超时清理；**成功路径未验证（无 daemon）** |
| P0 1.5 文件/工作区安全 | ✅ 部分 | UNC/设备/NUL 拒绝、realpath、敏感路径、目录读取有界；**TOCTOU 未彻底消除** |
| P0 1.6 状态接口 | ✅ 已修复 | loopback-only、GET/HEAD、拒绝 workspace 枚举 |
| P1 外部工具适配器 | ❌ 未实现 | 仅设计文档 `docs/adapter-contract-v2.md` |
| P1 任务系统 v2 | ❌ 未实现 | 仅设计文档 `docs/workflow-engine-v2.md` |
| P1 Windows 隔离管理 | ❌ 未实现 | 设计 `docs/isolation-providers.md`；L1 仍不可用 |
| P1 证据/任务数据体系 | ❌ 未实现 | 未做 schemaVersion/迁移；`armorbreak_files` 已记录 hashScope |
| P1 研究工作台 UI | ❌ 未实现 | 仍为状态卡 |
| P2 分析深度/智能流程 | ❌ 未实现 | 任务书允许后续版本 |

## 2. 实际执行的测试

```text
node --test
ℹ tests 153
ℹ pass 153
ℹ fail 0
```

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

- 分支：`feature/armorbreak-v1.1.0`
- 未推送 main、未创建 GitHub Release（任务书要求）。
- 建议：用户审阅本分支后，单独合并/发布 v1.0.4；B–E 阶段继续在该分支迭代。
