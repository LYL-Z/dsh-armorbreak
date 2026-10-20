# 验收报告 —— ArmorBreak「破甲模式」v1.0.3

- 验收时间：2026-10-20（America/Los_Angeles）
- 目标运行时：DeepSeek Harness Desktop **0.2.1-rc.2**（Cordis 4.0.x，Node 24.21 / 系统 Node v24.16）
- 交付目录：`D:\dsh-ABM\armorbreak`
- 结论：**可以交付**。模式已在真实桌面安装并激活；离线分析能力、策略强制、证据/报告、测试与文档均完成。
  未完成的验证项在 §7 明确列出，不伪造。

---

## 1. 交付物核对（任务书 §13）

| # | 交付物 | 位置 | 状态 |
|---|---|---|---|
| 1 | 完整项目源码 | `armorbreak/`（见 [file-changes.md](file-changes.md)） | ✅ |
| 2 | 可安装 Cordis Bundle | `package.json`（`dsh.bundle.patch`）+ `cordis.patch.yml` | ✅ 已安装到 desktop profile |
| 3 | Agent preset 配置 | `cordis.patch.yml` → `preset-armorbreak` | ✅ 已挂载（live Loader 可见） |
| 4 | Skills 文件 | `skills/*.md` + `skills.js`（7 个技能，运行时注册） | ✅ |
| 5 | 工具适配器 | `lib/analyzers/{binary,forensics,android,network,web,sast,ctf,live}/` 共 **39 个能力** | ✅ |
| 6 | 工作流实现 | `lib/core/workflows.js`（9 个模板）+ `lib/core/runner.js` | ✅ |
| 7 | 安全策略实现 | `lib/core/scope.js` + `runner.js`（L0-L3、审批、路径、网络、限速） | ✅ |
| 8 | 测试代码及实际结果 | `tests/`（16 个文件，**146 用例全部通过**） | ✅ 见 §3 |
| 9 | 安装/卸载说明 | [installation.md](installation.md) | ✅ 含实际生命周期验证 |
| 10 | 使用文档 | [usage.md](usage.md) + [README](../README.md) | ✅ |
| 11 | 架构文档 | [architecture.md](architecture.md) | ✅ |
| 12 | 安全模型文档 | [security-model.md](security-model.md) | ✅ |
| 13 | 已知问题清单 | [known-issues.md](known-issues.md) | ✅ |
| 14 | 兼容性矩阵 | [compatibility-matrix.md](compatibility-matrix.md) | ✅ |
| 15 | 后续扩展路线图 | [roadmap.md](roadmap.md) | ✅ |
| 16 | 文件变更清单 | [file-changes.md](file-changes.md)（脚本生成） | ✅ |

## 2. 真实安装与运行验证（本机实测）

### 2.1 Desktop profile 安装（正式交付路径）

`plugin_manager action=install_bundle target="D:\\dsh-ABM\\armorbreak"` 返回：

```
application: applied, enabled: true, bundle: dsh-armorbreak, version: 1.0.0, warnings: []
```

安装后 profile `package.json` 同时出现依赖与 bundle 选择：

```
"dependencies": { "dsh-armorbreak": "link:D:/dsh-ABM/armorbreak", ... }
"dsh.profile.bundles": [ ..., "dsh-armorbreak" ]
```

`plugin_manager list_bundles` 中该 bundle 的两行：

| rowId | moduleName | entryId |
|---|---|---|
| `armorbreak` | `dsh-armorbreak` | `include:armorbreak` |
| `preset-armorbreak` | `@deepseek-ai/dsh-agent-preset` | `include:preset-armorbreak` |

`cordis_inspect_query`（Host `Config.listConfigs`, name=`@deepseek-ai/dsh-agent-preset`）显示 5 条 preset 行，
其中包括 `include:preset-armorbreak`，与 shipped 的 standard/ptc/minimal/cordis 并列 —— 说明声明已被 live Loader 接受。

**运行中的桌面应用已激活 Host 半**（HMR，无需重启即生效）：

```
GET http://127.0.0.1:53824/armorbreak/state  →  200
> 注：v1.0.1 修复后状态快照版本为 `"1.0.1"`；desktop profile 的安装元数据在 `install_bundle` 时记录为 1.0.0，
> 重装（remove_bundle → install_bundle）后同步，不影响已链接源码的运行。
{ version: "1.0.1", registry: { capabilities: 39, domains: [android,binary,ctf,forensics,live,network,sast,web], diagnostics: [] }, isolation: { available: false }, ... }
```

> 未验证（诚实声明）：浏览器中状态卡的视觉效果、以及在桌面 GUI 里新建会话选择「破甲模式」后由模型实际发起工具调用。
> 该动作需要一个新的 UI 会话且有模型凭据；本次会话无法从 CLI 取得桌面账号的模型凭据（见 §7）。

### 2.2 独立测试 profile（同 0.2.1-rc.2 运行时）

> 说明：`abmtest` / `abmheadless` 是验证用临时 profile，验证完成后已删除，避免污染用户环境；
> 可用 [installation.md](installation.md) 中的命令一键重建。

- 用官方模板创建 `abmtest` web profile，`dsh plugin add link:` 安装后自动加入 bundle 选择；
- `dsh --profile abmtest --port 3099 --no-open` 启动成功；
- `GET /armorbreak/state` → `200`，`version=1.0.1`（修复后重新验证；修复前为 1.0.0），**39 capabilities / 8 domains / 0 diagnostics**；
- 页面启动图包含 `dsh-armorbreak/client.js`（`window.__DSH_BOOT__` 的插件 bundle 列表）；
- 启动输出只有 URL 行，无插件激活警告。

### 2.3 headless profile 的 preset 激活验证

在 `abmheadless` profile（同运行时）用 overlay 挂载 `agent-preset-registry` 后启动：

- 仅 1 个 pending 行：`armorbreak (dsh-armorbreak): pending (waiting for service: webServer)` —— 无 Web 端时的预期行为；
- **preset-armorbreak 无激活失败警告**：persona、工具、技能、压缩组全部激活成功；
- 运行止于预期中的 `MISSING_CREDENTIAL`（CLI 无桌面账号模型凭据），不是插件错误。

### 2.4 安装/卸载/恢复验证（测试 profile）

| 步骤 | 结果 |
|---|---|
| 安装前 dump | 4 个 shipped preset + 本 bundle 两行 |
| `dsh plugin remove` + 从 bundles 移除 | dump 中 **无** armorbreak 行；standard/ptc/minimal/cordis **仍在**（未破坏既有模式） |
| 重新安装 | 依赖与 bundle 自动恢复，dump 中两行再次出现 |

## 3. 自动化测试（实际运行结果）

命令（在 `D:\dsh-ABM\armorbreak` 执行）：

```
node --test
```

| 指标 | 数值 |
|---|---|
| 测试文件 | 16 |
| 用例总数 | **146** |
| 通过 | **146** |
| 失败 | **0** |
| 跳过 | 0 |
| 总耗时 | ≈ 4.1 s |

分域用例：binary 16、forensics 12、android 18、network 15、web 11、sast 11、ctf 10、
core-policy 9、core-runtime 10、tools-integration 8、tools-lossless 4、acceptance 5、runner-gates 4、
core-concurrency 3、runner-directory 5、hardening 5（合计 146）。

关键测试覆盖内容：

- **策略**：授权记录签名/过期/撤销、工作区边界、敏感路径拒绝、CIDR/通配符/端口匹配、L2 无授权/无审批/审批不匹配/任务不匹配/限速、L1 隔离缺失/无审批/审批通过、L3 始终拒绝、`recordApproval` 拒绝非 grant。
- **运行时**：任务状态机合法/非法迁移、取消、超时、能力缺失、部分成功保留证据、证据链篡改检测、审计链校验、报告 5 种格式、状态快照无敏感字段。
- **工具接线**：8 个工具 schema 校验、health/capabilities/task/scope/evidence/report 实际执行、真实 `BinaryStaticAnalysis` 全工作流（7 步）跑通并生成报告（notepad.exe，证据 ≥7 条，报告含 SHA-256 与 evidence id）、取消/部分成功/审计脱敏。

### 覆盖率（`node --test --experimental-test-coverage`）

| 范围 | 行覆盖 | 分支 | 函数 |
|---|---:|---:|---:|
| 全部文件 | **85.60%** | 62.77% | 86.16% |
| `lib/core/` 核心模块 | 平均 **92.5%**（最低 health 80.21%） | — | — |
| runner.js | 93.65% | 74.22% | 88.89% |
| runtime.js | 100% | 84.62% | 100% |
| tools.js | 86.71% | 55.73% | 63.64% |
| scope.js | 91.72% | 80.52% | 93.48% |
| tasks.js | 99.33% | 80.77% | 90.48% |
| audit.js | 96.15% | 68.00% | 100% |

> 任务书建议“核心模块 ≥80%”——**全部核心模块行覆盖均 ≥80%，已满足**。
> “关键权限判断分支 100%”未用工具单独计量：主要权限分支（L0 允许/越界/敏感路径、L1 隔离缺失/审批拒绝/审批通过、
> L2 无授权/无审批/不匹配/限速、L3 拒绝）均有直接用例；整体分支覆盖 61.91%，剩余分支主要是错误处理与探测辅助路径。
> 不把 61.91% 描述为 100%。
> （v1.0.3 后整体分支覆盖为 **62.77%**，核心模块平均行覆盖 **92.5%**；见上表。）

### 真实数据验证（非伪造）

- `C:\Windows\System32\notepad.exe`（360,448 字节，SHA-256 `468FFE12…4577E`）复制到工作区后：
  7 步 BinaryStaticAnalysis 全部 DONE，生成 Markdown 报告；
- 队友交叉验证（记录在各自报告中）：真实 Windows ZIP、真实 JPEG、真实 PCAP 结构解析；
  792 次畸形输入 fuzz 无崩溃；
- Android/网络/Web/SAST/CTF 测试均用**程序化构造**的 ZIP/AXML/DEX/证书/签名块/pcap/pcapng/TLS/HAR/OpenAPI 样本，
  不依赖外部二进制 fixture。

## 4. 任务书 §12 验收标准逐条对照

| # | 标准 | 状态 | 证据 |
|---|---|---|---|
| 1 | 能注册并选择破甲模式 | ✅ 注册已实测；UI 选择待用户新会话确认 | §2.1 preset 行 + §2.3 激活 |
| 2 | 与现有 Agent 共存 | ✅ | 只做 insert，不覆盖既有行；卸载后 4 个 shipped preset 完整（§2.4） |
| 3 | 插件可安装/启用/禁用/卸载 | ✅ 安装与卸载实测；启用/禁用由 plugin_manager 同路径支持 | §2.1/§2.4 |
| 4 | 每个声明为可用的工具都有实际执行实现 | ✅ | 8/8 工具执行测试；39/39 能力可加载；BinaryStaticAnalysis 全链路 |
| 5 | 工具缺失时明确提示 | ✅ | `armorbreak_health`/`armorbreak_capabilities` 标注外部工具 found/install/alternative；未知能力/缺能力均可操作报错 |
| 6 | 静态分析不自动执行未知样本 | ✅ | L0 能力不执行；L1 仅容器+审批；拒绝分支测试 |
| 7 | 未授权网络操作被阻止 | ✅ | L2 策略测试 + 默认拒绝；`live.http_probe` 仅在授权+审批后可执行 |
| 8 | 工作流失败后保留已有证据 | ✅ | partial-success 测试：成功步骤证据保留、报告仍生成 |
| 9 | 工具结果可追溯至原始输出 | ✅ | 每任务 evidence.jsonl（哈希链）+ target SHA-256 + 报告引用 evidence id |
| 10 | 报告中的发现有对应证据 | ✅ | 报告生成器强制 findings→evidenceIds；测试断言报告含 ev_/SHA-256 |
| 11 | 任务支持超时和取消 | ✅ | TIMEOUT 用例 + AbortSignal 取消用例（步骤/任务 CANCELLED） |
| 12 | 运行日志不泄露敏感凭据 | ✅ | 审计/证据脱敏测试（token/API key 原文不出现）；报告脱敏 |
| 13 | 不影响标准/创造模式 | ✅ | 未覆盖任何既有行；§2.4 卸载后 shipped preset 完整 |
| 14 | 所有关键功能均有自动化测试 | ✅ | 146 用例，覆盖策略/运行时/工具/8 个分析域 |
| 15 | 不存在已知权限绕过路径 | ✅（在本模型范围内） | 已修复审计出的 2 个真实 bug（CIDR 匹配、授权签名校验）；拒绝分支全覆盖；L3 无通道；剩余限制见 known-issues |
| 16 | 完整安装/使用/卸载/排障文档 | ✅ | docs/ 全部文档 |

## 5. 审计中发现并修复的真实缺陷（诚实记录）

1. **CIDR 目标解析错误**：`parseNetworkTarget` 把 `10.20.0.0/16` 的 `/16` 当路径截断，导致 L2 授权永远不匹配；
   已修复并有测试（`core-policy` CIDR 用例）。
2. **授权记录签名覆盖不一致**：签名时未包含 `id`，校验时包含，导致所有授权记录“已过期”；
   已修复（签名覆盖完整记录）并有 reload 校验测试。
3. **取消语义**：能力在收到 abort 后正常返回时曾把步骤记为 DONE；已改为按取消处理（CANCELLED），有测试。
4. **证据链校验字段**：`prevHash` 参与/不参与哈希的字段不一致导致链校验恒失败；已修复并加篡改检测测试。
5. **`node --test tests` 在 Node 24/Windows 下把目录当模块**：`package.json` 的 test 脚本改为 `node --test` 自动发现。
6. **（v1.0.1，用户在安装后的真实会话中报告）`armorbreak_health` 返回 `value is not lossless JSON`**：
   根因是 `runtime.stateSummary()` 的 `tools: registry.list()` 携带 capability 的 `run` / `networkTarget`
   函数值，而 harness 审计通道只放行无损 JSON。修复：状态快照移除冗余 `tools` 字段；`tools.js` 增加
   `toLosslessJson()` 深度净化（函数/`undefined`/BigInt/循环引用一律不进入工具输出）。
   回归测试：`tests/tools-lossless.test.mjs`（4 用例）递归校验所有工具输出为无损 JSON。
7. **（v1.0.1）默认工作区曾回退到宿主进程 cwd**：用户在真实会话中观察到任务落在 profile 目录。
   修复：工具执行前用 `ctx.get('workingDirectory').ensure(agent)` 解析当前会话工作目录；显式 `workspace` 仍优先，
   无该服务时回退进程工作区。回归测试覆盖两条路径。
8. **（v1.0.2，用户实际执行路由后报告）目录型工作流结构性不可用**：`WebCodeSecurityReview` 目标为目录，但
   sast 四能力未声明 `targetKind`，规划/执行按 file 处理 → 4 步全部 `TARGET_NOT_FILE`，且错误提示自相矛盾。
   修复：sast 能力声明 `targetKind:'directory'`；规划阶段新增 target-kind 兼容性校验（`TARGET_KIND_MISMATCH`，
   列出可用目录能力）；`env.readFile` 按契约返回 Buffer；新增目录工作流集成测试（真实多文件目录 4/4 步 DONE）。
9. **（v1.0.2）并发审计/证据追加可断链**：read-tail→append 无序列化。修复：按文件互斥队列；
   `audit`/`evidence`/`findings`/`task.json` 写入串行化；新增并发链完整性测试。
10. **（v1.0.2）`scope.js`/`tasks.js` 非法 UTF-8**：文本往返损坏 `—`/`→`。已修复，并新增全仓库 UTF-8 校验测试。
11. **（v1.0.2）目录读取未 realpath 校验**：junction/符号链接可越界读取。修复：双向 realpath 校验 + junction 逃逸测试。
12. **（v1.0.2）端口作用域匹配缺口**：带端口授权可覆盖无端口目标。修复并加端到端测试。
13. **（v1.0.2）YAML 解析器深度/原型键**：flow 递归无上限、危险键可改原型。修复：深度上限 + 危险键拒绝 + 测试。
14. **（v1.0.2）状态卡信息误导**：隔离不可用显示 docker、任务数 0（工作区默认 cwd）。修复：隔离标签与
    “最近使用的工作区”（MRU）状态快照。
15. **（v1.0.3）扫描噪声无配置出口**：真实会话重跑源码目录审计后，27 条发现中 26 条为规则自匹配/测试夹具/文档示例。
    新增可选的 `excludePaths`（路径子串、大小写不敏感）到 `sast.scan/secrets/deps/sbom`，用于排除已知噪声文件；
    排除只影响枚举，不降低其他文件覆盖；有测试覆盖（含规则文件/测试夹具/真实源码的混合目录）。

> **安装后的代码更新说明**：v1.0.3 修复已落在 `link:` 的 bundle 源码中，但**运行中的 Harness 进程已加载
> 旧模块代际**；需要完全退出并重开 Desktop（或新开会话宿主进程）后生效。v1.0.3 仅新增可选参数，向后兼容。

## 6. 未验证 / 未实现（与 known-issues 一致）

- 模型驱动的桌面 GUI 端到端会话（需要用户在 UI 新建会话并选择破甲模式；CLI 无桌面账号凭据）。
- 状态卡在浏览器中的视觉呈现（无浏览器控制；只验证了路由 200、boot 图包含模块）。
- L1 容器实际执行路径（本机未运行 Docker）；仅验证拒绝分支 + 代码路径 + 注入隔离提供者后的 Logic 测试。
- L2 真实对外发包（无授权实验室目标）；仅验证策略与实现。
- 外部工具：Semgrep/Trivy 已在 v1.1.0 Gate B 真实接入并验证（见 `docs/acceptance-v1.1.0.md` §2.2）；Ghidra/JADX/TShark 输出仍未接入报告（仅探测与指引）。
- macOS/Linux 真机未实测。

## 7. 复现方式

```powershell
cd D:\dsh-ABM\armorbreak
node --test                                   # 146/146
node --test --experimental-test-coverage      # 覆盖率报告
node scripts/file-changes.mjs                 # 重新生成文件清单
node scripts/clean-temp.mjs                   # 清理测试在 OS 临时目录留下的 abm-*/dbg-* 目录
```

运行时验收：

```powershell
plugin_manager action=list_bundles            # 应看到 dsh-armorbreak 两行
curl http://127.0.0.1:53824/armorbreak/state  # 运行中桌面应用的只读状态
```
