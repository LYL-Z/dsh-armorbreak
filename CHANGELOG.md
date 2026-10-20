# CHANGELOG

## 1.1.1 — 2026-10-20

真实 GUI + 真实模型 E2E 发现的热修复：

- 修复状态卡渲染期 TDZ 崩溃（postAction 依赖 load 过早求值）——状态卡恢复渲染。
- 修复 external 分析器诊断告警：适配器移至 lib/analyzers/sast/external-adapters.js（由 sast manifest 注册），registry 恢复 41 capabilities / 8 domains / 0 diagnostics。
- 验证：真实桌面 GUI 中破甲模式会话调用 armorbreak_health 成功；178/178 测试。

## 1.1.0 — 2026-10-20

Research Workbench release（Stage A–D/D2，具体交付见 docs/releases/v1.1.0.md）：

- v1.0.4 安全维护：strict preset、授权 request/activate、网络探测固定 IP、容器 digest/非 root、状态路由 loopback。
- Stage B：Semgrep 1.181.0 / Trivy 0.76.0 真实适配器与 Gate B（6 + 67 findings，证据链 150 条）。
- Stage C：DAG 工作流、后台队列、取消/恢复、重启恢复。
- Stage D/D2：只读+写操作工作台（L0 新建/取消/重试/恢复）、证据中心、报告预览、工具探测；会话级工作区绑定（首次工具调用后生效）。
- 178 自动化测试；Windows/Ubuntu CI + Docker L1 job。
- 未验证：真实 DeepSeek 模型桌面 GUI E2E、浏览器视觉/交互、L1/L2 工作台写操作（刻意限制）、Ghidra/JADX/TShark/Syft。

## Unreleased — v1.1.0 Stage D2（分支 feature/armorbreak-v1.1.0-stage-d2）

### 工作台补全（Stage D）

- **写操作 API**：`POST /armorbreak/actions`，支持 `create / cancel / retry / resume`。仅 loopback、仅 POST、要求 `x-armorbreak-ui: 1` + `application/json`（同源本地 UI 边界），body ≤ 64 KiB；浏览器没有平台审批通道，因此只允许 L0 工作流/任务，L1/L2 一律拒绝并提示用对话工具。
- **任务详情 UI**：新建任务表单（工作流/目标路径/标题）、取消/重试/恢复按钮、证据加载、报告预览（纯文本渲染，HTML 不注入 DOM）。
- **证据中心**：`GET /armorbreak/evidence?taskId=&severity=&verification=` 返回有界证据元数据（标题/kind/at/≤300 字符摘录）、finding 行（含 ≤500 字符描述）、过滤计数、证据哈希链状态；上限 200 条并标记 truncated。
- **报告预览**：`GET /armorbreak/report?taskId=&format=markdown|html` 返回 ≤256 KiB 文本、sha256 与路径；不提供任意外部路径读取（只读任务已生成的报告）。
- **工具中心探测**：`GET /armorbreak/tools?probe=1` 复用 HealthService 做有界版本探测，UI 按钮触发并展示 found/version/path；未探测时仍标记“未探测”，不谎报已安装。
- 测试：ui-api 新增 3 个用例（写操作边界、创建→执行→证据→报告→取消、未知工作流），全套 **177/177 通过**。
- 未完成/未验证：真实浏览器视觉与交互未验证（无浏览器控制）；会话级工作区绑定仍为 MRU；工作台写操作仅 L0；无真实模型 GUI E2E。

## Unreleased — v1.1.0 Stage C/D/E（分支 feature/armorbreak-v1.1.0-stage-cde）

### Workflow engine (Stage C)

- 依赖图执行：新增 `lib/core/dag.js`；步骤可声明 `dependsOn`（缺省沿用上一版顺序链，向后兼容）、`failurePolicy`（fail-fast / continue-independent / skip-dependent）、`retryPolicy`（retry-transient，最多 5 次）、`timeoutMs`。独立步骤在 `concurrency` 内并发；依赖未完成/失败时不执行，依赖失败的步骤标记 SKIPPED。
- 后台任务队列：新增 `lib/core/taskQueue.js`。`start/status/wait/cancel/recover/resume`，进程内租约与并发上限（默认 2），取消会 abort runner 并等待 settle 后落 CANCELLED。
- 可靠取消与恢复：新增任务状态 `WAITING / PAUSED / INTERRUPTED / RECOVERABLE`；进程重启后，未在队列中的 EXECUTING/COLLECTING_EVIDENCE 任务被标记 INTERRUPTED，RUNNING 步骤回到 PENDING，无法恢复时显式失败。
- 工具层：`armorbreak_workflow` 新增 `run_async / resume / retry`，status 返回队列状态；`concurrency` 参数。
- 新增测试：`tests/workflow-dag.test.mjs`（5）、`tests/task-queue.test.mjs`（3）。

### Workbench / API (Stage D)

- 新增只读工作台路由：`/armorbreak/tasks`（列表/任务详情：步骤、finding 元数据、报告指针）、`/armorbreak/tools`（能力域、隔离状态；外部工具不谎报已安装）；全部 loopback-only、GET/HEAD、拒绝 workspace 枚举。
- 新增 `lib/core/presentation.js`：状态文案（L2 显示“无授权目标”而非 0；隔离显示 DaemonReady 且标注未自检）、任务/发现/工具投影。
- 浏览器状态卡升级为三页签只读工作台（概览/任务/工具，可查看任务步骤与 finding 摘要）；不提供新建/取消（写操作仍走对话工具）。
- 工作区绑定明确标注“最近使用工作区；会话级绑定未实现”。

### Verification / CI (Stage E)

- 新增 `tests/ui-api.test.mjs`（5）、`tests/e2e-tool-flow.test.mjs`（mock-model 工具链 E2E：health → start → run_async → status → evidence chain → report）。
- CI 新增 `live-docker` job：拉取 digest-pinned busybox 并运行 `scripts/verify-l1.mjs`（真实 daemon）。
- 全套测试 **174/174 通过**（原 160 + 14）。
- 未完成/未验证：真实模型 GUI E2E、完整工作台写操作与工具安装引导、session 级工作区绑定、Ghidra/JADX/TShark/Syft、macOS/Linux 真机桌面。

## Unreleased — v1.1.0 Stage B（已合并 main，`8d3a8d5`；分支 `feature/armorbreak-v1.1.0-stage-b` 保留）

- **外部工具适配器首批**：新增 `sast.semgrep`、`sast.trivy`（L0，目录目标）。JSON 归一化到统一 findings/evidence（severity/confidence/verification 分离、位置/规则/证据引用、默认 hypothesis、输出上限、畸形 JSON 拒绝、缺失工具返回安装指引；不自动下载规则/漏洞库）。
- **Gate B 真实运行通过**：本机安装 Semgrep 1.181.0（`D:\dsh-tools\semgrep-venv`）与 Trivy 0.76.0（`D:\dsh-tools\trivy`，漏洞库约 1.56 GB 在 D:），`node scripts/verify-gate-b.mjs` 真实扫描 `fixtures/gate-b-sample`：capability 层 6 + 67 findings，runner 层任务 COMPLETED、证据链 150 条 verified；产物 `docs/acceptance/gate-b-*`，详见 `docs/acceptance-v1.1.0.md` §2.2。
- **修复（Gate B 实测发现）**：外部工具子进程环境白名单补 `LOCALAPPDATA`/`APPDATA`（否则 Trivy 在适配器内无法定位本地漏洞库）；`HealthService` 新增独立 `versionTimeoutMs`（默认 5s，Semgrep Python 冷启动不再被 1.5s 探活超时误判）。
- **测试**：新增 `tests/external-adapters.test.mjs`（7 用例）；全套 **160 用例：159 通过 + 1 跳过**（“缺失工具”路径在 Semgrep 已安装时按设计跳过；安装前 160/160）；适配器行覆盖 99.41%。
- **L1 Docker 真机验证**：`scripts/verify-l1.mjs` 在 Docker 29.8.1 + busybox digest 上验证 exit=0、`uid=65534`、`/sample` 只读、容器无 eth（仅 lo）；证据/报告落盘，结果见 `docs/acceptance/l1-docker-verification.json`。
- 能力数 39 → **41**（8 域不变）；工具数仍为 9。
- **未完成**：Ghidra/JADX/TShark/Syft 未实现；Linux/macOS 真实安装未验证。Gate B 已在 Windows 本机通过。

## 1.0.4 — 2026-10-20

Stage A 安全维护（v1.1.0 Research Workbench 的第一阶段）。只修安全边界，不新增分析能力。

### Security

- **统一研究工具权限边界**：preset 取消挂载 `tool-fs`/`tool-fs-search`/`tool-pwsh`/`tool-bash`/`tool-web`/`tool-jobs`（它们绕过 L0–L3）；新增策略网关内的只读 `armorbreak_files`（list/read/stat/search，有界、无写、无执行）。
- **授权创建与模型分离**：`armorbreak_scope` 改为 `request`（pending，不生效）→ 平台审批 `allowed-once` → `activate`（记录 approvalSource/approvedBy/approvalId）；移除 `action=authorize`；无审批服务时 fail-closed。
- **网络探测**：`live.http_probe` 改为流式有界读取（超限立即断连）、策略期解析并 pinned IP、不跟随重定向、超时/AbortSignal 传导、敏感头脱敏、拒绝云元数据地址。
- **L1 容器**：镜像必须 digest-pinned + allowlist；`--pull never`、非 root、tmpfs、唯一名称、超时 `docker rm -f` 清理；命令 argv 上限。真实成功路径未验证（无 daemon）。
- **文件路径**：拒绝 UNC/设备/NUL 路径形式。
- **状态接口**：`/armorbreak/state` 仅 loopback、GET/HEAD、拒绝 `?workspace=`。

### Tests

- 新增 `tests/security-boundary.test.mjs`（7 用例）；全套 **153/153 通过**（v1.0.3 的 146 个全部保留）。
- 未验证：真实 Docker 成功路径、模型驱动 GUI E2E、真实公网 SSRF 测试（按任务书禁止）。

## 1.0.3 — 2026-10-20

扫描降噪：用户重跑源码目录审计后报告 27 条发现中 26 条为规则自匹配/测试夹具/文档示例噪声。

### Added

- `sast.scan` / `sast.secrets` / `sast.deps` / `sast.sbom` 新增可选参数 `excludePaths`
  （字符串数组，按路径子串、大小写不敏感匹配；如 `["tests/","lib/analyzers/sast/rules.js"]`）。
  仅影响文件枚举，不改变规则与其余文件覆盖；排除数量可在结果中核对。
- 测试：混合目录（规则文件 + 测试夹具 + 真实源码）验证被排除文件不再扫描、真实源码仍覆盖。
- 全套测试 **146/146 通过**（+1），行覆盖 85.60% / 分支 62.77%。

### Notes

- 向后兼容（纯新增可选参数）；`link:` 安装需重启 Harness 加载新模块代际。

## 1.0.2 — 2026-10-20

修复安装后真实会话中由用户实际路由执行暴露的结构性缺陷（目录型工作流、并发链、编码与加固）。

### Fixed

- **目录型工作流结构性不可用（用户复现）**：`WebCodeSecurityReview` / `DependencyAudit` 声明
  `targetKind: 'directory'`，但 `sast.scan/secrets/deps/sbom` 未声明 targetKind，规划器按 `file` 处理，
  运行时报 `TARGET_NOT_FILE` 且提示语自相矛盾。修复：
  1）四个 sast 能力声明 `targetKind: 'directory'`；
  2）`prepareTask` 在 **PLANNING 阶段**做 targetKind 兼容性校验，不匹配直接 `FAILED/TARGET_KIND_MISMATCH`，
     并列出可用的目录型能力；
  3）`TARGET_NOT_FILE` 错误改为动态列出已注册目录型能力 + 建议目录工作流；
  4）`env.readFile` 按 `docs/CONTRACT.md` 返回 **Buffer**（此前返回 `{buffer,truncated,size}`，导致 sast 读取报
     "first argument must be of type string or Buffer"）；
  5）新增目录工作流集成测试（真实多文件目录 → 4 步全 DONE、findings 覆盖多个文件、报告生成）。
- **并发追加可断链（用户复核发现）**：`audit.js` / `evidence.js` 的 read-tail → append 无序列化，并发工具调用
  会写出重复 `seq`/`prevHash`。修复：`util.js` 增加进程内按文件互斥队列，`AuditLog.append`、
  `EvidenceStore.addEvidence/addFinding/verifyFinding`、`TaskStore.save` 全部串行化；新增并发链完整性测试。
- **源码文件非合法 UTF-8（用户复核发现）**：`scope.js`/`tasks.js` 中 `—`/`→` 曾被文本往返破坏为 `E2 80 3F` /
  `E2 86 3F`。已修复为合法 UTF-8，并新增“全仓库文本文件 UTF-8 校验”测试防止复发。
- **目录读取未 realpath 校验（用户复核发现）**：`env.readFile` 只做词法 `isPathInside`，junction/符号链接可把
  读取重定向到根目录之外。修复：目录根与读取目标均取 realpath 后双向校验，`env.listFiles` 起点同样校验；
  新增 Windows junction 逃逸测试（保留器可跳过）。
- **端口作用域匹配缺口（用户复核发现）**：带端口的授权/审批可覆盖无端口目标。修复：模式声明端口时，目标端口
  未知一律不匹配；新增端到端授权/审批端口测试。
- **YAML 子集解析器加固（用户复核发现）**：flow 集合递归无深度上限；`__proto__`/`constructor`/`prototype`
  键可改变解析对象原型。修复：flow 深度上限 64、缩进节点深度上限 128、危险键显式拒绝并报可操作错误；新增测试。
- **状态卡信息误导（用户截图）**：隔离不可用时仍显示 `docker`；`0 个任务` 因默认工作区是进程 cwd。修复：
  `isolation` 仅在实际可用时显示提供者，否则显示“不可用”；`stateSummary` 默认使用**本进程最近使用的工作区**
  （工具调用过的工作区），状态卡标注“最近使用的工作区”。

### Added

- `scripts/clean-temp.mjs`：清理测试在 OS 临时目录留下的 `abm-*`/`dbg-*` 目录（本次清理 1454 个 / 10.6 MiB）。
- 测试：`core-concurrency`、`runner-directory`、`hardening` 三组共 13 个用例；全套 **145/145 通过**，
  `runner.js` 行覆盖 93.65%，`runtime.js` 100%。

### Notes

- 本次修复为源码级（bundle 为 `link:` 安装）；运行中的 Desktop 仍加载旧模块代际，**需完全退出并重开一次**生效。

## 1.0.1 — 2026-10-20

修复真实会话中发现的安装后缺陷（用户以破甲模式实测报告）。

### Fixed

- **`armorbreak_health` 调用失败（`value is not lossless JSON`）**：`runtime.stateSummary()` 曾返回
  `tools: registry.list()`，其中 capability 对象携带 `run`/`networkTarget` 函数；harness 审计通道
  只允许无损 JSON，导致工具调用被拒绝。修复：从状态快照中移除冗余的 `tools` 字段（`capabilities`
  投影已含同等信息），并在 `tools.js` 增加 `toLosslessJson()` 深度净化，确保任何工具都不会输出
  函数/`undefined`/BigInt/循环引用等非 JSON 值（纵深防御）。
- **默认工作区错误**：未显式传 `workspace` 时工具曾落到宿主进程 cwd（如 profile 目录）。修复：
  工具执行前通过 `ctx.get('workingDirectory').ensure(agent)` 解析**当前会话工作目录**，显式
  `workspace` 仍优先；无该服务时回退到进程工作区。

### Tests

- 新增 `tests/tools-lossless.test.mjs`（4 用例）：所有工具输出递归校验为无损 JSON、health 不再包含
  原始 capability 对象、默认工作区=会话目录、显式 workspace 覆盖。
- 全套 `node --test` → **132/132 通过**；`tools.js` 行覆盖提升到 86.71%。

## 1.0.0 — 2026-10-20

首个交付版本（目标运行时 DeepSeek Harness Desktop 0.2.1-rc.2，Cordis 4.0.x）。

### Added

- **Cordis Bundle** `dsh-armorbreak`：`cordis.patch.yml` 插入 Host 行 + `preset-armorbreak` 模式声明；
  不覆盖任何既有行，标准/创造模式不受影响。
- **Agent preset「破甲模式」**：专业 persona（授权边界、证据纪律、防提示注入、工作方法）、
  标准文件/Shell/技能/压缩工具、8 个 ArmorBreak 工具、7 个内置技能。
- **核心运行时**：能力注册表（契约校验 + 诊断）、执行器（L0/L1/L2/L3 策略门、平台审批、超时、取消、
  输入/输出上限）、范围策略（授权记录签名、路径 realpath 边界、网络白名单/CIDR/端口、速率限制）、
  任务状态机（14 状态 + 异常终态）、证据链存储、审计哈希链、健康探测、报告引擎。
- **离线分析能力**：二进制（识别/头与节/符号与导入导出/字符串/熵）、取证（哈希/元数据/时间线/IOC/
  规则匹配/文件类型）、Android（APK 结构/AXML Manifest/DEX/签名/发现汇总）、网络（PCAP/PCAPNG 总览/
  会话/DNS/TLS/HTTP/IOC/异常）、Web（HAR/OpenAPI/响应头/HTTP 报文）、SAST（危险调用/密钥/依赖/SBOM/补丁建议）、
  CTF（分类/解码/哈希识别/古典密码/flag 扫描）。
- **受控 live 能力**：`live.http_probe`（L2，授权+审批+限速）、`live.container_exec`（L1，Docker 隔离+审批）。
- **8 个工作流**：BinaryStaticAnalysis、AndroidAPKReview、WebCodeSecurityReview、PCAPInvestigation、
  DependencyAudit、CTFArtifactAnalysis、ForensicFileReview、SecurityReportGeneration（+ WebAPIReview）。
- **报告**：Markdown / HTML / JSON / SARIF 2.1.0 / PDF（LibreOffice 转换），含发现（验证状态、CWE、CVSS 依据）、
  证据附录（目标 SHA-256）、授权/审批记录、状态轨迹、审计摘要、复现条件与限制。
- **Web 状态卡**：`dsh.client` 浏览器插件，注册到 `conversation.composer.dock`，读取只读脱敏路由
  `GET /armorbreak/state`，展示能力数量、隔离状态、策略与最近任务。
- **测试**：`node:test` 套件覆盖策略/运行时/工具接线 + 各分析域（见 `docs/acceptance.md` 实际结果）。
- **文档**：环境与架构审计、架构设计、安全模型、安装/卸载、使用指南、验收报告、兼容性矩阵、
  已知问题、路线图、适配器契约、文件变更清单。

### Verified on this machine

- **Desktop 0.2.1-rc.2 正式安装**：`plugin_manager install_bundle` → `application: applied`、`warnings: []`；
  live Loader 出现 `armorbreak` 与 `preset-armorbreak` 两行；`GET http://127.0.0.1:53824/armorbreak/state` → 200
  （39 capabilities / 8 domains / 0 diagnostics；Host 半经 HMR 激活，无需重启）。
- 测试 profile（CLI `web`，同一运行时）安装、启动、状态路由 200、浏览器模块编入启动图；
- headless 测试 profile 中 preset 激活成功（仅 Host 状态路由因无 `webServer` 保持 pending）；
- 安装/卸载/重装生命周期：卸载后 4 个 shipped preset 完整保留；
- 自动化测试：`node --test` → **128/128 通过**；核心模块行覆盖 ≥80%（见 acceptance.md）。
