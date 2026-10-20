# CHANGELOG

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
