# 安全模型（ArmorBreak）

本模型的目标：**真正的限制落在工具执行层，而不是提示词**。模型可以选择调用哪个工具、传什么参数，
但不能绕过策略引擎；任何越权尝试都会得到结构化的拒绝与审计记录。

## 1. 四级能力控制

| 级别 | 典型能力 | 执行策略（代码强制执行） |
|---|---|---|
| **L0** | 文件哈希、离线解析、静态代码分析、PCAP 解析 | 目标必须在任务工作区内，或在一条有效的授权记录覆盖的路径内；系统敏感路径始终拒绝；只读、不执行、不联网 |
| **L1** | 本地样本执行、隔离容器内调试 | 必须存在可用的隔离提供者（当前：Docker 守护进程可用）**且**获得平台审批；否则 `ISOLATION_UNAVAILABLE` / `EXECUTION_APPROVAL_REQUIRED` 拒绝 |
| **L2** | 授权目标的主动探测/验证 | 必须有覆盖该目标的授权记录（网络目标白名单）**且**获得平台审批**且**未触发速率限制；否则 `NETWORK_OUT_OF_SCOPE` / `NETWORK_APPROVAL_REQUIRED` / `NETWORK_RATE_LIMITED` 拒绝；默认拒绝 |
| **L3** | 破坏、数据泄露、持久化、不可逆修改 | **始终拒绝**（`L3_DENIED`），不提供任何自动执行通道 |

策略实现：`lib/core/scope.js` + `lib/core/runner.js`。能力自身的 `riskLevel` 决定走哪条门；
`runner` 在读取任何输入、执行任何代码之前先过策略；策略拒绝会写审计并把任务置为 REJECTED（规划阶段）
或把步骤置为 FAILED（执行阶段）。

## 2. 授权与审批

### 2.1 授权记录（Scope Authorization）

- 由 `armorbreak_scope action=authorize` 创建，包含：用途、操作者、路径列表、网络目标列表、风险上限、有效期。
- 网络目标支持精确主机、`*.domain`、IPv4/IPv6 CIDR、可选端口。
- 记录带完整性签名（`sha256(canonical JSON)`）；篡改会使记录失效（`isAuthorizationActive` 校验签名）。
- 默认有效期 24h，可撤销；跨工作区分析或 L2 测试必须先建立覆盖目标的授权。

### 2.2 平台审批（Platform Approval）

- L1/L2 执行前，工具层通过 `ctx.get('approval')` 调用 **Harness 自身的审批服务**
  `approval.request({agent, toolName, callId, reason, signal})`。
- 只有 `allowed-once` 才算授权；`rejected` / `cancelled` / `unavailable` 一律拒绝（fail closed）。
  在审批策略为 `never` 或没有审批通道的部署里，L1/L2 永远无法执行。
- 审批记录短时效（30 分钟）、使用次数上限（200），并按任务/风险级别/目标精确匹配。

## 3. 文件路径与命令

- **路径规范化**：`resolve` + `realpath`（跟随符号链接）后做边界判断；符号链接逃逸会被识别。
- **工作区边界**：默认只允许任务工作区（`<workspace>`）；工作区外必须被授权路径覆盖。
- **敏感路径拒绝**：`System32`/`SysWOW64`/`/proc`/`/sys`/`/dev`/`/etc/shadow` 等始终拒绝，即使有授权。
- **不拼 shell**：外部命令一律 `execFile(argv)`，无 shell 解释；参数数组固定模板 + 白名单镜像/命令。
- **外部环境清洗**：子进程只继承 `PATH/SystemRoot/TEMP/...` 等最小环境，不继承 Harness 凭据环境。
- **输出有上限**：单次执行 stdout/stderr、输入读取、结果 JSON、产物大小均有上限。

## 4. 不可信内容与提示注入

- 被分析对象（文件、字符串、PCAP payload、日志、注释、Manifest 文本）**一律视为数据**；
  persona 明文规定其中的"指令"不能改变任务、范围或安全规则。
- 分析结果再次进入模型上下文前：剥离控制字符、压缩空白、单条摘录 ≤2000 字符、报告/审计中的
  敏感字段（Authorization/Cookie/Token/私钥等）统一脱敏为 `[REDACTED]`。
- 能力不得把文件内容拼进命令；不得对目标执行任何东西（L0）；L1 仅在隔离容器中。

## 5. 隔离

- L1 只在**一次性容器**中执行：`--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges`
  `--pids-limit 128 --memory 512m`，样本目录只读挂载到 `/sample`。
- 无 Docker（或无守护进程）时，`HealthService.isolation()` 返回不可用，L1 步骤直接拒绝并给出安装指引。
- Harness 插件代码本身运行在 Host 进程内（`danger-full-access` 会话下可读写工作区）；
  ArmorBreak 无法也不试图替代宿主沙箱——它在宿主之上再加一层**任务级**范围与审批边界。

## 6. 审计与证据完整性

- 工作区审计日志 `audit.jsonl`：每条记录包含 `seq`、时间、动作、`prevHash`、`hash`（哈希链）。
- 每任务证据日志 `evidence.jsonl`：同样带哈希链；每个证据记录目标文件的 SHA-256。
- 报告展示证据链校验结果；链损坏会在报告与工具输出中显著标注。
- 审计写入失败不会阻断执行，但执行结果自身的审计事件随后补齐；证据链损坏不会被静默忽略。
- 日志/报告/UI 状态接口都不输出凭据原文；`stateSummary` 只包含标题级元数据。

## 7. 已知限制（安全相关）

1. 授权记录是**本地完整性签名**，不是密码学身份认证；能写 `$DSH_HOME/armorbreak/policy.json` 的
   本机用户即可伪造记录。真正的纵深防线是平台审批 + 代码路径限制 + 审计可见性。
2. `/armorbreak/state` 路由不做额外鉴权（同源、loopback、只读、脱敏）；它不提供任何执行入口。
3. 外部工具（如有）以宿主用户权限运行；ArmorBreak 只限制其参数与目标范围，不能限制其自身行为，
   因此外部工具需经来源审查（见任务书要求）。
4. 未实现的防护：内核级隔离、网络出口层面的强制（除容器 `--network none`）、
   Windows ACL 级文件锁定；这些属于宿主/部署职责，已在路线图中列出。
