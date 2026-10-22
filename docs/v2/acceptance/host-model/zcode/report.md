# ArmorBreak 安全研究报告 — MCP 硬编码凭据与密钥检测

- 报告 ID：`task_mvjo2nqy_726bd805`
- 生成时间：2026-10-22T14:59:15.210Z
- 任务状态：**REPORTING**
- 工作区：`D:\dsh-ABM\armorbreak`
- 目标：`D:\dsh-ABM\armorbreak`
- 操作者：zcode-host
- 证据链：校验通过，4 条记录

## 1. 摘要

共 2 条发现：critical 1 · high 1 · medium 0 · low 0 · info 0。留档证据 4 条。

| # | 严重程度 | 标题 | 验证状态 | CWE | 位置 |
|---|---|---|---|---|---|
| 1 | critical | [secret:private-key-block] 私钥内容 | observed | CWE-321 | D:\dsh-ABM\armorbreak\lib\analyzers\sast\secrets.js:209 |
| 2 | high | [secret:aws-access-key] AWS Access Key ID | observed | CWE-798 | D:\dsh-ABM\armorbreak\scripts\v2\core-benchmark.mjs:100 |

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-22T14:59:14.747Z) → SCOPE_VALIDATION(2026-10-22T14:59:14.759Z) → ENVIRONMENT_CHECK(2026-10-22T14:59:14.767Z) → PLANNING(2026-10-22T14:59:14.776Z) → EXECUTING(2026-10-22T14:59:14.783Z) → VERIFYING(2026-10-22T14:59:15.180Z) → REPORTING(2026-10-22T14:59:15.196Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| analyze | sast.secrets | DONE | 332 ms | 凭据扫描：读取 282 个文件，发现 2 个唯一疑似凭据（候选出现 2 次，跳过二进制 0 个文件）：critical 1 / high 1 / medium 0 / low 0。 类型：aws-access-key、private-key-block。 所有值已脱敏；若为真实凭据请立即轮换。 |

## 4. 发现

### 4.1 [secret:private-key-block] 私钥内容

- 编号：`fnd_mvjo2o23_80b5a937`
- 严重程度：**critical**（评分依据：严重程度映射 9.5）
- 验证状态：**observed**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-321 — https://cwe.mitre.org/data/definitions/321.html
- 检测方法：regex-entropy-secret-scan
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\secrets.js:209`

**说明**：在源码中观察到符合 “私钥内容” 形态的凭据字符串（已脱敏显示为 -----BEGIN PRIVATE KEY----- [内容已省略]）。 可能是真实凭据，也可能是测试数据/占位符；请人工确认有效性。若为真实凭据，任何读过仓库的人都应视为已泄露。

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：立即在对应平台轮换/吊销该凭据，从 git 历史中清除（filter-repo/BFG），改用环境变量或密钥管理服务（Vault/KMS/Secrets Manager），并启用 secret scanning 防止再次提交。

**证据**：`ev_mvjo2o1y_770980b2`, `ev_mvjo2o1h_3b961c52`

### 4.2 [secret:aws-access-key] AWS Access Key ID

- 编号：`fnd_mvjo2o2h_8d50fb4b`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**observed**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-798 — https://cwe.mitre.org/data/definitions/798.html
- 检测方法：regex-entropy-secret-scan
- 定位：`D:\dsh-ABM\armorbreak\scripts\v2\core-benchmark.mjs:100`

**说明**：在源码中观察到符合 “AWS Access Key ID” 形态的凭据字符串（已脱敏显示为 AKIA***）。 可能是真实凭据，也可能是测试数据/占位符；请人工确认有效性。若为真实凭据，任何读过仓库的人都应视为已泄露。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：立即在对应平台轮换/吊销该凭据，从 git 历史中清除（filter-repo/BFG），改用环境变量或密钥管理服务（Vault/KMS/Secrets Manager），并启用 secret scanning 防止再次提交。

**证据**：`ev_mvjo2o2a_c5562f7a`, `ev_mvjo2o1h_3b961c52`

## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvjo2o1h_3b961c52` | execution | sast.secrets | - | 凭据扫描：读取 282 个文件，发现 2 个唯一疑似凭据（候选出现 2 次，跳过二进制 0 个文件）：critical 1 / high 1 / medium 0 / low 0。 类型：aws-access-key、private-key-block。 所有值已脱敏；若为真实凭据请立即轮换。 |
| 2 | `ev_mvjo2o1o_32a992af` | secret-scan | sast.secrets | - | files=282 skippedBinary=0 uniqueSecrets=2 candidateOccurrences=2 byType={"aws-access-key":1,"private-key-block":1} |
| 3 | `ev_mvjo2o1y_770980b2` | finding-evidence | sast.secrets | - |     return matchText.replace(/-----[A-Z ]*PRIVATE KEY-----/g, '-----BEGIN PRIVATE KEY----- [内容已省略] [内容已省略]'); |
| 4 | `ev_mvjo2o2a_c5562f7a` | finding-evidence | sast.secrets | - |   'strings.bin': Buffer.from('MZ\x90\x00ArmorBreakCoreBench http://bench.example.test/flag AKIA***\n', 'latin1'), |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 1068 | 2026-10-22T14:59:14.753Z | task.create | {"seq":1068,"at":"2026-10-22T14:59:14.753Z","prevHash":"91dd37aced9a6240594a264fd304de7ade55dda08236c973aeeac1a41fdd62c9","action":"task.create","taskId":"task_mvjo2nqy_726bd805","title":"MCP 硬编码凭据与密钥检测","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak","hash":"494fe1b39ffd649ec4cc4fde5d362a13719865a16a57b3a8f036130719983017"} |
| 1069 | 2026-10-22T14:59:14.764Z | task.transition | {"seq":1069,"at":"2026-10-22T14:59:14.764Z","prevHash":"494fe1b39ffd649ec4cc4fde5d362a13719865a16a57b3a8f036130719983017","action":"task.transition","taskId":"task_mvjo2nqy_726bd805","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"1c51859471296270675190a49988804b1a10ada447f58389074e574035317a83"} |
| 1070 | 2026-10-22T14:59:14.774Z | task.transition | {"seq":1070,"at":"2026-10-22T14:59:14.774Z","prevHash":"1c51859471296270675190a49988804b1a10ada447f58389074e574035317a83","action":"task.transition","taskId":"task_mvjo2nqy_726bd805","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"ba7c2ff88bccde9f9fefc727bb6e5d08a6295dbc9d20974609256721f8971bec"} |
| 1071 | 2026-10-22T14:59:14.781Z | task.transition | {"seq":1071,"at":"2026-10-22T14:59:14.781Z","prevHash":"ba7c2ff88bccde9f9fefc727bb6e5d08a6295dbc9d20974609256721f8971bec","action":"task.transition","taskId":"task_mvjo2nqy_726bd805","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"9a40eb8a49599f57b4048e6357b65c74d7aa61489b2fe1ef70bbd0569667d29d"} |
| 1072 | 2026-10-22T14:59:14.788Z | task.transition | {"seq":1072,"at":"2026-10-22T14:59:14.788Z","prevHash":"9a40eb8a49599f57b4048e6357b65c74d7aa61489b2fe1ef70bbd0569667d29d","action":"task.transition","taskId":"task_mvjo2nqy_726bd805","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"a4e0b032282364b9b27f9b6f7f4d09458857533f29d3dde4c2a9351634e9caca"} |
| 1073 | 2026-10-22T14:59:14.794Z | capability.run.start | {"seq":1073,"at":"2026-10-22T14:59:14.794Z","prevHash":"a4e0b032282364b9b27f9b6f7f4d09458857533f29d3dde4c2a9351634e9caca","action":"capability.run.start","taskId":"task_mvjo2nqy_726bd805","stepId":"analyze","capability":"sast.secrets","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak","options":{"minEntropy":3,"maxFiles":600,"excludePaths":["fixtures/","tests/","bench |
| 1074 | 2026-10-22T14:59:15.129Z | evidence.add | {"seq":1074,"at":"2026-10-22T14:59:15.129Z","prevHash":"18363fca49fcc39c6bda31169be999ed3b38fc5f8200b835c9ef043e746a29dc","action":"evidence.add","taskId":"task_mvjo2nqy_726bd805","evidenceId":"ev_mvjo2o1h_3b961c52","title":"sast.secrets execution","target":"D:\\dsh-ABM\\armorbreak","hash":"8b5e77f7c687a406c1802b4ce91103723f01173e8aec77d1703305c605e713b8"} |
| 1075 | 2026-10-22T14:59:15.136Z | evidence.add | {"seq":1075,"at":"2026-10-22T14:59:15.136Z","prevHash":"8b5e77f7c687a406c1802b4ce91103723f01173e8aec77d1703305c605e713b8","action":"evidence.add","taskId":"task_mvjo2nqy_726bd805","evidenceId":"ev_mvjo2o1o_32a992af","title":"凭据扫描统计（值已脱敏）","target":"D:\\dsh-ABM\\armorbreak","hash":"2071a6cfba0687438b5d9853ed9d5d79c31f036d68dbd393dc6742308e5f2a78"} |
| 1076 | 2026-10-22T14:59:15.145Z | evidence.add | {"seq":1076,"at":"2026-10-22T14:59:15.145Z","prevHash":"2071a6cfba0687438b5d9853ed9d5d79c31f036d68dbd393dc6742308e5f2a78","action":"evidence.add","taskId":"task_mvjo2nqy_726bd805","evidenceId":"ev_mvjo2o1y_770980b2","title":"secrets.js:209","target":"D:\\dsh-ABM\\armorbreak","hash":"cb8ac7c171374455a46ac4016c8cfac8e2d4839a5bf6b07202521567fa0a81ff"} |
| 1077 | 2026-10-22T14:59:15.151Z | finding.record | {"seq":1077,"at":"2026-10-22T14:59:15.151Z","prevHash":"cb8ac7c171374455a46ac4016c8cfac8e2d4839a5bf6b07202521567fa0a81ff","action":"finding.record","taskId":"task_mvjo2nqy_726bd805","findingId":"fnd_mvjo2o23_80b5a937","severity":"critical","verification":"observed","title":"[secret:[REDACTED] 私钥内容","hash":"148101bd12836e69bdfddad75098da99d194f9e5576717a498ef6e159922d025"} |
| 1078 | 2026-10-22T14:59:15.158Z | evidence.add | {"seq":1078,"at":"2026-10-22T14:59:15.158Z","prevHash":"148101bd12836e69bdfddad75098da99d194f9e5576717a498ef6e159922d025","action":"evidence.add","taskId":"task_mvjo2nqy_726bd805","evidenceId":"ev_mvjo2o2a_c5562f7a","title":"core-benchmark.mjs:100","target":"D:\\dsh-ABM\\armorbreak","hash":"d0e219c80540148f2cba52a923e6810884219bd4906f49fc4eb12a306b9657d9"} |
| 1079 | 2026-10-22T14:59:15.165Z | finding.record | {"seq":1079,"at":"2026-10-22T14:59:15.165Z","prevHash":"d0e219c80540148f2cba52a923e6810884219bd4906f49fc4eb12a306b9657d9","action":"finding.record","taskId":"task_mvjo2nqy_726bd805","findingId":"fnd_mvjo2o2h_8d50fb4b","severity":"high","verification":"observed","title":"[secret:[REDACTED] AWS Access Key ID","hash":"695bfdd26da11c44b373db564279d6c79eaa2688484003ec2c251bf5e1ed8297"} |
| 1080 | 2026-10-22T14:59:15.177Z | capability.run.end | {"seq":1080,"at":"2026-10-22T14:59:15.177Z","prevHash":"695bfdd26da11c44b373db564279d6c79eaa2688484003ec2c251bf5e1ed8297","action":"capability.run.end","taskId":"task_mvjo2nqy_726bd805","capability":"sast.secrets","status":"ok","durationMs":384,"evidence":2,"findings":2,"targetSha256":null,"hash":"d4686ae02654349238bcc7f73b54f6bcd925f5d92e37ebbfdb5a3fe141b98135"} |
| 1081 | 2026-10-22T14:59:15.184Z | task.transition | {"seq":1081,"at":"2026-10-22T14:59:15.184Z","prevHash":"d4686ae02654349238bcc7f73b54f6bcd925f5d92e37ebbfdb5a3fe141b98135","action":"task.transition","taskId":"task_mvjo2nqy_726bd805","to":"VERIFYING","reason":"all steps settled","hash":"327cbc9f75422c1b65ece29c5d5bbc2575269ec33f379ba60d5334c1fbd11e7f"} |
| 1082 | 2026-10-22T14:59:15.200Z | task.transition | {"seq":1082,"at":"2026-10-22T14:59:15.200Z","prevHash":"327cbc9f75422c1b65ece29c5d5bbc2575269ec33f379ba60d5334c1fbd11e7f","action":"task.transition","taskId":"task_mvjo2nqy_726bd805","to":"REPORTING","reason":"generating report","hash":"9c3f1b36d6d5a25844dfdbb684574a1bc2e248f4a4b5aa96cd0b017536ca2bbf"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.16.0，DSH unknown，Profile n/a。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (4 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
