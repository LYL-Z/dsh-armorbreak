# ArmorBreak 安全研究报告 — MCP 多语言源码危险 API 扫描

- 报告 ID：`task_mvjf4409_3916dfb3`
- 生成时间：2026-10-22T10:48:28.499Z
- 任务状态：**REPORTING**
- 工作区：`D:\dsh-ABM\armorbreak`
- 目标：`D:\dsh-ABM\armorbreak`
- 操作者：trae-host
- 证据链：校验通过，11 条记录

## 1. 摘要

共 9 条发现：critical 0 · high 8 · medium 1 · low 0 · info 0。留档证据 11 条。

| # | 严重程度 | 标题 | 验证状态 | CWE | 位置 |
|---|---|---|---|---|---|
| 1 | high | [js-eval] 动态执行 eval() | hypothesis | CWE-95 | D:\dsh-ABM\armorbreak\benchmarks\bench.mjs:117 |
| 2 | high | [js-exec-dynamic] child_process.exec 使用动态/拼接命令（命令注入） | hypothesis | CWE-78 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:14 |
| 3 | high | [js-sql-concat] SQL 查询由字符串拼接/模板插值构造（SQL 注入） | hypothesis | CWE-89 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:21 |
| 4 | high | [js-eval] 动态执行 eval() | hypothesis | CWE-95 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:9 |
| 5 | high | [js-new-function] new Function() 动态构造代码 | hypothesis | CWE-95 | D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:101 |
| 6 | high | [js-shell-true] child_process 启用 shell: true | hypothesis | CWE-78 | D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:141 |
| 7 | high | [js-deserialization] 不安全反序列化（node-serialize 等） | hypothesis | CWE-502 | D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:541 |
| 8 | high | [js-eval] 动态执行 eval() | hypothesis | CWE-95 | D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:93 |
| 9 | medium | [js-weak-hash] 使用 MD5/SHA1 弱哈希 | observed | CWE-328 | D:\dsh-ABM\armorbreak\lib\analyzers\ctf\hash_id.js:68 |

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-22T10:48:25.929Z) → SCOPE_VALIDATION(2026-10-22T10:48:25.948Z) → ENVIRONMENT_CHECK(2026-10-22T10:48:25.961Z) → PLANNING(2026-10-22T10:48:25.976Z) → EXECUTING(2026-10-22T10:48:25.988Z) → VERIFYING(2026-10-22T10:48:26.788Z) → REPORTING(2026-10-22T10:48:26.825Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| analyze | sast.scan | DONE | 309 ms | 扫描 132 个源文件（跳过二进制 0，共 26556 行），命中 7 条规则 / 9 条候选发现：critical 0 / high 8 / medium 1 / low 0 / info 0。 问题最集中：D:\dsh-ABM\armorbreak\benchmarks\bench.mjs、D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js、D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js、D:\dsh-ABM\armorbreak\lib\analyzers\ctf\hash_id.js。 规则为逐行正则匹配（无数据流分析），taint 相关命中需人工确认可达性。 |

## 4. 发现

### 4.1 [js-eval] 动态执行 eval()

- 编号：`fnd_mvjf44c8_12ab069f`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\benchmarks\bench.mjs:117`

**说明**：动态执行 eval()。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjf44bs_fad7a021`, `ev_mvjf44ay_0af9a766`

### 4.2 [js-exec-dynamic] child_process.exec 使用动态/拼接命令（命令注入）

- 编号：`fnd_mvjf44db_0ed75b9b`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-78 — https://cwe.mitre.org/data/definitions/78.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:14`

**说明**：child_process.exec 使用动态/拼接命令（命令注入）。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：避免拼接命令；使用 execFile/spawn 参数数组或语言级 API，并对参数做白名单校验。

**证据**：`ev_mvjf44cs_b506d425`, `ev_mvjf44ay_0af9a766`

### 4.3 [js-sql-concat] SQL 查询由字符串拼接/模板插值构造（SQL 注入）

- 编号：`fnd_mvjf44ec_359c6e18`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:21`

**说明**：SQL 查询由字符串拼接/模板插值构造（SQL 注入）。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：使用参数化查询/预编译语句；不要拼接 SQL 字符串。

**证据**：`ev_mvjf44dy_23169de7`, `ev_mvjf44ay_0af9a766`

### 4.4 [js-eval] 动态执行 eval()

- 编号：`fnd_mvjf44fa_558e32dc`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:9`

**说明**：动态执行 eval()。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjf44es_63d85109`, `ev_mvjf44ay_0af9a766`

### 4.5 [js-new-function] new Function() 动态构造代码

- 编号：`fnd_mvjf44gr_9fab9880`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:101`

**说明**：new Function() 动态构造代码。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjf44g3_b67cf670`, `ev_mvjf44ay_0af9a766`

### 4.6 [js-shell-true] child_process 启用 shell: true

- 编号：`fnd_mvjf44ii_45cdf75f`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-78 — https://cwe.mitre.org/data/definitions/78.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:141`

**说明**：child_process 启用 shell: true。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：避免拼接命令；使用 execFile/spawn 参数数组或语言级 API，并对参数做白名单校验。

**证据**：`ev_mvjf44hq_4c3bc574`, `ev_mvjf44ay_0af9a766`

### 4.7 [js-deserialization] 不安全反序列化（node-serialize 等）

- 编号：`fnd_mvjf44k2_8b860d66`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-502 — https://cwe.mitre.org/data/definitions/502.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:541`

**说明**：不安全反序列化（node-serialize 等）。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：不要反序列化不可信数据；使用 JSON 等数据格式，或对反序列化做类型白名单与签名校验。

**证据**：`ev_mvjf44jc_fb6d62f6`, `ev_mvjf44ay_0af9a766`

### 4.8 [js-eval] 动态执行 eval()

- 编号：`fnd_mvjf44lj_649840ad`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:93`

**说明**：动态执行 eval()。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjf44kw_44c3de98`, `ev_mvjf44ay_0af9a766`

### 4.9 [js-weak-hash] 使用 MD5/SHA1 弱哈希

- 编号：`fnd_mvjf44mu_0f41ee78`
- 严重程度：**medium**（评分依据：严重程度映射 5.5）
- 验证状态：**observed**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-328 — https://cwe.mitre.org/data/definitions/328.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\ctf\hash_id.js:68`

**说明**：使用 MD5/SHA1 弱哈希。 该事实由源码直接观察得到，实际影响需结合上下文确认。

**影响**：基于 medium 级别的影响评估

**修复/复核建议**：改用 SHA-256/CH 系列或 bcrypt/scrypt/argon2 处理口令；不要用 MD5/SHA1 做安全用途。

**证据**：`ev_mvjf44m4_c31c4b26`, `ev_mvjf44ay_0af9a766`

## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvjf44ay_0af9a766` | execution | sast.scan | - | 扫描 132 个源文件（跳过二进制 0，共 26556 行），命中 7 条规则 / 9 条候选发现：critical 0 / high 8 / medium 1 / low 0 / info 0。 问题最集中：D:\dsh-ABM\armorbreak\benchmarks\bench.mjs、D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js、D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js、D:\dsh-ABM\armorbreak\lib\analyzers\ctf\hash_id.js。 规则为逐行正则匹配（无数据流分析），taint 相关命中需人工确认可达性。 |
| 2 | `ev_mvjf44bc_9eb74ac2` | sast-scan | sast.scan | - | files=132 skippedBinary=0 lines=26556 matchedRules=js-deserialization, js-eval, js-exec-dynamic, js-new-function, js-shell-true, js-sql-concat, js-weak-hash byLanguage={"javascript":132} readErrors=0 |
| 3 | `ev_mvjf44bs_fad7a021` | finding-evidence | sast.scan | - |     `  const ret = eval("(" + userId + ")")`, |
| 4 | `ev_mvjf44cs_b506d425` | finding-evidence | sast.scan | - |   exec('ping -n 1 ' + host, (error, stdout) => { |
| 5 | `ev_mvjf44dy_23169de7` | finding-evidence | sast.scan | - |   return db.query('SELECT * FROM users WHERE id = ' + userId) |
| 6 | `ev_mvjf44es_63d85109` | finding-evidence | sast.scan | - |   return eval(code) |
| 7 | `ev_mvjf44g3_b67cf670` | finding-evidence | sast.scan | - |     title: 'new Function() 动态构造代码', |
| 8 | `ev_mvjf44hq_4c3bc574` | finding-evidence | sast.scan | - |     title: 'child_process 启用 shell: true', |
| 9 | `ev_mvjf44jc_fb6d62f6` | finding-evidence | sast.scan | - |     title: 'unserialize() 反序列化不可信数据', |
| 10 | `ev_mvjf44kw_44c3de98` | finding-evidence | sast.scan | - |     title: '动态执行 eval()', |
| 11 | `ev_mvjf44m4_c31c4b26` | finding-evidence | sast.scan | - |     add('mysql41', 'likely', 'MySQL 4.1+ 密码哈希（* + SHA1(SHA1(密码))）'); |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 1024 | 2026-10-22T10:48:25.939Z | task.create | {"seq":1024,"at":"2026-10-22T10:48:25.939Z","prevHash":"133dd6d054f2e665c8efbad7ee45c3704a1c3d2e181b1dc8845f6b242b7407d7","action":"task.create","taskId":"task_mvjf4409_3916dfb3","title":"MCP 多语言源码危险 API 扫描","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak","hash":"2e272947e0eeff027f5a551a36dbb68a3d07a6e8b0f29924ad28a31e126a92c0"} |
| 1025 | 2026-10-22T10:48:25.957Z | task.transition | {"seq":1025,"at":"2026-10-22T10:48:25.957Z","prevHash":"2e272947e0eeff027f5a551a36dbb68a3d07a6e8b0f29924ad28a31e126a92c0","action":"task.transition","taskId":"task_mvjf4409_3916dfb3","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"975d07149d11b17a454343c87340396254acd60318297cc188431f6160ecdadd"} |
| 1026 | 2026-10-22T10:48:25.974Z | task.transition | {"seq":1026,"at":"2026-10-22T10:48:25.974Z","prevHash":"975d07149d11b17a454343c87340396254acd60318297cc188431f6160ecdadd","action":"task.transition","taskId":"task_mvjf4409_3916dfb3","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"37ddb5856610475c2969416e3e2187a232fa1bc41563e1d85f8c2a2d455f7c82"} |
| 1027 | 2026-10-22T10:48:25.986Z | task.transition | {"seq":1027,"at":"2026-10-22T10:48:25.986Z","prevHash":"37ddb5856610475c2969416e3e2187a232fa1bc41563e1d85f8c2a2d455f7c82","action":"task.transition","taskId":"task_mvjf4409_3916dfb3","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"72d5aa52048857e5b913820b9bbcc4ec208b4fa5a1cd24fd405548a3ef1e0707"} |
| 1028 | 2026-10-22T10:48:25.997Z | task.transition | {"seq":1028,"at":"2026-10-22T10:48:25.997Z","prevHash":"72d5aa52048857e5b913820b9bbcc4ec208b4fa5a1cd24fd405548a3ef1e0707","action":"task.transition","taskId":"task_mvjf4409_3916dfb3","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"e52bbaa333e874ad275a3902447b725da88a03b96538e2ac9eae0778e6aacb1f"} |
| 1029 | 2026-10-22T10:48:26.004Z | capability.run.start | {"seq":1029,"at":"2026-10-22T10:48:26.004Z","prevHash":"e52bbaa333e874ad275a3902447b725da88a03b96538e2ac9eae0778e6aacb1f","action":"capability.run.start","taskId":"task_mvjf4409_3916dfb3","stepId":"analyze","capability":"sast.scan","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak","options":{"maxFiles":400,"minSeverity":"medium"},"hash":"4a859f7d9f8cd50f07660775c7ac4 |
| 1030 | 2026-10-22T10:48:26.322Z | evidence.add | {"seq":1030,"at":"2026-10-22T10:48:26.322Z","prevHash":"4a859f7d9f8cd50f07660775c7ac48e8e5f1b57dbedb1a84891d46833c725a33","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44ay_0af9a766","title":"sast.scan execution","target":"D:\\dsh-ABM\\armorbreak","hash":"f3a43e59f3c5efbb86bf07c61d9069a93c557c5f6c78a460c6dbc088b976e397"} |
| 1031 | 2026-10-22T10:48:26.337Z | evidence.add | {"seq":1031,"at":"2026-10-22T10:48:26.337Z","prevHash":"f3a43e59f3c5efbb86bf07c61d9069a93c557c5f6c78a460c6dbc088b976e397","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44bc_9eb74ac2","title":"源码扫描统计","target":"D:\\dsh-ABM\\armorbreak","hash":"4229192b52e294242b809f13b104a865a2e4ae3103c86f7b9302c0455759d481"} |
| 1032 | 2026-10-22T10:48:26.355Z | evidence.add | {"seq":1032,"at":"2026-10-22T10:48:26.355Z","prevHash":"4229192b52e294242b809f13b104a865a2e4ae3103c86f7b9302c0455759d481","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44bs_fad7a021","title":"bench.mjs:117","target":"D:\\dsh-ABM\\armorbreak","hash":"ae6188188fb05653f4a9b78c479c0de35f52d538e9d3bcd0d948002600b2536f"} |
| 1033 | 2026-10-22T10:48:26.373Z | finding.record | {"seq":1033,"at":"2026-10-22T10:48:26.373Z","prevHash":"ae6188188fb05653f4a9b78c479c0de35f52d538e9d3bcd0d948002600b2536f","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44c8_12ab069f","severity":"high","verification":"hypothesis","title":"[js-eval] 动态执行 eval()","hash":"9b275d6f01db9c0b9361fbc20df85fc60d50661168487eb315d621bc14d92c09"} |
| 1034 | 2026-10-22T10:48:26.389Z | evidence.add | {"seq":1034,"at":"2026-10-22T10:48:26.389Z","prevHash":"9b275d6f01db9c0b9361fbc20df85fc60d50661168487eb315d621bc14d92c09","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44cs_b506d425","title":"app.js:14","target":"D:\\dsh-ABM\\armorbreak","hash":"3459da46b1c7b180120e486b83bb56262bcf1817b557779a8505b6243d33dfcc"} |
| 1035 | 2026-10-22T10:48:26.411Z | finding.record | {"seq":1035,"at":"2026-10-22T10:48:26.411Z","prevHash":"3459da46b1c7b180120e486b83bb56262bcf1817b557779a8505b6243d33dfcc","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44db_0ed75b9b","severity":"high","verification":"hypothesis","title":"[js-exec-dynamic] child_process.exec 使用动态/拼接命令（命令注入）","hash":"2e2d25b573b105a65b936e9a7bb141751318f5aff86a3dfa619f16fb84e62fc3" |
| 1036 | 2026-10-22T10:48:26.431Z | evidence.add | {"seq":1036,"at":"2026-10-22T10:48:26.431Z","prevHash":"2e2d25b573b105a65b936e9a7bb141751318f5aff86a3dfa619f16fb84e62fc3","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44dy_23169de7","title":"app.js:21","target":"D:\\dsh-ABM\\armorbreak","hash":"4a5e6c4b7e9d9fc41f1c88716655e0768822388eb70802653833f69263d5d8ec"} |
| 1037 | 2026-10-22T10:48:26.446Z | finding.record | {"seq":1037,"at":"2026-10-22T10:48:26.446Z","prevHash":"4a5e6c4b7e9d9fc41f1c88716655e0768822388eb70802653833f69263d5d8ec","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44ec_359c6e18","severity":"high","verification":"hypothesis","title":"[js-sql-concat] SQL 查询由字符串拼接/模板插值构造（SQL 注入）","hash":"5333a5a81f86953dc2d4b184ac61f7061393d621874632830cdd11a72206c146"} |
| 1038 | 2026-10-22T10:48:26.461Z | evidence.add | {"seq":1038,"at":"2026-10-22T10:48:26.461Z","prevHash":"5333a5a81f86953dc2d4b184ac61f7061393d621874632830cdd11a72206c146","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44es_63d85109","title":"app.js:9","target":"D:\\dsh-ABM\\armorbreak","hash":"82c9b65845f07988c40d0d861c8cd62450c573cd673738c9913041b06ac6cfb4"} |
| 1039 | 2026-10-22T10:48:26.486Z | finding.record | {"seq":1039,"at":"2026-10-22T10:48:26.486Z","prevHash":"82c9b65845f07988c40d0d861c8cd62450c573cd673738c9913041b06ac6cfb4","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44fa_558e32dc","severity":"high","verification":"hypothesis","title":"[js-eval] 动态执行 eval()","hash":"7b388df7a39fd5c307a2c221abb6c1b659407eac2e9701ff94f8c9d17de7e185"} |
| 1040 | 2026-10-22T10:48:26.512Z | evidence.add | {"seq":1040,"at":"2026-10-22T10:48:26.512Z","prevHash":"7b388df7a39fd5c307a2c221abb6c1b659407eac2e9701ff94f8c9d17de7e185","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44g3_b67cf670","title":"rules.js:101","target":"D:\\dsh-ABM\\armorbreak","hash":"6e7f59f3711c12d1630f35555dad0c2bec2b5fb04280360ad05726e8b2c70525"} |
| 1041 | 2026-10-22T10:48:26.544Z | finding.record | {"seq":1041,"at":"2026-10-22T10:48:26.544Z","prevHash":"6e7f59f3711c12d1630f35555dad0c2bec2b5fb04280360ad05726e8b2c70525","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44gr_9fab9880","severity":"high","verification":"hypothesis","title":"[js-new-function] new Function() 动态构造代码","hash":"4aeb672a7d521b8dc176d1c6fd225478d54f7236a1f81e9d6bca6b51e06939e6"} |
| 1042 | 2026-10-22T10:48:26.573Z | evidence.add | {"seq":1042,"at":"2026-10-22T10:48:26.573Z","prevHash":"4aeb672a7d521b8dc176d1c6fd225478d54f7236a1f81e9d6bca6b51e06939e6","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44hq_4c3bc574","title":"rules.js:141","target":"D:\\dsh-ABM\\armorbreak","hash":"5b98b39f874679360b71c06b464c3eb7680b87f3575ab9a8f6d19d82a63372e8"} |
| 1043 | 2026-10-22T10:48:26.605Z | finding.record | {"seq":1043,"at":"2026-10-22T10:48:26.605Z","prevHash":"5b98b39f874679360b71c06b464c3eb7680b87f3575ab9a8f6d19d82a63372e8","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44ii_45cdf75f","severity":"high","verification":"hypothesis","title":"[js-shell-true] child_process 启用 shell: true","hash":"9d4a0be9984ef377e8be9dfbf2e9d8cd07e98cbcff880cfc7c9c54b4ed5d5de6"} |
| 1044 | 2026-10-22T10:48:26.631Z | evidence.add | {"seq":1044,"at":"2026-10-22T10:48:26.631Z","prevHash":"9d4a0be9984ef377e8be9dfbf2e9d8cd07e98cbcff880cfc7c9c54b4ed5d5de6","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44jc_fb6d62f6","title":"rules.js:541","target":"D:\\dsh-ABM\\armorbreak","hash":"725d06616756a420d6512e4dcfefc5d67ca6b6c69eb7b312502bbf40c3dceeff"} |
| 1045 | 2026-10-22T10:48:26.657Z | finding.record | {"seq":1045,"at":"2026-10-22T10:48:26.657Z","prevHash":"725d06616756a420d6512e4dcfefc5d67ca6b6c69eb7b312502bbf40c3dceeff","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44k2_8b860d66","severity":"high","verification":"hypothesis","title":"[js-deserialization] 不安全反序列化（node-serialize 等）","hash":"49a62a66fa75aa88f21759ee262ee5eb03aa1b90fbc4b7d3d27770c5720e4e63"} |
| 1046 | 2026-10-22T10:48:26.685Z | evidence.add | {"seq":1046,"at":"2026-10-22T10:48:26.685Z","prevHash":"49a62a66fa75aa88f21759ee262ee5eb03aa1b90fbc4b7d3d27770c5720e4e63","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44kw_44c3de98","title":"rules.js:93","target":"D:\\dsh-ABM\\armorbreak","hash":"57c9623827bb1aa1a08fe5bb9c48d548bd7acf5a048c0456dab41d9f94395638"} |
| 1047 | 2026-10-22T10:48:26.710Z | finding.record | {"seq":1047,"at":"2026-10-22T10:48:26.710Z","prevHash":"57c9623827bb1aa1a08fe5bb9c48d548bd7acf5a048c0456dab41d9f94395638","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44lj_649840ad","severity":"high","verification":"hypothesis","title":"[js-eval] 动态执行 eval()","hash":"e580c487dc1e81252f7f9377522ddbf3d44af92cbd6ded7d59a085849104fc67"} |
| 1048 | 2026-10-22T10:48:26.729Z | evidence.add | {"seq":1048,"at":"2026-10-22T10:48:26.729Z","prevHash":"e580c487dc1e81252f7f9377522ddbf3d44af92cbd6ded7d59a085849104fc67","action":"evidence.add","taskId":"task_mvjf4409_3916dfb3","evidenceId":"ev_mvjf44m4_c31c4b26","title":"hash_id.js:68","target":"D:\\dsh-ABM\\armorbreak","hash":"feec21e50e82d0900aa9606cf0e570c81acd0d652e1bb3696820957ee679e56a"} |
| 1049 | 2026-10-22T10:48:26.754Z | finding.record | {"seq":1049,"at":"2026-10-22T10:48:26.754Z","prevHash":"feec21e50e82d0900aa9606cf0e570c81acd0d652e1bb3696820957ee679e56a","action":"finding.record","taskId":"task_mvjf4409_3916dfb3","findingId":"fnd_mvjf44mu_0f41ee78","severity":"medium","verification":"observed","title":"[js-weak-hash] 使用 MD5/SHA1 弱哈希","hash":"d0f5b399a9f32b42e45840a33d5ad3820b37849d5d8395232b5ce5885f59c0d4"} |
| 1050 | 2026-10-22T10:48:26.781Z | capability.run.end | {"seq":1050,"at":"2026-10-22T10:48:26.781Z","prevHash":"d0f5b399a9f32b42e45840a33d5ad3820b37849d5d8395232b5ce5885f59c0d4","action":"capability.run.end","taskId":"task_mvjf4409_3916dfb3","capability":"sast.scan","status":"ok","durationMs":777,"evidence":2,"findings":9,"targetSha256":null,"hash":"13ffc44fc99871a703136cb3445690b3f982286ab470a488f046ca3a32663880"} |
| 1051 | 2026-10-22T10:48:26.800Z | task.transition | {"seq":1051,"at":"2026-10-22T10:48:26.800Z","prevHash":"13ffc44fc99871a703136cb3445690b3f982286ab470a488f046ca3a32663880","action":"task.transition","taskId":"task_mvjf4409_3916dfb3","to":"VERIFYING","reason":"all steps settled","hash":"cfc196b8fa690c99f96367171dcf63731fe9eca0281a5fb1a6c4d889c92cc614"} |
| 1052 | 2026-10-22T10:48:26.837Z | task.transition | {"seq":1052,"at":"2026-10-22T10:48:26.837Z","prevHash":"cfc196b8fa690c99f96367171dcf63731fe9eca0281a5fb1a6c4d889c92cc614","action":"task.transition","taskId":"task_mvjf4409_3916dfb3","to":"REPORTING","reason":"generating report","hash":"6ea634ce3aa5080a8e616de32e45f76b0fa3abbf92e6f11a847401262ec1574e"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.16.0，DSH unknown，Profile n/a。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (11 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
