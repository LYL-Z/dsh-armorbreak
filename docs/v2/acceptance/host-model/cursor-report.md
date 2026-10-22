# ArmorBreak 安全研究报告 — MCP 多语言源码危险 API 扫描

- 报告 ID：`task_mvjey0mk_d002525a`
- 生成时间：2026-10-22T10:43:42.473Z
- 任务状态：**REPORTING**
- 工作区：`D:\dsh-ABM\armorbreak`
- 目标：`D:\dsh-ABM\armorbreak`
- 操作者：cursor-host
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
- 状态轨迹：CREATED(2026-10-22T10:43:41.616Z) → SCOPE_VALIDATION(2026-10-22T10:43:41.646Z) → ENVIRONMENT_CHECK(2026-10-22T10:43:41.659Z) → PLANNING(2026-10-22T10:43:41.674Z) → EXECUTING(2026-10-22T10:43:41.687Z) → VERIFYING(2026-10-22T10:43:42.396Z) → REPORTING(2026-10-22T10:43:42.424Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| analyze | sast.scan | DONE | 353 ms | 扫描 132 个源文件（跳过二进制 0，共 26556 行），命中 7 条规则 / 9 条候选发现：critical 0 / high 8 / medium 1 / low 0 / info 0。 问题最集中：D:\dsh-ABM\armorbreak\benchmarks\bench.mjs、D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js、D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js、D:\dsh-ABM\armorbreak\lib\analyzers\ctf\hash_id.js。 规则为逐行正则匹配（无数据流分析），taint 相关命中需人工确认可达性。 |

## 4. 发现

### 4.1 [js-eval] 动态执行 eval()

- 编号：`fnd_mvjey104_3e362335`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\benchmarks\bench.mjs:117`

**说明**：动态执行 eval()。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjey0zu_ae62f451`, `ev_mvjey0z2_7643d255`

### 4.2 [js-exec-dynamic] child_process.exec 使用动态/拼接命令（命令注入）

- 编号：`fnd_mvjey10z_b8c46b4b`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-78 — https://cwe.mitre.org/data/definitions/78.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:14`

**说明**：child_process.exec 使用动态/拼接命令（命令注入）。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：避免拼接命令；使用 execFile/spawn 参数数组或语言级 API，并对参数做白名单校验。

**证据**：`ev_mvjey10h_11e7b267`, `ev_mvjey0z2_7643d255`

### 4.3 [js-sql-concat] SQL 查询由字符串拼接/模板插值构造（SQL 注入）

- 编号：`fnd_mvjey11u_e23a24d8`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:21`

**说明**：SQL 查询由字符串拼接/模板插值构造（SQL 注入）。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：使用参数化查询/预编译语句；不要拼接 SQL 字符串。

**证据**：`ev_mvjey11e_6a778d56`, `ev_mvjey0z2_7643d255`

### 4.4 [js-eval] 动态执行 eval()

- 编号：`fnd_mvjey12l_f7a4856f`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:9`

**说明**：动态执行 eval()。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjey128_2ea9cd90`, `ev_mvjey0z2_7643d255`

### 4.5 [js-new-function] new Function() 动态构造代码

- 编号：`fnd_mvjey13g_b4e1381a`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:101`

**说明**：new Function() 动态构造代码。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjey131_5ecb5fdf`, `ev_mvjey0z2_7643d255`

### 4.6 [js-shell-true] child_process 启用 shell: true

- 编号：`fnd_mvjey149_70800e8e`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-78 — https://cwe.mitre.org/data/definitions/78.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:141`

**说明**：child_process 启用 shell: true。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：避免拼接命令；使用 execFile/spawn 参数数组或语言级 API，并对参数做白名单校验。

**证据**：`ev_mvjey13u_330c23bb`, `ev_mvjey0z2_7643d255`

### 4.7 [js-deserialization] 不安全反序列化（node-serialize 等）

- 编号：`fnd_mvjey152_8e62e61c`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-502 — https://cwe.mitre.org/data/definitions/502.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:541`

**说明**：不安全反序列化（node-serialize 等）。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：不要反序列化不可信数据；使用 JSON 等数据格式，或对反序列化做类型白名单与签名校验。

**证据**：`ev_mvjey14m_19f5b2da`, `ev_mvjey0z2_7643d255`

### 4.8 [js-eval] 动态执行 eval()

- 编号：`fnd_mvjey15y_041e8770`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js:93`

**说明**：动态执行 eval()。 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：移除动态代码执行；必须动态分发时使用白名单映射。

**证据**：`ev_mvjey15h_8f9dc172`, `ev_mvjey0z2_7643d255`

### 4.9 [js-weak-hash] 使用 MD5/SHA1 弱哈希

- 编号：`fnd_mvjey172_01a10e71`
- 严重程度：**medium**（评分依据：严重程度映射 5.5）
- 验证状态：**observed**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-328 — https://cwe.mitre.org/data/definitions/328.html
- 检测方法：line-regex-source-analysis
- 定位：`D:\dsh-ABM\armorbreak\lib\analyzers\ctf\hash_id.js:68`

**说明**：使用 MD5/SHA1 弱哈希。 该事实由源码直接观察得到，实际影响需结合上下文确认。

**影响**：基于 medium 级别的影响评估

**修复/复核建议**：改用 SHA-256/CH 系列或 bcrypt/scrypt/argon2 处理口令；不要用 MD5/SHA1 做安全用途。

**证据**：`ev_mvjey16j_841b9a7d`, `ev_mvjey0z2_7643d255`

## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvjey0z2_7643d255` | execution | sast.scan | - | 扫描 132 个源文件（跳过二进制 0，共 26556 行），命中 7 条规则 / 9 条候选发现：critical 0 / high 8 / medium 1 / low 0 / info 0。 问题最集中：D:\dsh-ABM\armorbreak\benchmarks\bench.mjs、D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js、D:\dsh-ABM\armorbreak\lib\analyzers\sast\rules.js、D:\dsh-ABM\armorbreak\lib\analyzers\ctf\hash_id.js。 规则为逐行正则匹配（无数据流分析），taint 相关命中需人工确认可达性。 |
| 2 | `ev_mvjey0zg_108e4c37` | sast-scan | sast.scan | - | files=132 skippedBinary=0 lines=26556 matchedRules=js-deserialization, js-eval, js-exec-dynamic, js-new-function, js-shell-true, js-sql-concat, js-weak-hash byLanguage={"javascript":132} readErrors=0 |
| 3 | `ev_mvjey0zu_ae62f451` | finding-evidence | sast.scan | - |     `  const ret = eval("(" + userId + ")")`, |
| 4 | `ev_mvjey10h_11e7b267` | finding-evidence | sast.scan | - |   exec('ping -n 1 ' + host, (error, stdout) => { |
| 5 | `ev_mvjey11e_6a778d56` | finding-evidence | sast.scan | - |   return db.query('SELECT * FROM users WHERE id = ' + userId) |
| 6 | `ev_mvjey128_2ea9cd90` | finding-evidence | sast.scan | - |   return eval(code) |
| 7 | `ev_mvjey131_5ecb5fdf` | finding-evidence | sast.scan | - |     title: 'new Function() 动态构造代码', |
| 8 | `ev_mvjey13u_330c23bb` | finding-evidence | sast.scan | - |     title: 'child_process 启用 shell: true', |
| 9 | `ev_mvjey14m_19f5b2da` | finding-evidence | sast.scan | - |     title: 'unserialize() 反序列化不可信数据', |
| 10 | `ev_mvjey15h_8f9dc172` | finding-evidence | sast.scan | - |     title: '动态执行 eval()', |
| 11 | `ev_mvjey16j_841b9a7d` | finding-evidence | sast.scan | - |     add('mysql41', 'likely', 'MySQL 4.1+ 密码哈希（* + SHA1(SHA1(密码))）'); |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 993 | 2026-10-22T10:43:41.628Z | task.create | {"seq":993,"at":"2026-10-22T10:43:41.628Z","prevHash":"a3e5a1b6255373c433f80931ac5b68de0fd37bffe759cbe00ab15148abddd8e2","action":"task.create","taskId":"task_mvjey0mk_d002525a","title":"MCP 多语言源码危险 API 扫描","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak","hash":"6b10ebdd4130142dcb5b3dfb916d5420d4e31013efaeba61ee76b81302a4928e"} |
| 994 | 2026-10-22T10:43:41.654Z | task.transition | {"seq":994,"at":"2026-10-22T10:43:41.654Z","prevHash":"6b10ebdd4130142dcb5b3dfb916d5420d4e31013efaeba61ee76b81302a4928e","action":"task.transition","taskId":"task_mvjey0mk_d002525a","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"532f8b8c981d93da81986d40074873deee5907efb25e5032a4d49ce68d80c4a7"} |
| 995 | 2026-10-22T10:43:41.670Z | task.transition | {"seq":995,"at":"2026-10-22T10:43:41.670Z","prevHash":"532f8b8c981d93da81986d40074873deee5907efb25e5032a4d49ce68d80c4a7","action":"task.transition","taskId":"task_mvjey0mk_d002525a","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"9bc4f3371b0d50bef2b827bdc33dde8b5d6db1f08b053e949405b8e79a624299"} |
| 996 | 2026-10-22T10:43:41.684Z | task.transition | {"seq":996,"at":"2026-10-22T10:43:41.684Z","prevHash":"9bc4f3371b0d50bef2b827bdc33dde8b5d6db1f08b053e949405b8e79a624299","action":"task.transition","taskId":"task_mvjey0mk_d002525a","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"48c65e9b54997f91c27b9af4e92d94be6d159cf5fabd4e3227b7d771aa21f2ee"} |
| 997 | 2026-10-22T10:43:41.700Z | task.transition | {"seq":997,"at":"2026-10-22T10:43:41.700Z","prevHash":"48c65e9b54997f91c27b9af4e92d94be6d159cf5fabd4e3227b7d771aa21f2ee","action":"task.transition","taskId":"task_mvjey0mk_d002525a","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"1a7bf6f73449fb8413273eb1e35d57c3c17823817f34f8efd60efd306a2b176a"} |
| 998 | 2026-10-22T10:43:41.715Z | capability.run.start | {"seq":998,"at":"2026-10-22T10:43:41.715Z","prevHash":"1a7bf6f73449fb8413273eb1e35d57c3c17823817f34f8efd60efd306a2b176a","action":"capability.run.start","taskId":"task_mvjey0mk_d002525a","stepId":"analyze","capability":"sast.scan","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak","options":{"maxFiles":400,"minSeverity":"medium"},"hash":"209d2bfc528a79014dc76b499af0d4 |
| 999 | 2026-10-22T10:43:42.067Z | evidence.add | {"seq":999,"at":"2026-10-22T10:43:42.067Z","prevHash":"209d2bfc528a79014dc76b499af0d467ba48b0473677ef756c989d0e568f7b52","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey0z2_7643d255","title":"sast.scan execution","target":"D:\\dsh-ABM\\armorbreak","hash":"fcb2e4f1ecfe849a1ac0e1b26a5d326cdfd8bf236ab381df9b66abf659802c56"} |
| 1000 | 2026-10-22T10:43:42.082Z | evidence.add | {"seq":1000,"at":"2026-10-22T10:43:42.082Z","prevHash":"fcb2e4f1ecfe849a1ac0e1b26a5d326cdfd8bf236ab381df9b66abf659802c56","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey0zg_108e4c37","title":"源码扫描统计","target":"D:\\dsh-ABM\\armorbreak","hash":"6ffd1dd556af60b72bd74174505a61b4e065a23f3e67063201a7832cb6119a0d"} |
| 1001 | 2026-10-22T10:43:42.096Z | evidence.add | {"seq":1001,"at":"2026-10-22T10:43:42.096Z","prevHash":"6ffd1dd556af60b72bd74174505a61b4e065a23f3e67063201a7832cb6119a0d","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey0zu_ae62f451","title":"bench.mjs:117","target":"D:\\dsh-ABM\\armorbreak","hash":"e231317de7c3113361b8b5288303c7c451ae9d5d45a490536c51f4f7fa55c6e1"} |
| 1002 | 2026-10-22T10:43:42.109Z | finding.record | {"seq":1002,"at":"2026-10-22T10:43:42.109Z","prevHash":"e231317de7c3113361b8b5288303c7c451ae9d5d45a490536c51f4f7fa55c6e1","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey104_3e362335","severity":"high","verification":"hypothesis","title":"[js-eval] 动态执行 eval()","hash":"873cf28c8d52e3343980ef1a008f55f9acdd3d4e87649a6c55f5776dfc36cfc9"} |
| 1003 | 2026-10-22T10:43:42.127Z | evidence.add | {"seq":1003,"at":"2026-10-22T10:43:42.127Z","prevHash":"873cf28c8d52e3343980ef1a008f55f9acdd3d4e87649a6c55f5776dfc36cfc9","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey10h_11e7b267","title":"app.js:14","target":"D:\\dsh-ABM\\armorbreak","hash":"67c0de5c28717872a33d90ec956e819405dc3fb9d6135cde0ba0f8fe3f78c11d"} |
| 1004 | 2026-10-22T10:43:42.142Z | finding.record | {"seq":1004,"at":"2026-10-22T10:43:42.142Z","prevHash":"67c0de5c28717872a33d90ec956e819405dc3fb9d6135cde0ba0f8fe3f78c11d","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey10z_b8c46b4b","severity":"high","verification":"hypothesis","title":"[js-exec-dynamic] child_process.exec 使用动态/拼接命令（命令注入）","hash":"5e2e312b27c440e20e156ab7cb5129f141e21eb39793821f84e70a38916f9b1b" |
| 1005 | 2026-10-22T10:43:42.158Z | evidence.add | {"seq":1005,"at":"2026-10-22T10:43:42.158Z","prevHash":"5e2e312b27c440e20e156ab7cb5129f141e21eb39793821f84e70a38916f9b1b","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey11e_6a778d56","title":"app.js:21","target":"D:\\dsh-ABM\\armorbreak","hash":"c9049d0389a24df5200bcae378f7f1a2b2eef3a00a83997b7ebc0fd9e8c9c01e"} |
| 1006 | 2026-10-22T10:43:42.172Z | finding.record | {"seq":1006,"at":"2026-10-22T10:43:42.172Z","prevHash":"c9049d0389a24df5200bcae378f7f1a2b2eef3a00a83997b7ebc0fd9e8c9c01e","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey11u_e23a24d8","severity":"high","verification":"hypothesis","title":"[js-sql-concat] SQL 查询由字符串拼接/模板插值构造（SQL 注入）","hash":"0583af623576161c3a8599a1cbe74e978dcefda70532d4c7227867f006608a5c"} |
| 1007 | 2026-10-22T10:43:42.185Z | evidence.add | {"seq":1007,"at":"2026-10-22T10:43:42.185Z","prevHash":"0583af623576161c3a8599a1cbe74e978dcefda70532d4c7227867f006608a5c","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey128_2ea9cd90","title":"app.js:9","target":"D:\\dsh-ABM\\armorbreak","hash":"1123689569ff7f06b6872a0e80575ddbb2db01e892279c8f2ec0f8598e40aa8a"} |
| 1008 | 2026-10-22T10:43:42.201Z | finding.record | {"seq":1008,"at":"2026-10-22T10:43:42.201Z","prevHash":"1123689569ff7f06b6872a0e80575ddbb2db01e892279c8f2ec0f8598e40aa8a","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey12l_f7a4856f","severity":"high","verification":"hypothesis","title":"[js-eval] 动态执行 eval()","hash":"efe3e61582082f5ede15d602a1bcb226586e2d78ff1edcb60d48565f1036b51d"} |
| 1009 | 2026-10-22T10:43:42.217Z | evidence.add | {"seq":1009,"at":"2026-10-22T10:43:42.217Z","prevHash":"efe3e61582082f5ede15d602a1bcb226586e2d78ff1edcb60d48565f1036b51d","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey131_5ecb5fdf","title":"rules.js:101","target":"D:\\dsh-ABM\\armorbreak","hash":"1d63345cb08d231205026231b82089dd348c1b6a79cb9a2d800d96d5fb662c07"} |
| 1010 | 2026-10-22T10:43:42.230Z | finding.record | {"seq":1010,"at":"2026-10-22T10:43:42.230Z","prevHash":"1d63345cb08d231205026231b82089dd348c1b6a79cb9a2d800d96d5fb662c07","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey13g_b4e1381a","severity":"high","verification":"hypothesis","title":"[js-new-function] new Function() 动态构造代码","hash":"14dd8cd5c3f13b8709a4c93866e6d4fae3ec1e6e38f389134aded617d7a97be8"} |
| 1011 | 2026-10-22T10:43:42.244Z | evidence.add | {"seq":1011,"at":"2026-10-22T10:43:42.244Z","prevHash":"14dd8cd5c3f13b8709a4c93866e6d4fae3ec1e6e38f389134aded617d7a97be8","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey13u_330c23bb","title":"rules.js:141","target":"D:\\dsh-ABM\\armorbreak","hash":"fbb61b69de09a02c758d450f0a016d5d4c498379d37103a39f99fdbbfdcf58b8"} |
| 1012 | 2026-10-22T10:43:42.259Z | finding.record | {"seq":1012,"at":"2026-10-22T10:43:42.259Z","prevHash":"fbb61b69de09a02c758d450f0a016d5d4c498379d37103a39f99fdbbfdcf58b8","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey149_70800e8e","severity":"high","verification":"hypothesis","title":"[js-shell-true] child_process 启用 shell: true","hash":"102b057064f6bb7a021f93808f1b97036e008e1092c36e944cbe69d8bc830baf"} |
| 1013 | 2026-10-22T10:43:42.274Z | evidence.add | {"seq":1013,"at":"2026-10-22T10:43:42.274Z","prevHash":"102b057064f6bb7a021f93808f1b97036e008e1092c36e944cbe69d8bc830baf","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey14m_19f5b2da","title":"rules.js:541","target":"D:\\dsh-ABM\\armorbreak","hash":"a2ad23495513e2d59dd1da4ace90d63d2979038fab90eae4823d67aa5b464619"} |
| 1014 | 2026-10-22T10:43:42.288Z | finding.record | {"seq":1014,"at":"2026-10-22T10:43:42.288Z","prevHash":"a2ad23495513e2d59dd1da4ace90d63d2979038fab90eae4823d67aa5b464619","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey152_8e62e61c","severity":"high","verification":"hypothesis","title":"[js-deserialization] 不安全反序列化（node-serialize 等）","hash":"e29972d872b2f7088034b7e9a6b6e123b8aaed0e6fffeee57a070c4fa800e0dd"} |
| 1015 | 2026-10-22T10:43:42.304Z | evidence.add | {"seq":1015,"at":"2026-10-22T10:43:42.304Z","prevHash":"e29972d872b2f7088034b7e9a6b6e123b8aaed0e6fffeee57a070c4fa800e0dd","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey15h_8f9dc172","title":"rules.js:93","target":"D:\\dsh-ABM\\armorbreak","hash":"4a156452945b4f69592decaf1b884f144ec793cfe25a2c3fef9d39a52bf0110c"} |
| 1016 | 2026-10-22T10:43:42.327Z | finding.record | {"seq":1016,"at":"2026-10-22T10:43:42.327Z","prevHash":"4a156452945b4f69592decaf1b884f144ec793cfe25a2c3fef9d39a52bf0110c","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey15y_041e8770","severity":"high","verification":"hypothesis","title":"[js-eval] 动态执行 eval()","hash":"2ca0399af271e1f00a7cf4a418dd98d7cd497049c06a11d64f297cf02cf53df8"} |
| 1017 | 2026-10-22T10:43:42.344Z | evidence.add | {"seq":1017,"at":"2026-10-22T10:43:42.344Z","prevHash":"2ca0399af271e1f00a7cf4a418dd98d7cd497049c06a11d64f297cf02cf53df8","action":"evidence.add","taskId":"task_mvjey0mk_d002525a","evidenceId":"ev_mvjey16j_841b9a7d","title":"hash_id.js:68","target":"D:\\dsh-ABM\\armorbreak","hash":"9e2096812c369670923876671af2f1300aedd6ea3b697774eab48082bb4b3023"} |
| 1018 | 2026-10-22T10:43:42.361Z | finding.record | {"seq":1018,"at":"2026-10-22T10:43:42.361Z","prevHash":"9e2096812c369670923876671af2f1300aedd6ea3b697774eab48082bb4b3023","action":"finding.record","taskId":"task_mvjey0mk_d002525a","findingId":"fnd_mvjey172_01a10e71","severity":"medium","verification":"observed","title":"[js-weak-hash] 使用 MD5/SHA1 弱哈希","hash":"eafaa207583956e27bd1f62477d9091053923398de43820b982b39bdcc16c4b6"} |
| 1019 | 2026-10-22T10:43:42.390Z | capability.run.end | {"seq":1019,"at":"2026-10-22T10:43:42.390Z","prevHash":"eafaa207583956e27bd1f62477d9091053923398de43820b982b39bdcc16c4b6","action":"capability.run.end","taskId":"task_mvjey0mk_d002525a","capability":"sast.scan","status":"ok","durationMs":682,"evidence":2,"findings":9,"targetSha256":null,"hash":"3236acd0bf33067205e22ccc07d5774c1207672a691f164e03d7f3a81d9534dc"} |
| 1020 | 2026-10-22T10:43:42.405Z | task.transition | {"seq":1020,"at":"2026-10-22T10:43:42.405Z","prevHash":"3236acd0bf33067205e22ccc07d5774c1207672a691f164e03d7f3a81d9534dc","action":"task.transition","taskId":"task_mvjey0mk_d002525a","to":"VERIFYING","reason":"all steps settled","hash":"cd43be85cc9ee26234d07d5a4f7b03b7f0d076467eb1574813c26c26c5178f36"} |
| 1021 | 2026-10-22T10:43:42.435Z | task.transition | {"seq":1021,"at":"2026-10-22T10:43:42.435Z","prevHash":"cd43be85cc9ee26234d07d5a4f7b03b7f0d076467eb1574813c26c26c5178f36","action":"task.transition","taskId":"task_mvjey0mk_d002525a","to":"REPORTING","reason":"generating report","hash":"50551207a67bbea0a6d11ef0054fa6ae640840efbaf6a1ca92693ea37ff500b2"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v22.22.1，DSH unknown，Profile n/a。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (11 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
