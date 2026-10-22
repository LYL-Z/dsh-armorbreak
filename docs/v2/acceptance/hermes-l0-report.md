# ArmorBreak 安全研究报告 — MCP 多算法文件哈希与完整性标识

- 报告 ID：`task_mvj10y9p_44aab54e`
- 生成时间：2026-10-22T04:14:05.179Z
- 任务状态：**REPORTING**
- 工作区：`C:\Users\Lenovo\AppData\Local\Temp\hermes-l0w-e4580bcc-6e5e-410f-acb9-66acce041be9`
- 目标：`C:\Users\Lenovo\AppData\Local\Temp\hermes-l0w-e4580bcc-6e5e-410f-acb9-66acce041be9\l0-sample.txt`
- 操作者：hermes-l0
- 证据链：校验通过，2 条记录

## 1. 摘要

共 0 条发现：critical 0 · high 0 · medium 0 · low 0 · info 0。留档证据 2 条。

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-22T04:14:03.902Z) → SCOPE_VALIDATION(2026-10-22T04:14:03.913Z) → ENVIRONMENT_CHECK(2026-10-22T04:14:03.919Z) → PLANNING(2026-10-22T04:14:03.924Z) → EXECUTING(2026-10-22T04:14:03.929Z) → VERIFYING(2026-10-22T04:14:03.960Z) → REPORTING(2026-10-22T04:14:03.973Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| analyze | forensics.hash | DONE | 7 ms | 文件大小 30 字节。 类型：text（text，high）。 md5: b0b3481f91e9c29f295d0d01909f9290 sha1: acd157d1fd779164c945c43ae1db7c2311da9309 sha256: 0dbaba1f56a201e9c5c7aadc33a5a05f714e3c6c00f519d8d43d15adc8e3ff9d sha512: 6f2d5a82f71e74942d610a1e660da262788d725fd5e5a7fd60134b5e82e434466f626669999c98fc6e02a2b0b346123732e35ab25cbe0053d4c6436d17d97bc0 |

## 4. 发现

没有记录到带证据的发现。这不等于目标安全：未覆盖的检测能力与未验证的假设见第 7 节。
## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvj10yav_43fd8be4` | execution | forensics.hash | `0dbaba1f56a201e9c5c7aadc33a5a05f714e3c6c00f519d8d43d15adc8e3ff9d` | 文件大小 30 字节。 类型：text（text，high）。 md5: b0b3481f91e9c29f295d0d01909f9290 sha1: acd157d1fd779164c945c43ae1db7c2311da9309 sha256: 0dbaba1f56a201e9c5c7aadc33a5a05f714e3c6c00f519d8d43d15adc8e3ff9d sha512: 6f2d5a82f71e74942d610a1e660da262788d725fd5e5a7fd60134b5e82e434466f626669999c98fc6e02a2b0b346123732e35ab25cbe0053d4c6436d17d97bc0 |
| 2 | `ev_mvj10yb0_a594654c` | file-hashes | forensics.hash | `0dbaba1f56a201e9c5c7aadc33a5a05f714e3c6c00f519d8d43d15adc8e3ff9d` | size=30 fileSize=30 truncated=false type=text (text/plain) md5=b0b3481f91e9c29f295d0d01909f9290 sha1=acd157d1fd779164c945c43ae1db7c2311da9309 sha256=0dbaba1f56a201e9c5c7aadc33a5a05f714e3c6c00f519d8d43d15adc8e3ff9d sha512=6f2d5a82f71e74942d610a1e660da262788d725fd5e5a7fd60134b5e82e434466f626669999c98fc6e02a2b0b346123732e35ab25cbe0053d4c6436d17d97bc0 |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 1 | 2026-10-22T04:14:03.907Z | task.create | {"seq":1,"at":"2026-10-22T04:14:03.907Z","prevHash":"genesis","action":"task.create","taskId":"task_mvj10y9p_44aab54e","title":"MCP 多算法文件哈希与完整性标识","workflowId":null,"target":"C:\\Users\\Lenovo\\AppData\\Local\\Temp\\hermes-l0w-e4580bcc-6e5e-410f-acb9-66acce041be9\\l0-sample.txt","hash":"6321f29a92b6a771b72042a87f7d0f7503ec62ab71f4f6cc750e84a4e724635f"} |
| 2 | 2026-10-22T04:14:03.916Z | task.transition | {"seq":2,"at":"2026-10-22T04:14:03.916Z","prevHash":"6321f29a92b6a771b72042a87f7d0f7503ec62ab71f4f6cc750e84a4e724635f","action":"task.transition","taskId":"task_mvj10y9p_44aab54e","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"37de2faffbf2c6949581a4ba129c453457c45d1436b6b82e0ae9df43838ad9f3"} |
| 3 | 2026-10-22T04:14:03.923Z | task.transition | {"seq":3,"at":"2026-10-22T04:14:03.923Z","prevHash":"37de2faffbf2c6949581a4ba129c453457c45d1436b6b82e0ae9df43838ad9f3","action":"task.transition","taskId":"task_mvj10y9p_44aab54e","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"c438fda0b405eeeb8fe62700850658458689bd52e3197c939db63b2b242b3823"} |
| 4 | 2026-10-22T04:14:03.928Z | task.transition | {"seq":4,"at":"2026-10-22T04:14:03.928Z","prevHash":"c438fda0b405eeeb8fe62700850658458689bd52e3197c939db63b2b242b3823","action":"task.transition","taskId":"task_mvj10y9p_44aab54e","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"a3d5c3fc8abfb2cebbd09d771defd68eb32522af6b5b744765ae0cac6672c03a"} |
| 5 | 2026-10-22T04:14:03.933Z | task.transition | {"seq":5,"at":"2026-10-22T04:14:03.933Z","prevHash":"a3d5c3fc8abfb2cebbd09d771defd68eb32522af6b5b744765ae0cac6672c03a","action":"task.transition","taskId":"task_mvj10y9p_44aab54e","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"49eb161fd5f55fab5f6da1eb5ec17791010ae309745cf250ca273b0d786b8567"} |
| 6 | 2026-10-22T04:14:03.936Z | capability.run.start | {"seq":6,"at":"2026-10-22T04:14:03.936Z","prevHash":"49eb161fd5f55fab5f6da1eb5ec17791010ae309745cf250ca273b0d786b8567","action":"capability.run.start","taskId":"task_mvj10y9p_44aab54e","stepId":"analyze","capability":"forensics.hash","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"C:\\Users\\Lenovo\\AppData\\Local\\Temp\\hermes-l0w-e4580bcc-6e5e-410f-acb9-66acce041be9\\l0-sample.txt","opti |
| 7 | 2026-10-22T04:14:03.946Z | evidence.add | {"seq":7,"at":"2026-10-22T04:14:03.946Z","prevHash":"9caff8a74c3a32540ea225e11056fc6e6c08a80beb090b656e32787096436a03","action":"evidence.add","taskId":"task_mvj10y9p_44aab54e","evidenceId":"ev_mvj10yav_43fd8be4","title":"forensics.hash execution","target":"C:\\Users\\Lenovo\\AppData\\Local\\Temp\\hermes-l0w-e4580bcc-6e5e-410f-acb9-66acce041be9\\l0-sample.txt","hash":"37317e5101ff3ccd0b207bf97c61e |
| 8 | 2026-10-22T04:14:03.950Z | evidence.add | {"seq":8,"at":"2026-10-22T04:14:03.950Z","prevHash":"37317e5101ff3ccd0b207bf97c61e5d3b3d20313cb74d80dcbb06c4b9be94c06","action":"evidence.add","taskId":"task_mvj10y9p_44aab54e","evidenceId":"ev_mvj10yb0_a594654c","title":"文件哈希","target":"C:\\Users\\Lenovo\\AppData\\Local\\Temp\\hermes-l0w-e4580bcc-6e5e-410f-acb9-66acce041be9\\l0-sample.txt","hash":"ea068abba2fe28421df15cb83185f568152390ee81b4ff6e2 |
| 9 | 2026-10-22T04:14:03.958Z | capability.run.end | {"seq":9,"at":"2026-10-22T04:14:03.958Z","prevHash":"ea068abba2fe28421df15cb83185f568152390ee81b4ff6e2cdc40c92fb67482","action":"capability.run.end","taskId":"task_mvj10y9p_44aab54e","capability":"forensics.hash","status":"ok","durationMs":22,"evidence":2,"findings":0,"targetSha256":"0dbaba1f56a201e9c5c7aadc33a5a05f714e3c6c00f519d8d43d15adc8e3ff9d","hash":"21df2463e5a87d16586b912d0cf4ba2623e4f4239 |
| 10 | 2026-10-22T04:14:03.964Z | task.transition | {"seq":10,"at":"2026-10-22T04:14:03.964Z","prevHash":"21df2463e5a87d16586b912d0cf4ba2623e4f4239c72c727c8b5ae7aa6155e7a","action":"task.transition","taskId":"task_mvj10y9p_44aab54e","to":"VERIFYING","reason":"all steps settled","hash":"2a968f2fe15f67a996d9ce1f64abf66b81f37b41da9074a944d0c7b93b77042f"} |
| 11 | 2026-10-22T04:14:03.976Z | task.transition | {"seq":11,"at":"2026-10-22T04:14:03.976Z","prevHash":"2a968f2fe15f67a996d9ce1f64abf66b81f37b41da9074a944d0c7b93b77042f","action":"task.transition","taskId":"task_mvj10y9p_44aab54e","to":"REPORTING","reason":"generating report","hash":"a71c1b95b9664a0fafe5bce49c5a45c498a5718e22455088714e3264b2eb5517"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.16.0，DSH unknown，Profile n/a。
- 隔离提供者：不可用（L1 动态分析保持拒绝）。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (2 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
