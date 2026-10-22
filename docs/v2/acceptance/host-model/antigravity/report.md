# ArmorBreak 安全研究报告 — MCP 多算法文件哈希与完整性标识

- 报告 ID：`task_mvjoq3xk_a07113b4`
- 生成时间：2026-10-22T15:17:28.941Z
- 任务状态：**REPORTING**
- 工作区：`D:\dsh-ABM\armorbreak`
- 目标：`D:\dsh-ABM\armorbreak\README.md`
- 操作者：antigravity-host
- 证据链：校验通过，2 条记录

## 1. 摘要

共 0 条发现：critical 0 · high 0 · medium 0 · low 0 · info 0。留档证据 2 条。

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-22T15:17:28.809Z) → SCOPE_VALIDATION(2026-10-22T15:17:28.822Z) → ENVIRONMENT_CHECK(2026-10-22T15:17:28.831Z) → PLANNING(2026-10-22T15:17:28.839Z) → EXECUTING(2026-10-22T15:17:28.846Z) → VERIFYING(2026-10-22T15:17:28.902Z) → REPORTING(2026-10-22T15:17:28.922Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| analyze | forensics.hash | DONE | 12 ms | 文件大小 62134 字节。 类型：text（text，high）。 md5: 8f932536f2b5e9eafd458159318906cb sha1: 39b03f40f719902143bb42a932fcd2f1e121a58d sha256: 3c02be24d5229ec05ef63e098e954355547c93f09572b2fb3ad95a10a58e5828 sha512: 6bd0b80dad9967bfcc302eec4b6b80ad6fefd1352a0519c53f70c8d94107ed00a1a10a6493f189dec8e1bf10f20cf925d17e20189e393b6821b5fed38312b445 |

## 4. 发现

没有记录到带证据的发现。这不等于目标安全：未覆盖的检测能力与未验证的假设见第 7 节。
## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvjoq3z9_e180e4b2` | execution | forensics.hash | `3c02be24d5229ec05ef63e098e954355547c93f09572b2fb3ad95a10a58e5828` | 文件大小 62134 字节。 类型：text（text，high）。 md5: 8f932536f2b5e9eafd458159318906cb sha1: 39b03f40f719902143bb42a932fcd2f1e121a58d sha256: 3c02be24d5229ec05ef63e098e954355547c93f09572b2fb3ad95a10a58e5828 sha512: 6bd0b80dad9967bfcc302eec4b6b80ad6fefd1352a0519c53f70c8d94107ed00a1a10a6493f189dec8e1bf10f20cf925d17e20189e393b6821b5fed38312b445 |
| 2 | `ev_mvjoq3zi_ac71fae0` | file-hashes | forensics.hash | `3c02be24d5229ec05ef63e098e954355547c93f09572b2fb3ad95a10a58e5828` | size=62134 fileSize=62134 truncated=false type=text (text/plain) md5=8f932536f2b5e9eafd458159318906cb sha1=39b03f40f719902143bb42a932fcd2f1e121a58d sha256=3c02be24d5229ec05ef63e098e954355547c93f09572b2fb3ad95a10a58e5828 sha512=6bd0b80dad9967bfcc302eec4b6b80ad6fefd1352a0519c53f70c8d94107ed00a1a10a6493f189dec8e1bf10f20cf925d17e20189e393b6821b5fed38312b445 |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 1098 | 2026-10-22T15:17:28.816Z | task.create | {"seq":1098,"at":"2026-10-22T15:17:28.816Z","prevHash":"4f2bd5b3209678ec768d06e3dd38c12c64873fe860450d54cddc761593c70c2f","action":"task.create","taskId":"task_mvjoq3xk_a07113b4","title":"MCP 多算法文件哈希与完整性标识","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak\\README.md","hash":"50feb6ff87d9761e1897f04757ee6563ee7941378443eada6ff30c28fdfbdfe2"} |
| 1099 | 2026-10-22T15:17:28.828Z | task.transition | {"seq":1099,"at":"2026-10-22T15:17:28.828Z","prevHash":"50feb6ff87d9761e1897f04757ee6563ee7941378443eada6ff30c28fdfbdfe2","action":"task.transition","taskId":"task_mvjoq3xk_a07113b4","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"5a32abb94153261d7ec5f6382b1a98827f85fbb3b533b5074af6c05d0e78a232"} |
| 1100 | 2026-10-22T15:17:28.837Z | task.transition | {"seq":1100,"at":"2026-10-22T15:17:28.837Z","prevHash":"5a32abb94153261d7ec5f6382b1a98827f85fbb3b533b5074af6c05d0e78a232","action":"task.transition","taskId":"task_mvjoq3xk_a07113b4","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"3fe3e3b812a685cb249263b4b111f00ef378a3026506e6681b8727fe8c13ee6c"} |
| 1101 | 2026-10-22T15:17:28.845Z | task.transition | {"seq":1101,"at":"2026-10-22T15:17:28.845Z","prevHash":"3fe3e3b812a685cb249263b4b111f00ef378a3026506e6681b8727fe8c13ee6c","action":"task.transition","taskId":"task_mvjoq3xk_a07113b4","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"f5f8089ae2ba0520254c1228b25e765286f4a152edb1c26417b69ff2b0ad4dc8"} |
| 1102 | 2026-10-22T15:17:28.852Z | task.transition | {"seq":1102,"at":"2026-10-22T15:17:28.852Z","prevHash":"f5f8089ae2ba0520254c1228b25e765286f4a152edb1c26417b69ff2b0ad4dc8","action":"task.transition","taskId":"task_mvjoq3xk_a07113b4","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"804e931538a74717a0c2ebbc41b35b94a4eac3a0c3df86d23723f3ad19377793"} |
| 1103 | 2026-10-22T15:17:28.857Z | capability.run.start | {"seq":1103,"at":"2026-10-22T15:17:28.857Z","prevHash":"804e931538a74717a0c2ebbc41b35b94a4eac3a0c3df86d23723f3ad19377793","action":"capability.run.start","taskId":"task_mvjoq3xk_a07113b4","stepId":"analyze","capability":"forensics.hash","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak\\README.md","options":{},"hash":"94a3db27a3e689a1d2ddb7a64e4225b09472a8938bf53ce561 |
| 1104 | 2026-10-22T15:17:28.873Z | evidence.add | {"seq":1104,"at":"2026-10-22T15:17:28.873Z","prevHash":"94a3db27a3e689a1d2ddb7a64e4225b09472a8938bf53ce5616d0f067ec18711","action":"evidence.add","taskId":"task_mvjoq3xk_a07113b4","evidenceId":"ev_mvjoq3z9_e180e4b2","title":"forensics.hash execution","target":"D:\\dsh-ABM\\armorbreak\\README.md","hash":"ad65e66158aa0026d6e79adc7e469c5baaf89cbf5a439264a0222bee4f4f05da"} |
| 1105 | 2026-10-22T15:17:28.883Z | evidence.add | {"seq":1105,"at":"2026-10-22T15:17:28.883Z","prevHash":"ad65e66158aa0026d6e79adc7e469c5baaf89cbf5a439264a0222bee4f4f05da","action":"evidence.add","taskId":"task_mvjoq3xk_a07113b4","evidenceId":"ev_mvjoq3zi_ac71fae0","title":"文件哈希","target":"D:\\dsh-ABM\\armorbreak\\README.md","hash":"c92d681251d7142ebc3071172ae7bc069471b5e431b884ee7639c84bd65538b6"} |
| 1106 | 2026-10-22T15:17:28.898Z | capability.run.end | {"seq":1106,"at":"2026-10-22T15:17:28.898Z","prevHash":"c92d681251d7142ebc3071172ae7bc069471b5e431b884ee7639c84bd65538b6","action":"capability.run.end","taskId":"task_mvjoq3xk_a07113b4","capability":"forensics.hash","status":"ok","durationMs":41,"evidence":2,"findings":0,"targetSha256":"3c02be24d5229ec05ef63e098e954355547c93f09572b2fb3ad95a10a58e5828","hash":"b924e719541bc86a492e7b917083542f37f843 |
| 1107 | 2026-10-22T15:17:28.909Z | task.transition | {"seq":1107,"at":"2026-10-22T15:17:28.909Z","prevHash":"b924e719541bc86a492e7b917083542f37f843fdd10b61f5b8899d4f4f207406","action":"task.transition","taskId":"task_mvjoq3xk_a07113b4","to":"VERIFYING","reason":"all steps settled","hash":"10247d810084180c351e03686061a2ea6caf115bcc362c6463777a1e8d753acb"} |
| 1108 | 2026-10-22T15:17:28.928Z | task.transition | {"seq":1108,"at":"2026-10-22T15:17:28.928Z","prevHash":"10247d810084180c351e03686061a2ea6caf115bcc362c6463777a1e8d753acb","action":"task.transition","taskId":"task_mvjoq3xk_a07113b4","to":"REPORTING","reason":"generating report","hash":"7d01da3d0ea080adb6910f75869222ee45bad7ff2daf742dd81f96797c269df2"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.16.0，DSH unknown，Profile n/a。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (2 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
