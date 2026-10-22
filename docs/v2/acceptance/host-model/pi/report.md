# ArmorBreak 安全研究报告 — MCP 多算法文件哈希与完整性标识

- 报告 ID：`task_mvjistyn_dda26919`
- 生成时间：2026-10-22T12:31:39.601Z
- 任务状态：**REPORTING**
- 工作区：`D:\dsh-ABM\armorbreak`
- 目标：`D:\dsh-ABM\armorbreak\README.md`
- 操作者：pi-host
- 证据链：校验通过，2 条记录

## 1. 摘要

共 0 条发现：critical 0 · high 0 · medium 0 · low 0 · info 0。留档证据 2 条。

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-22T12:31:38.159Z) → SCOPE_VALIDATION(2026-10-22T12:31:38.177Z) → ENVIRONMENT_CHECK(2026-10-22T12:31:38.194Z) → PLANNING(2026-10-22T12:31:38.205Z) → EXECUTING(2026-10-22T12:31:38.217Z) → VERIFYING(2026-10-22T12:31:38.287Z) → REPORTING(2026-10-22T12:31:38.314Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| analyze | forensics.hash | DONE | 14 ms | 文件大小 62050 字节。 类型：text（text，high）。 md5: 7420cd97a5f703a5113b3089fea8fac8 sha1: 81919ac57169271b2a55ae40acf5cb8c8ae5c3da sha256: 52137f3b825cb5b4c34a730a487dc2f2abeeecc3fdd59e6b5c9fd10ed6756014 sha512: afdcc340a6995e5761e57bc79713a9bd990610ee73f1e3149efe3a3ca01b09a2bb4d34a24194bb91abec62642647da215ea9683f1b9626bd13f5d33f92457c58 |

## 4. 发现

没有记录到带证据的发现。这不等于目标安全：未覆盖的检测能力与未验证的假设见第 7 节。
## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvjisu14_defc9399` | execution | forensics.hash | `52137f3b825cb5b4c34a730a487dc2f2abeeecc3fdd59e6b5c9fd10ed6756014` | 文件大小 62050 字节。 类型：text（text，high）。 md5: 7420cd97a5f703a5113b3089fea8fac8 sha1: 81919ac57169271b2a55ae40acf5cb8c8ae5c3da sha256: 52137f3b825cb5b4c34a730a487dc2f2abeeecc3fdd59e6b5c9fd10ed6756014 sha512: afdcc340a6995e5761e57bc79713a9bd990610ee73f1e3149efe3a3ca01b09a2bb4d34a24194bb91abec62642647da215ea9683f1b9626bd13f5d33f92457c58 |
| 2 | `ev_mvjisu1d_5bee141e` | file-hashes | forensics.hash | `52137f3b825cb5b4c34a730a487dc2f2abeeecc3fdd59e6b5c9fd10ed6756014` | size=62050 fileSize=62050 truncated=false type=text (text/plain) md5=7420cd97a5f703a5113b3089fea8fac8 sha1=81919ac57169271b2a55ae40acf5cb8c8ae5c3da sha256=52137f3b825cb5b4c34a730a487dc2f2abeeecc3fdd59e6b5c9fd10ed6756014 sha512=afdcc340a6995e5761e57bc79713a9bd990610ee73f1e3149efe3a3ca01b09a2bb4d34a24194bb91abec62642647da215ea9683f1b9626bd13f5d33f92457c58 |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 1055 | 2026-10-22T12:31:38.168Z | task.create | {"seq":1055,"at":"2026-10-22T12:31:38.168Z","prevHash":"d3da9f942574d4526cdb3c724c0ca55e8964040ba4026fe1f020454107a12825","action":"task.create","taskId":"task_mvjistyn_dda26919","title":"MCP 多算法文件哈希与完整性标识","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak\\README.md","hash":"1a676c2f5e7ab52bb8c8e3ecac59066a01f3aa59ed41972829d3f1a0f7dcf2a4"} |
| 1056 | 2026-10-22T12:31:38.190Z | task.transition | {"seq":1056,"at":"2026-10-22T12:31:38.190Z","prevHash":"1a676c2f5e7ab52bb8c8e3ecac59066a01f3aa59ed41972829d3f1a0f7dcf2a4","action":"task.transition","taskId":"task_mvjistyn_dda26919","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"1998f723ff30393379e254cf02c2b8df0bd6beb2ae159354ff35c712160bdc4d"} |
| 1057 | 2026-10-22T12:31:38.202Z | task.transition | {"seq":1057,"at":"2026-10-22T12:31:38.202Z","prevHash":"1998f723ff30393379e254cf02c2b8df0bd6beb2ae159354ff35c712160bdc4d","action":"task.transition","taskId":"task_mvjistyn_dda26919","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"15396e33da6ed8ac157536bd4ca5bc175e04cf389b27f3bddb4e0b5ee5709ba7"} |
| 1058 | 2026-10-22T12:31:38.214Z | task.transition | {"seq":1058,"at":"2026-10-22T12:31:38.214Z","prevHash":"15396e33da6ed8ac157536bd4ca5bc175e04cf389b27f3bddb4e0b5ee5709ba7","action":"task.transition","taskId":"task_mvjistyn_dda26919","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"6edad802a94a0b0e34aaaf810ab8c1ab1871a863a58fe257d8662cc144428b00"} |
| 1059 | 2026-10-22T12:31:38.226Z | task.transition | {"seq":1059,"at":"2026-10-22T12:31:38.226Z","prevHash":"6edad802a94a0b0e34aaaf810ab8c1ab1871a863a58fe257d8662cc144428b00","action":"task.transition","taskId":"task_mvjistyn_dda26919","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"1ac8617ec3a421af3b1b9079eb134e50fe071598a0eeba161df9d1649a5dbe31"} |
| 1060 | 2026-10-22T12:31:38.233Z | capability.run.start | {"seq":1060,"at":"2026-10-22T12:31:38.233Z","prevHash":"1ac8617ec3a421af3b1b9079eb134e50fe071598a0eeba161df9d1649a5dbe31","action":"capability.run.start","taskId":"task_mvjistyn_dda26919","stepId":"analyze","capability":"forensics.hash","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak\\README.md","options":{},"hash":"13a902366ad1efcd6e96ec6536f0aedd971a6478ece6cf674e |
| 1061 | 2026-10-22T12:31:38.253Z | evidence.add | {"seq":1061,"at":"2026-10-22T12:31:38.253Z","prevHash":"13a902366ad1efcd6e96ec6536f0aedd971a6478ece6cf674e52b02c13422119","action":"evidence.add","taskId":"task_mvjistyn_dda26919","evidenceId":"ev_mvjisu14_defc9399","title":"forensics.hash execution","target":"D:\\dsh-ABM\\armorbreak\\README.md","hash":"81d00f8b64006c58b6ab601509472ff736e44ea576ba57512044c3ff592cc0ff"} |
| 1062 | 2026-10-22T12:31:38.262Z | evidence.add | {"seq":1062,"at":"2026-10-22T12:31:38.262Z","prevHash":"81d00f8b64006c58b6ab601509472ff736e44ea576ba57512044c3ff592cc0ff","action":"evidence.add","taskId":"task_mvjistyn_dda26919","evidenceId":"ev_mvjisu1d_5bee141e","title":"文件哈希","target":"D:\\dsh-ABM\\armorbreak\\README.md","hash":"cab47a0a4d2fb69d6c9c2bdfeb82b13b61901aceafeb974ad4c9294c1bc09365"} |
| 1063 | 2026-10-22T12:31:38.282Z | capability.run.end | {"seq":1063,"at":"2026-10-22T12:31:38.282Z","prevHash":"cab47a0a4d2fb69d6c9c2bdfeb82b13b61901aceafeb974ad4c9294c1bc09365","action":"capability.run.end","taskId":"task_mvjistyn_dda26919","capability":"forensics.hash","status":"ok","durationMs":49,"evidence":2,"findings":0,"targetSha256":"52137f3b825cb5b4c34a730a487dc2f2abeeecc3fdd59e6b5c9fd10ed6756014","hash":"48206428c842bd1d68ad9ee41a82c7a76f2121 |
| 1064 | 2026-10-22T12:31:38.296Z | task.transition | {"seq":1064,"at":"2026-10-22T12:31:38.296Z","prevHash":"48206428c842bd1d68ad9ee41a82c7a76f212187ba882d7692773723f46e7f5b","action":"task.transition","taskId":"task_mvjistyn_dda26919","to":"VERIFYING","reason":"all steps settled","hash":"8819b2faf090231b147b596f934289652cd103f46ac02bb5b3a3055c5da7137a"} |
| 1065 | 2026-10-22T12:31:38.324Z | task.transition | {"seq":1065,"at":"2026-10-22T12:31:38.324Z","prevHash":"8819b2faf090231b147b596f934289652cd103f46ac02bb5b3a3055c5da7137a","action":"task.transition","taskId":"task_mvjistyn_dda26919","to":"REPORTING","reason":"generating report","hash":"65c0c07d5332987b242103e69fe1af2e5c9a38d08f17bc025e7c0c4110112c27"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.16.0，DSH unknown，Profile desktop。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (2 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
