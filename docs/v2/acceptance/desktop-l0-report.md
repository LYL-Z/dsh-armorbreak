# ArmorBreak 安全研究报告 — core-scenarios.json 完整性哈希登记

- 报告 ID：`task_mvi33mq6_00e28f71`
- 生成时间：2026-10-21T12:24:24.628Z
- 任务状态：**COMPLETED**
- 工作区：`D:\dsh-ABM`
- 目标：`D:\dsh-ABM\armorbreak\docs\v2\benchmark\core-scenarios.json`
- 操作者：local-user
- 证据链：校验通过，2 条记录

## 1. 摘要

共 0 条发现：critical 0 · high 0 · medium 0 · low 0 · info 0。留档证据 2 条。

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-21T12:24:21.966Z) → SCOPE_VALIDATION(2026-10-21T12:24:23.480Z) → ENVIRONMENT_CHECK(2026-10-21T12:24:23.484Z) → PLANNING(2026-10-21T12:24:23.490Z) → EXECUTING(2026-10-21T12:24:23.496Z) → VERIFYING(2026-10-21T12:24:23.534Z) → REPORTING(2026-10-21T12:24:23.544Z) → COMPLETED(2026-10-21T12:24:23.560Z)

## 4. 发现

没有记录到带证据的发现。这不等于目标安全：未覆盖的检测能力与未验证的假设见第 7 节。
## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvi33nx8_c55674ff` | execution | forensics.hash | `50eea274f68780a501df2f79aea32fd6785dcc2a2f87a1e198e6f5b7c79e1fc8` | 文件大小 13746 字节。 类型：json（document，high）。 md5: f7ddf78bab50c96ff138d786046d2bc6 sha1: def787a67b754f0a0425e30b7dd3af9cb6621ff3 sha256: 50eea274f68780a501df2f79aea32fd6785dcc2a2f87a1e198e6f5b7c79e1fc8 sha512: 868df4b1968bbdcda26c742414ce0f7bda9ee6f39b103a6ff726fe69716110b60145037936c16a65eee27e31fb9462d013b4ec0738b8daa13d085038c6e24243 |
| 2 | `ev_mvi33nxf_3566fb8c` | file-hashes | forensics.hash | `50eea274f68780a501df2f79aea32fd6785dcc2a2f87a1e198e6f5b7c79e1fc8` | size=13746 fileSize=13746 truncated=false type=json (application/json) md5=f7ddf78bab50c96ff138d786046d2bc6 sha1=def787a67b754f0a0425e30b7dd3af9cb6621ff3 sha256=50eea274f68780a501df2f79aea32fd6785dcc2a2f87a1e198e6f5b7c79e1fc8 sha512=868df4b1968bbdcda26c742414ce0f7bda9ee6f39b103a6ff726fe69716110b60145037936c16a65eee27e31fb9462d013b4ec0738b8daa13d085038c6e24243 |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 325 | 2026-10-21T12:24:21.974Z | task.create | {"seq":325,"at":"2026-10-21T12:24:21.974Z","prevHash":"6518c1fad41d3088d776651a98be2c7099d06243875c2d2507007d65ca218351","action":"task.create","taskId":"task_mvi33mq6_00e28f71","title":"core-scenarios.json 完整性哈希登记","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak\\docs\\v2\\benchmark\\core-scenarios.json","hash":"ab147472a9d8357f2d2de1ce34e65e58f3a83b2f1735c28046507a70fa5632fe"} |
| 326 | 2026-10-21T12:24:23.482Z | task.transition | {"seq":326,"at":"2026-10-21T12:24:23.482Z","prevHash":"ab147472a9d8357f2d2de1ce34e65e58f3a83b2f1735c28046507a70fa5632fe","action":"task.transition","taskId":"task_mvi33mq6_00e28f71","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"f49fac74a89f0d4a599525ea512ad0435596af9bb4e54be415a478f1e572f66d"} |
| 327 | 2026-10-21T12:24:23.489Z | task.transition | {"seq":327,"at":"2026-10-21T12:24:23.489Z","prevHash":"f49fac74a89f0d4a599525ea512ad0435596af9bb4e54be415a478f1e572f66d","action":"task.transition","taskId":"task_mvi33mq6_00e28f71","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"acf48dbac94761b6bd6e350d45d2661242f4421c8043fb8b1638186e2510b1c4"} |
| 328 | 2026-10-21T12:24:23.495Z | task.transition | {"seq":328,"at":"2026-10-21T12:24:23.495Z","prevHash":"acf48dbac94761b6bd6e350d45d2661242f4421c8043fb8b1638186e2510b1c4","action":"task.transition","taskId":"task_mvi33mq6_00e28f71","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"44c4727bf6e2c443059f435c0257be256b63ffee993e755bb6f5342a4e36d1b5"} |
| 329 | 2026-10-21T12:24:23.501Z | task.transition | {"seq":329,"at":"2026-10-21T12:24:23.501Z","prevHash":"44c4727bf6e2c443059f435c0257be256b63ffee993e755bb6f5342a4e36d1b5","action":"task.transition","taskId":"task_mvi33mq6_00e28f71","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"1ac6137177db882d552ef71dd4b568e440d7a60862807553bc0cc17d75c9500c"} |
| 330 | 2026-10-21T12:24:23.508Z | capability.run.start | {"seq":330,"at":"2026-10-21T12:24:23.508Z","prevHash":"1ac6137177db882d552ef71dd4b568e440d7a60862807553bc0cc17d75c9500c","action":"capability.run.start","taskId":"task_mvi33mq6_00e28f71","stepId":null,"capability":"forensics.hash","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak\\docs\\v2\\benchmark\\core-scenarios.json","options":{},"hash":"aa8ba037d65f04a8cf2cb178d |
| 331 | 2026-10-21T12:24:23.518Z | evidence.add | {"seq":331,"at":"2026-10-21T12:24:23.518Z","prevHash":"aa8ba037d65f04a8cf2cb178d9daf4f4b53bd1de6f701af6dad24d7763271d03","action":"evidence.add","taskId":"task_mvi33mq6_00e28f71","evidenceId":"ev_mvi33nx8_c55674ff","title":"forensics.hash execution","target":"D:\\dsh-ABM\\armorbreak\\docs\\v2\\benchmark\\core-scenarios.json","hash":"2cba8bb72605510f1c834e8d17ec4fdfb746ae6b054809de75b107c360aa66b2" |
| 332 | 2026-10-21T12:24:23.525Z | evidence.add | {"seq":332,"at":"2026-10-21T12:24:23.525Z","prevHash":"2cba8bb72605510f1c834e8d17ec4fdfb746ae6b054809de75b107c360aa66b2","action":"evidence.add","taskId":"task_mvi33mq6_00e28f71","evidenceId":"ev_mvi33nxf_3566fb8c","title":"文件哈希","target":"D:\\dsh-ABM\\armorbreak\\docs\\v2\\benchmark\\core-scenarios.json","hash":"3012087339de43e8b6ccead6d087f0f84e9f51bf302334b4367783196071aec2"} |
| 333 | 2026-10-21T12:24:23.532Z | capability.run.end | {"seq":333,"at":"2026-10-21T12:24:23.532Z","prevHash":"3012087339de43e8b6ccead6d087f0f84e9f51bf302334b4367783196071aec2","action":"capability.run.end","taskId":"task_mvi33mq6_00e28f71","capability":"forensics.hash","status":"ok","durationMs":29,"evidence":2,"findings":0,"targetSha256":"50eea274f68780a501df2f79aea32fd6785dcc2a2f87a1e198e6f5b7c79e1fc8","hash":"e9998b46b32d5f5670e8f0720488a40147f0b3c |
| 334 | 2026-10-21T12:24:23.539Z | task.transition | {"seq":334,"at":"2026-10-21T12:24:23.539Z","prevHash":"e9998b46b32d5f5670e8f0720488a40147f0b3c01db39de64a82feaab34084c7","action":"task.transition","taskId":"task_mvi33mq6_00e28f71","to":"VERIFYING","reason":"all steps settled","hash":"6f95d6fda6df8eb97fc755c30bfb31aa6492967826d285407a07480931cf63bc"} |
| 335 | 2026-10-21T12:24:23.547Z | task.transition | {"seq":335,"at":"2026-10-21T12:24:23.547Z","prevHash":"6f95d6fda6df8eb97fc755c30bfb31aa6492967826d285407a07480931cf63bc","action":"task.transition","taskId":"task_mvi33mq6_00e28f71","to":"REPORTING","reason":"generating report","hash":"7d7808ecdf0fe3e7e9258dde50f69b43409537d6fc136130f69284fe4d7fe1e9"} |
| 336 | 2026-10-21T12:24:23.562Z | task.transition | {"seq":336,"at":"2026-10-21T12:24:23.562Z","prevHash":"7d7808ecdf0fe3e7e9258dde50f69b43409537d6fc136130f69284fe4d7fe1e9","action":"task.transition","taskId":"task_mvi33mq6_00e28f71","to":"COMPLETED","reason":"analysis completed","hash":"a2d148a3c73dbe24303445d6a9ffb5d4cf463c0ef76f62b142c1e6e913ebe945"} |
| 337 | 2026-10-21T12:24:23.568Z | task.finalize | {"seq":337,"at":"2026-10-21T12:24:23.568Z","prevHash":"a2d148a3c73dbe24303445d6a9ffb5d4cf463c0ef76f62b142c1e6e913ebe945","action":"task.finalize","taskId":"task_mvi33mq6_00e28f71","terminal":"COMPLETED","evidence":2,"findings":0,"failedSteps":0,"evidenceChain":{"valid":true,"records":2,"brokenAt":null,"reason":null},"report":{"format":"markdown","path":"D:\\dsh-ABM\\.armorbreak\\tasks\\task_mvi33m |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.21.0，DSH 0.2.1-rc.2，Profile n/a。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (2 records)
- report generated: D:\dsh-ABM\.armorbreak\tasks\task_mvi33mq6_00e28f71\reports\core-scenarios-json-完整性哈希登记_2026-10-21_12-24-23.md

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
