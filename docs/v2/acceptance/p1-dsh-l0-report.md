# ArmorBreak 安全研究报告 — core/index.js 完整性哈希登记

- 报告 ID：`task_mvi9s8sb_821b3068`
- 生成时间：2026-10-21T15:31:30.273Z
- 任务状态：**COMPLETED**
- 工作区：`D:\dsh-ABM`
- 目标：`D:\dsh-ABM\armorbreak\packages\core\index.js`
- 操作者：local-user
- 证据链：校验通过，2 条记录

## 1. 摘要

共 0 条发现：critical 0 · high 0 · medium 0 · low 0 · info 0。留档证据 2 条。

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-21T15:31:27.995Z) → SCOPE_VALIDATION(2026-10-21T15:31:29.047Z) → ENVIRONMENT_CHECK(2026-10-21T15:31:29.051Z) → PLANNING(2026-10-21T15:31:29.057Z) → EXECUTING(2026-10-21T15:31:29.069Z) → VERIFYING(2026-10-21T15:31:29.108Z) → REPORTING(2026-10-21T15:31:29.118Z) → COMPLETED(2026-10-21T15:31:29.134Z)

## 4. 发现

没有记录到带证据的发现。这不等于目标安全：未覆盖的检测能力与未验证的假设见第 7 节。
## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvi9s9mp_4ff58d4a` | execution | forensics.hash | `1f0579721ae3085d72fa92618517406fa4bd00810981d60dbe72b0148b596b39` | 文件大小 2013 字节。 类型：text（text，high）。 md5: 0060e77a86fe7d295dd42d4e25a98740 sha1: 9cda3da2e732816432a70b8093e353c2f0054623 sha256: 1f0579721ae3085d72fa92618517406fa4bd00810981d60dbe72b0148b596b39 sha512: e591de1bd038131f6cde1b9c84b72d649dd63049ab4fc73975671642f8b416f2356970dc892bd795f59cdd1af119e1d4bae9bab17ef29b684e009be09b6ba1c1 |
| 2 | `ev_mvi9s9mx_097a9b93` | file-hashes | forensics.hash | `1f0579721ae3085d72fa92618517406fa4bd00810981d60dbe72b0148b596b39` | size=2013 fileSize=2013 truncated=false type=text (text/plain) md5=0060e77a86fe7d295dd42d4e25a98740 sha1=9cda3da2e732816432a70b8093e353c2f0054623 sha256=1f0579721ae3085d72fa92618517406fa4bd00810981d60dbe72b0148b596b39 sha512=e591de1bd038131f6cde1b9c84b72d649dd63049ab4fc73975671642f8b416f2356970dc892bd795f59cdd1af119e1d4bae9bab17ef29b684e009be09b6ba1c1 |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 338 | 2026-10-21T15:31:27.998Z | task.create | {"seq":338,"at":"2026-10-21T15:31:27.998Z","prevHash":"f2911a5724b64020ab6a922b905f26615e5db3e5f6dd36e402d58d7ab34a8818","action":"task.create","taskId":"task_mvi9s8sb_821b3068","title":"core/index.js 完整性哈希登记","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak\\packages\\core\\index.js","hash":"84350d9ab3e480f8d9907f76898b9919be0244e5741c9e9406d248387c22824b"} |
| 339 | 2026-10-21T15:31:29.049Z | task.transition | {"seq":339,"at":"2026-10-21T15:31:29.049Z","prevHash":"84350d9ab3e480f8d9907f76898b9919be0244e5741c9e9406d248387c22824b","action":"task.transition","taskId":"task_mvi9s8sb_821b3068","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"44341f2de8863e823f25c76ead7198e939c990eec2c10713d5f9d790926b7891"} |
| 340 | 2026-10-21T15:31:29.056Z | task.transition | {"seq":340,"at":"2026-10-21T15:31:29.056Z","prevHash":"44341f2de8863e823f25c76ead7198e939c990eec2c10713d5f9d790926b7891","action":"task.transition","taskId":"task_mvi9s8sb_821b3068","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"10c82e54f1d75662983c7ac3c56986398fa7341dd3594536a832ca8eac0412ee"} |
| 341 | 2026-10-21T15:31:29.068Z | task.transition | {"seq":341,"at":"2026-10-21T15:31:29.068Z","prevHash":"10c82e54f1d75662983c7ac3c56986398fa7341dd3594536a832ca8eac0412ee","action":"task.transition","taskId":"task_mvi9s8sb_821b3068","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"1cccb28f9281d1d2e5701f6d15ce227bfbc383bddfc09c5b8fbdd55b6c52e1f1"} |
| 342 | 2026-10-21T15:31:29.075Z | task.transition | {"seq":342,"at":"2026-10-21T15:31:29.075Z","prevHash":"1cccb28f9281d1d2e5701f6d15ce227bfbc383bddfc09c5b8fbdd55b6c52e1f1","action":"task.transition","taskId":"task_mvi9s8sb_821b3068","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"9b88713a381409fe16f7ab798be06f13c98621cfd4f09bf4aad656a506f8c982"} |
| 343 | 2026-10-21T15:31:29.083Z | capability.run.start | {"seq":343,"at":"2026-10-21T15:31:29.083Z","prevHash":"9b88713a381409fe16f7ab798be06f13c98621cfd4f09bf4aad656a506f8c982","action":"capability.run.start","taskId":"task_mvi9s8sb_821b3068","stepId":null,"capability":"forensics.hash","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak\\packages\\core\\index.js","options":{},"hash":"7347b2cc89959543b397603f83950081ec0b5393d |
| 344 | 2026-10-21T15:31:29.091Z | evidence.add | {"seq":344,"at":"2026-10-21T15:31:29.091Z","prevHash":"7347b2cc89959543b397603f83950081ec0b5393dd619db68f72c7c64ba338e6","action":"evidence.add","taskId":"task_mvi9s8sb_821b3068","evidenceId":"ev_mvi9s9mp_4ff58d4a","title":"forensics.hash execution","target":"D:\\dsh-ABM\\armorbreak\\packages\\core\\index.js","hash":"60513eff49a4423e2061505fbcddc13f26a04e07d1ea2063cf022e6ef377a5ef"} |
| 345 | 2026-10-21T15:31:29.099Z | evidence.add | {"seq":345,"at":"2026-10-21T15:31:29.099Z","prevHash":"60513eff49a4423e2061505fbcddc13f26a04e07d1ea2063cf022e6ef377a5ef","action":"evidence.add","taskId":"task_mvi9s8sb_821b3068","evidenceId":"ev_mvi9s9mx_097a9b93","title":"文件哈希","target":"D:\\dsh-ABM\\armorbreak\\packages\\core\\index.js","hash":"5c17788313f9701ea073c4935a4c3d54ac885890833636ede795ca1af43d66ff"} |
| 346 | 2026-10-21T15:31:29.105Z | capability.run.end | {"seq":346,"at":"2026-10-21T15:31:29.105Z","prevHash":"5c17788313f9701ea073c4935a4c3d54ac885890833636ede795ca1af43d66ff","action":"capability.run.end","taskId":"task_mvi9s8sb_821b3068","capability":"forensics.hash","status":"ok","durationMs":29,"evidence":2,"findings":0,"targetSha256":"1f0579721ae3085d72fa92618517406fa4bd00810981d60dbe72b0148b596b39","hash":"c8fb595086ad530bde164e746ba6728f71be134 |
| 347 | 2026-10-21T15:31:29.112Z | task.transition | {"seq":347,"at":"2026-10-21T15:31:29.112Z","prevHash":"c8fb595086ad530bde164e746ba6728f71be134c7a557de5d43d2ec74ea4df85","action":"task.transition","taskId":"task_mvi9s8sb_821b3068","to":"VERIFYING","reason":"all steps settled","hash":"7301f276ac28f74dddfb96383244d9726736c0b2d4eda141627f7c14f0ca52a8"} |
| 348 | 2026-10-21T15:31:29.120Z | task.transition | {"seq":348,"at":"2026-10-21T15:31:29.120Z","prevHash":"7301f276ac28f74dddfb96383244d9726736c0b2d4eda141627f7c14f0ca52a8","action":"task.transition","taskId":"task_mvi9s8sb_821b3068","to":"REPORTING","reason":"generating report","hash":"34f035498696762f739bdba20578b607245904678eb15708f6cc553f926ca9cf"} |
| 349 | 2026-10-21T15:31:29.136Z | task.transition | {"seq":349,"at":"2026-10-21T15:31:29.136Z","prevHash":"34f035498696762f739bdba20578b607245904678eb15708f6cc553f926ca9cf","action":"task.transition","taskId":"task_mvi9s8sb_821b3068","to":"COMPLETED","reason":"analysis completed","hash":"9ca2fe3287b4194240d1cddcfb65cb6a1e355d42489922bc01e758518101f448"} |
| 350 | 2026-10-21T15:31:29.144Z | task.finalize | {"seq":350,"at":"2026-10-21T15:31:29.144Z","prevHash":"9ca2fe3287b4194240d1cddcfb65cb6a1e355d42489922bc01e758518101f448","action":"task.finalize","taskId":"task_mvi9s8sb_821b3068","terminal":"COMPLETED","evidence":2,"findings":0,"failedSteps":0,"evidenceChain":{"valid":true,"records":2,"brokenAt":null,"reason":null},"report":{"format":"markdown","path":"D:\\dsh-ABM\\.armorbreak\\tasks\\task_mvi9s8 |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.21.0，DSH 0.2.1-rc.2，Profile n/a。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (2 records)
- report generated: D:\dsh-ABM\.armorbreak\tasks\task_mvi9s8sb_821b3068\reports\core-index-js-完整性哈希登记_2026-10-21_15-31-29.md

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
