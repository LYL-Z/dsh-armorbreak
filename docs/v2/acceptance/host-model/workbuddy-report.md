# ArmorBreak 安全研究报告 — MCP 依赖清单与供应链启发式审计

- 报告 ID：`task_mvjewuhz_6d0bc96f`
- 生成时间：2026-10-22T10:42:48.943Z
- 任务状态：**REPORTING**
- 工作区：`D:\dsh-ABM\armorbreak`
- 目标：`D:\dsh-ABM\armorbreak`
- 操作者：workbuddy-host
- 证据链：校验通过，12 条记录

## 1. 摘要

共 13 条发现：critical 0 · high 5 · medium 5 · low 0 · info 3。留档证据 12 条。

| # | 严重程度 | 标题 | 验证状态 | CWE | 位置 |
|---|---|---|---|---|---|
| 1 | high | [deps-known-risky] ejs 3.1.6 低于已知修复版本 3.1.7 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json |
| 2 | high | [deps-known-risky] lodash 4.17.15 低于已知修复版本 4.17.21 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json |
| 3 | high | [deps-known-risky] minimist 1.2.5 低于已知修复版本 1.2.6 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json |
| 4 | high | [deps-known-risky] Django 2.2.0 低于已知修复版本 4.2.14 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt |
| 5 | high | [deps-known-risky] PyYAML 5.1 低于已知修复版本 5.4 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt |
| 6 | medium | [deps-known-risky] axios 0.21.1 低于已知修复版本 0.21.2 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json |
| 7 | medium | [deps-known-risky] express 4.16.0 低于已知修复版本 4.17.3 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json |
| 8 | medium | [deps-known-risky] node-fetch 2.6.0 低于已知修复版本 2.6.7 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json |
| 9 | medium | [deps-known-risky] Jinja2 2.10 低于已知修复版本 3.1.3 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt |
| 10 | medium | [deps-known-risky] requests 2.19.0 低于已知修复版本 2.31.0 | hypothesis | CWE-1395 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt |
| 11 | info | [deps-no-lockfile] 未发现锁文件：package.json | observed | CWE-494 | D:\dsh-ABM\armorbreak\package.json |
| 12 | info | [deps-no-lockfile] 未发现锁文件：package.json | observed | CWE-494 | D:\dsh-ABM\armorbreak\packages\adapter-dsh\package.json |
| 13 | info | [deps-no-lockfile] 未发现锁文件：package.json | observed | CWE-494 | D:\dsh-ABM\armorbreak\packages\cli\package.json |

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-22T10:42:47.015Z) → SCOPE_VALIDATION(2026-10-22T10:42:47.048Z) → ENVIRONMENT_CHECK(2026-10-22T10:42:47.059Z) → PLANNING(2026-10-22T10:42:47.069Z) → EXECUTING(2026-10-22T10:42:47.081Z) → VERIFYING(2026-10-22T10:42:47.475Z) → REPORTING(2026-10-22T10:42:47.500Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| analyze | sast.deps | DONE | 58 ms | 依赖审计：5 个清单（npm=4, pip=1），共 12 个依赖；未固定 0、范围 0、已知风险版本匹配 10，清单解析错误 0。发现 13 条问题。 |

## 4. 发现

### 4.1 [deps-known-risky] ejs 3.1.6 低于已知修复版本 3.1.7

- 编号：`fnd_mvjewumo_c7db06fd`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json 中依赖 ejs 固定为 3.1.6，低于公开修复版本 3.1.7（参考：CVE-2022-29078 服务端模板注入 RCE）。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：升级 ejs 到 3.1.7 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewume_aec37036`, `ev_mvjewulu_fd5ce4e6`

### 4.2 [deps-known-risky] lodash 4.17.15 低于已知修复版本 4.17.21

- 编号：`fnd_mvjewune_7df5ecb0`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json 中依赖 lodash 固定为 4.17.15，低于公开修复版本 4.17.21（参考：原型污染等修复（CVE-2021-23337 等））。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：升级 lodash 到 4.17.21 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewun0_b46e5457`, `ev_mvjewulu_fd5ce4e6`

### 4.3 [deps-known-risky] minimist 1.2.5 低于已知修复版本 1.2.6

- 编号：`fnd_mvjewuo1_9e0a0046`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json 中依赖 minimist 固定为 1.2.5，低于公开修复版本 1.2.6（参考：CVE-2021-44906 原型污染）。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：升级 minimist 到 1.2.6 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewunp_3457aacc`, `ev_mvjewulu_fd5ce4e6`

### 4.4 [deps-known-risky] Django 2.2.0 低于已知修复版本 4.2.14

- 编号：`fnd_mvjewuop_a57e409a`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt 中依赖 Django 固定为 2.2.0，低于公开修复版本 4.2.14（参考：CVE-2023-46695 等（以官方公告为准））。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：升级 Django 到 4.2.14 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewuod_2344c2d7`, `ev_mvjewulu_fd5ce4e6`

### 4.5 [deps-known-risky] PyYAML 5.1 低于已知修复版本 5.4

- 编号：`fnd_mvjewupb_ebb78086`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt 中依赖 PyYAML 固定为 5.1，低于公开修复版本 5.4（参考：CVE-2020-14343 反序列化）。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 high 级别的影响评估

**修复/复核建议**：升级 PyYAML 到 5.4 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewup0_41ed9b00`, `ev_mvjewulu_fd5ce4e6`

### 4.6 [deps-known-risky] axios 0.21.1 低于已知修复版本 0.21.2

- 编号：`fnd_mvjewuq0_e86379de`
- 严重程度：**medium**（评分依据：严重程度映射 5.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json 中依赖 axios 固定为 0.21.1，低于公开修复版本 0.21.2（参考：CVE-2021-3749 SSRF/ReDoS）。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 medium 级别的影响评估

**修复/复核建议**：升级 axios 到 0.21.2 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewupm_1a14a517`, `ev_mvjewulu_fd5ce4e6`

### 4.7 [deps-known-risky] express 4.16.0 低于已知修复版本 4.17.3

- 编号：`fnd_mvjewuqo_27e8666f`
- 严重程度：**medium**（评分依据：严重程度映射 5.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json 中依赖 express 固定为 4.16.0，低于公开修复版本 4.17.3（参考：多个修复（以官方 advisory 为准））。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 medium 级别的影响评估

**修复/复核建议**：升级 express 到 4.17.3 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewuqb_83f367d4`, `ev_mvjewulu_fd5ce4e6`

### 4.8 [deps-known-risky] node-fetch 2.6.0 低于已知修复版本 2.6.7

- 编号：`fnd_mvjewuri_44b6bc63`
- 严重程度：**medium**（评分依据：严重程度映射 5.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json 中依赖 node-fetch 固定为 2.6.0，低于公开修复版本 2.6.7（参考：CVE-2022-0235 凭据泄露）。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 medium 级别的影响评估

**修复/复核建议**：升级 node-fetch 到 2.6.7 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewur7_6c1a9c52`, `ev_mvjewulu_fd5ce4e6`

### 4.9 [deps-known-risky] Jinja2 2.10 低于已知修复版本 3.1.3

- 编号：`fnd_mvjewus6_8556c554`
- 严重程度：**medium**（评分依据：严重程度映射 5.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt 中依赖 Jinja2 固定为 2.10，低于公开修复版本 3.1.3（参考：CVE-2024-22195 等模板安全修复）。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 medium 级别的影响评估

**修复/复核建议**：升级 Jinja2 到 3.1.3 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewurv_bf732b36`, `ev_mvjewulu_fd5ce4e6`

### 4.10 [deps-known-risky] requests 2.19.0 低于已知修复版本 2.31.0

- 编号：`fnd_mvjewusu_b991a246`
- 严重程度：**medium**（评分依据：严重程度映射 5.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1395 — https://cwe.mitre.org/data/definitions/1395.html
- 检测方法：curated-version-advisory-heuristic
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt`

**说明**：D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt 中依赖 requests 固定为 2.19.0，低于公开修复版本 2.31.0（参考：CVE-2023-32681 代理凭据泄露）。 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。

**影响**：基于 medium 级别的影响评估

**修复/复核建议**：升级 requests 到 2.31.0 或更高版本，并回归验证兼容性。

**证据**：`ev_mvjewusi_26141bed`, `ev_mvjewulu_fd5ce4e6`

### 4.11 [deps-no-lockfile] 未发现锁文件：package.json

- 编号：`fnd_mvjewut6_941dfb35`
- 严重程度：**info**（评分依据：严重程度映射 0）
- 验证状态：**observed**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-494 — https://cwe.mitre.org/data/definitions/494.html
- 检测方法：dependency-pinning-heuristic
- 定位：`D:\dsh-ABM\armorbreak\package.json`

**说明**：在 D:\dsh-ABM\armorbreak\package.json 所在目录未发现锁文件（package-lock.json / yarn.lock / pnpm-lock.yaml / npm-shrinkwrap.json），依赖解析结果不可复现。

**影响**：基于 info 级别的影响评估

**修复/复核建议**：提交锁文件并在 CI 中使用 npm ci / pip install -r 固定版本。

**证据**：`ev_mvjewulu_fd5ce4e6`

### 4.12 [deps-no-lockfile] 未发现锁文件：package.json

- 编号：`fnd_mvjewuti_36fbdb57`
- 严重程度：**info**（评分依据：严重程度映射 0）
- 验证状态：**observed**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-494 — https://cwe.mitre.org/data/definitions/494.html
- 检测方法：dependency-pinning-heuristic
- 定位：`D:\dsh-ABM\armorbreak\packages\adapter-dsh\package.json`

**说明**：在 D:\dsh-ABM\armorbreak\packages\adapter-dsh\package.json 所在目录未发现锁文件（package-lock.json / yarn.lock / pnpm-lock.yaml / npm-shrinkwrap.json），依赖解析结果不可复现。

**影响**：基于 info 级别的影响评估

**修复/复核建议**：提交锁文件并在 CI 中使用 npm ci / pip install -r 固定版本。

**证据**：`ev_mvjewulu_fd5ce4e6`

### 4.13 [deps-no-lockfile] 未发现锁文件：package.json

- 编号：`fnd_mvjewutx_1126bc91`
- 严重程度：**info**（评分依据：严重程度映射 0）
- 验证状态：**observed**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-494 — https://cwe.mitre.org/data/definitions/494.html
- 检测方法：dependency-pinning-heuristic
- 定位：`D:\dsh-ABM\armorbreak\packages\cli\package.json`

**说明**：在 D:\dsh-ABM\armorbreak\packages\cli\package.json 所在目录未发现锁文件（package-lock.json / yarn.lock / pnpm-lock.yaml / npm-shrinkwrap.json），依赖解析结果不可复现。

**影响**：基于 info 级别的影响评估

**修复/复核建议**：提交锁文件并在 CI 中使用 npm ci / pip install -r 固定版本。

**证据**：`ev_mvjewulu_fd5ce4e6`

## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvjewulu_fd5ce4e6` | execution | sast.deps | - | 依赖审计：5 个清单（npm=4, pip=1），共 12 个依赖；未固定 0、范围 0、已知风险版本匹配 10，清单解析错误 0。发现 13 条问题。 |
| 2 | `ev_mvjewum4_3f87a6c6` | dependency-inventory | sast.deps | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\package.json [npm] deps=8 D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\requirements.txt [pip] deps=4 D:\dsh-ABM\armorbreak\package.json [npm] deps=0 D:\dsh-ABM\armorbreak\packages\adapter-dsh\package.json [npm] deps=0 D:\dsh-ABM\armorbreak\packages\cli\package.json [npm] deps=0 |
| 3 | `ev_mvjewume_aec37036` | finding-evidence | sast.deps | - | ejs 3.1.6 < 3.1.7（CVE-2022-29078 服务端模板注入 RCE） |
| 4 | `ev_mvjewun0_b46e5457` | finding-evidence | sast.deps | - | lodash 4.17.15 < 4.17.21（原型污染等修复（CVE-2021-23337 等）） |
| 5 | `ev_mvjewunp_3457aacc` | finding-evidence | sast.deps | - | minimist 1.2.5 < 1.2.6（CVE-2021-44906 原型污染） |
| 6 | `ev_mvjewuod_2344c2d7` | finding-evidence | sast.deps | - | Django 2.2.0 < 4.2.14（CVE-2023-46695 等（以官方公告为准）） |
| 7 | `ev_mvjewup0_41ed9b00` | finding-evidence | sast.deps | - | PyYAML 5.1 < 5.4（CVE-2020-14343 反序列化） |
| 8 | `ev_mvjewupm_1a14a517` | finding-evidence | sast.deps | - | axios 0.21.1 < 0.21.2（CVE-2021-3749 SSRF/ReDoS） |
| 9 | `ev_mvjewuqb_83f367d4` | finding-evidence | sast.deps | - | express 4.16.0 < 4.17.3（多个修复（以官方 advisory 为准）） |
| 10 | `ev_mvjewur7_6c1a9c52` | finding-evidence | sast.deps | - | node-fetch 2.6.0 < 2.6.7（CVE-2022-0235 凭据泄露） |
| 11 | `ev_mvjewurv_bf732b36` | finding-evidence | sast.deps | - | Jinja2 2.10 < 3.1.3（CVE-2024-22195 等模板安全修复） |
| 12 | `ev_mvjewusi_26141bed` | finding-evidence | sast.deps | - | requests 2.19.0 < 2.31.0（CVE-2023-32681 代理凭据泄露） |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 957 | 2026-10-22T10:42:47.034Z | task.create | {"seq":957,"at":"2026-10-22T10:42:47.034Z","prevHash":"afa142cd6b56347a12d693405a7b3c5c29b529ba30824b01df89bd144fc1edd2","action":"task.create","taskId":"task_mvjewuhz_6d0bc96f","title":"MCP 依赖清单与供应链启发式审计","workflowId":null,"target":"D:\\dsh-ABM\\armorbreak","hash":"a464656334881f22fa6178fcc1274e2092d197cdb351d7a46b09a2872f62df3f"} |
| 958 | 2026-10-22T10:42:47.055Z | task.transition | {"seq":958,"at":"2026-10-22T10:42:47.055Z","prevHash":"a464656334881f22fa6178fcc1274e2092d197cdb351d7a46b09a2872f62df3f","action":"task.transition","taskId":"task_mvjewuhz_6d0bc96f","to":"SCOPE_VALIDATION","reason":"validating authorization scope","hash":"9b42e5fc6b0607dd088bbffdbc043d6897b20dfc1ff6c5cf7a8417316ce51e37"} |
| 959 | 2026-10-22T10:42:47.066Z | task.transition | {"seq":959,"at":"2026-10-22T10:42:47.066Z","prevHash":"9b42e5fc6b0607dd088bbffdbc043d6897b20dfc1ff6c5cf7a8417316ce51e37","action":"task.transition","taskId":"task_mvjewuhz_6d0bc96f","to":"ENVIRONMENT_CHECK","reason":"scope validated","hash":"d8496565fdaf303047eea16ba127452112cffcb43cf5d06ced32c8615bd0607b"} |
| 960 | 2026-10-22T10:42:47.078Z | task.transition | {"seq":960,"at":"2026-10-22T10:42:47.078Z","prevHash":"d8496565fdaf303047eea16ba127452112cffcb43cf5d06ced32c8615bd0607b","action":"task.transition","taskId":"task_mvjewuhz_6d0bc96f","to":"PLANNING","reason":"environment checked; riskMax=L0","hash":"a8b81cfb84a551485c01275676f53343120af4b289e9bf96fb596d761705d5e8"} |
| 961 | 2026-10-22T10:42:47.089Z | task.transition | {"seq":961,"at":"2026-10-22T10:42:47.089Z","prevHash":"a8b81cfb84a551485c01275676f53343120af4b289e9bf96fb596d761705d5e8","action":"task.transition","taskId":"task_mvjewuhz_6d0bc96f","to":"EXECUTING","reason":"planned; offline L0 analysis","hash":"cdd38e404e8f44fda6a1657df046f41efd68ffe800de2b62be3222eb5c542149"} |
| 962 | 2026-10-22T10:42:47.102Z | capability.run.start | {"seq":962,"at":"2026-10-22T10:42:47.102Z","prevHash":"cdd38e404e8f44fda6a1657df046f41efd68ffe800de2b62be3222eb5c542149","action":"capability.run.start","taskId":"task_mvjewuhz_6d0bc96f","stepId":"analyze","capability":"sast.deps","riskLevel":"L0","policy":"WORKSPACE_ALLOWED","target":"D:\\dsh-ABM\\armorbreak","options":{"maxManifests":30,"maxDepsPerManifest":200},"hash":"ea775a35c341ce672573d7bd2 |
| 963 | 2026-10-22T10:42:47.158Z | evidence.add | {"seq":963,"at":"2026-10-22T10:42:47.158Z","prevHash":"ea775a35c341ce672573d7bd2b081e00fbb93307a7b66b19738850efd2f8c81c","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewulu_fd5ce4e6","title":"sast.deps execution","target":"D:\\dsh-ABM\\armorbreak","hash":"8a89933d601fce457e20170183e644852a26442610a3cde1b4c697822e590b43"} |
| 964 | 2026-10-22T10:42:47.169Z | evidence.add | {"seq":964,"at":"2026-10-22T10:42:47.169Z","prevHash":"8a89933d601fce457e20170183e644852a26442610a3cde1b4c697822e590b43","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewum4_3f87a6c6","title":"依赖清单概览","target":"D:\\dsh-ABM\\armorbreak","hash":"86eaaad7711ab5fa9ab59f7ce0ebd37135c1e2891799e3dd07eccd9feaf9c8be"} |
| 965 | 2026-10-22T10:42:47.181Z | evidence.add | {"seq":965,"at":"2026-10-22T10:42:47.181Z","prevHash":"86eaaad7711ab5fa9ab59f7ce0ebd37135c1e2891799e3dd07eccd9feaf9c8be","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewume_aec37036","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"4a6dcf96252bb1788b1c4ee5f4603ede5a430435ca3cc61a5d96234c9951848b"} |
| 966 | 2026-10-22T10:42:47.193Z | finding.record | {"seq":966,"at":"2026-10-22T10:42:47.193Z","prevHash":"4a6dcf96252bb1788b1c4ee5f4603ede5a430435ca3cc61a5d96234c9951848b","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewumo_c7db06fd","severity":"high","verification":"hypothesis","title":"[deps-known-risky] ejs 3.1.6 低于已知修复版本 3.1.7","hash":"42e6a20e0fcbbfcf7a435bd848fc79723179bb47b87caa1f2b746ca1d11f286b"} |
| 967 | 2026-10-22T10:42:47.206Z | evidence.add | {"seq":967,"at":"2026-10-22T10:42:47.206Z","prevHash":"42e6a20e0fcbbfcf7a435bd848fc79723179bb47b87caa1f2b746ca1d11f286b","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewun0_b46e5457","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"fbe8edb57e1c9b9a7149d9d4a9e385a223abb61bdae973215293df31482ecc7f"} |
| 968 | 2026-10-22T10:42:47.218Z | finding.record | {"seq":968,"at":"2026-10-22T10:42:47.218Z","prevHash":"fbe8edb57e1c9b9a7149d9d4a9e385a223abb61bdae973215293df31482ecc7f","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewune_7df5ecb0","severity":"high","verification":"hypothesis","title":"[deps-known-risky] lodash 4.17.15 低于已知修复版本 4.17.21","hash":"82985f3951dad8a18fadfaa73e939b26bda7f4dabb45f86724dcbca10c263bed"} |
| 969 | 2026-10-22T10:42:47.230Z | evidence.add | {"seq":969,"at":"2026-10-22T10:42:47.230Z","prevHash":"82985f3951dad8a18fadfaa73e939b26bda7f4dabb45f86724dcbca10c263bed","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewunp_3457aacc","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"c4bf19c6c39669b1b838ca6d6375c565de8bb7e81d16100e17bd4289771f1d14"} |
| 970 | 2026-10-22T10:42:47.242Z | finding.record | {"seq":970,"at":"2026-10-22T10:42:47.242Z","prevHash":"c4bf19c6c39669b1b838ca6d6375c565de8bb7e81d16100e17bd4289771f1d14","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewuo1_9e0a0046","severity":"high","verification":"hypothesis","title":"[deps-known-risky] minimist 1.2.5 低于已知修复版本 1.2.6","hash":"2e2b635509522a1382929ff90482490bb7ab35f4034d05e4abba81625df81574"} |
| 971 | 2026-10-22T10:42:47.254Z | evidence.add | {"seq":971,"at":"2026-10-22T10:42:47.254Z","prevHash":"2e2b635509522a1382929ff90482490bb7ab35f4034d05e4abba81625df81574","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewuod_2344c2d7","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"346f2acece4ca0ad91b6e39693becf35c2eaa2ceeaddbeb22d5ad84a22a4410c"} |
| 972 | 2026-10-22T10:42:47.265Z | finding.record | {"seq":972,"at":"2026-10-22T10:42:47.265Z","prevHash":"346f2acece4ca0ad91b6e39693becf35c2eaa2ceeaddbeb22d5ad84a22a4410c","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewuop_a57e409a","severity":"high","verification":"hypothesis","title":"[deps-known-risky] Django 2.2.0 低于已知修复版本 4.2.14","hash":"35c155b04568f419c66b169ab0fc02aeae1f2650097629c2686531143a8eea19"} |
| 973 | 2026-10-22T10:42:47.276Z | evidence.add | {"seq":973,"at":"2026-10-22T10:42:47.276Z","prevHash":"35c155b04568f419c66b169ab0fc02aeae1f2650097629c2686531143a8eea19","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewup0_41ed9b00","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"2d1b893a8ac2081a67f0a9abad6f18de2181573e6817a44196e1b7098d780f11"} |
| 974 | 2026-10-22T10:42:47.287Z | finding.record | {"seq":974,"at":"2026-10-22T10:42:47.287Z","prevHash":"2d1b893a8ac2081a67f0a9abad6f18de2181573e6817a44196e1b7098d780f11","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewupb_ebb78086","severity":"high","verification":"hypothesis","title":"[deps-known-risky] PyYAML 5.1 低于已知修复版本 5.4","hash":"b7c98ba96b7a9f494bd418ac45517b61ad1e091da0a07158040d9c6f9c6fb4db"} |
| 975 | 2026-10-22T10:42:47.299Z | evidence.add | {"seq":975,"at":"2026-10-22T10:42:47.299Z","prevHash":"b7c98ba96b7a9f494bd418ac45517b61ad1e091da0a07158040d9c6f9c6fb4db","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewupm_1a14a517","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"9dcbc36d84420693bdc578ea7ce13b3b9da04329e07e63e91657819c22fb47bc"} |
| 976 | 2026-10-22T10:42:47.311Z | finding.record | {"seq":976,"at":"2026-10-22T10:42:47.311Z","prevHash":"9dcbc36d84420693bdc578ea7ce13b3b9da04329e07e63e91657819c22fb47bc","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewuq0_e86379de","severity":"medium","verification":"hypothesis","title":"[deps-known-risky] axios 0.21.1 低于已知修复版本 0.21.2","hash":"acdd9333bbf7ee6ffaa3ec9797d294b4d080f7b741fcbf0cd84423a78cc7e9c1"} |
| 977 | 2026-10-22T10:42:47.323Z | evidence.add | {"seq":977,"at":"2026-10-22T10:42:47.323Z","prevHash":"acdd9333bbf7ee6ffaa3ec9797d294b4d080f7b741fcbf0cd84423a78cc7e9c1","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewuqb_83f367d4","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"c93700ce2c2b714e602049b933fdedf1d4b252ffeb5fb3ec049108e50055b4ee"} |
| 978 | 2026-10-22T10:42:47.342Z | finding.record | {"seq":978,"at":"2026-10-22T10:42:47.342Z","prevHash":"c93700ce2c2b714e602049b933fdedf1d4b252ffeb5fb3ec049108e50055b4ee","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewuqo_27e8666f","severity":"medium","verification":"hypothesis","title":"[deps-known-risky] express 4.16.0 低于已知修复版本 4.17.3","hash":"3e775765a610c0f2644341edb0a0de7958f54d67fcc78cd610e0ac7c7936a986"} |
| 979 | 2026-10-22T10:42:47.355Z | evidence.add | {"seq":979,"at":"2026-10-22T10:42:47.355Z","prevHash":"3e775765a610c0f2644341edb0a0de7958f54d67fcc78cd610e0ac7c7936a986","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewur7_6c1a9c52","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"81a5e35d7bb5ea3d22f3b3afb7b9b5db9e237c5d349b210cd8e4c86bc638f32e"} |
| 980 | 2026-10-22T10:42:47.367Z | finding.record | {"seq":980,"at":"2026-10-22T10:42:47.367Z","prevHash":"81a5e35d7bb5ea3d22f3b3afb7b9b5db9e237c5d349b210cd8e4c86bc638f32e","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewuri_44b6bc63","severity":"medium","verification":"hypothesis","title":"[deps-known-risky] node-fetch 2.6.0 低于已知修复版本 2.6.7","hash":"f040778dcd3379cb5dc94e21405e0dd3781996746d1a6ec45c330af147cb1cdd"} |
| 981 | 2026-10-22T10:42:47.379Z | evidence.add | {"seq":981,"at":"2026-10-22T10:42:47.379Z","prevHash":"f040778dcd3379cb5dc94e21405e0dd3781996746d1a6ec45c330af147cb1cdd","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewurv_bf732b36","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"e213213be0cd36f9086b6676c570d13f1b111517e0347626ed3e20eb2df147c6"} |
| 982 | 2026-10-22T10:42:47.391Z | finding.record | {"seq":982,"at":"2026-10-22T10:42:47.391Z","prevHash":"e213213be0cd36f9086b6676c570d13f1b111517e0347626ed3e20eb2df147c6","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewus6_8556c554","severity":"medium","verification":"hypothesis","title":"[deps-known-risky] Jinja2 2.10 低于已知修复版本 3.1.3","hash":"2755686a37eb6f23f755c58d446f9556ca5859788f60bc828351b83c77f0e81f"} |
| 983 | 2026-10-22T10:42:47.402Z | evidence.add | {"seq":983,"at":"2026-10-22T10:42:47.402Z","prevHash":"2755686a37eb6f23f755c58d446f9556ca5859788f60bc828351b83c77f0e81f","action":"evidence.add","taskId":"task_mvjewuhz_6d0bc96f","evidenceId":"ev_mvjewusi_26141bed","title":"版本匹配","target":"D:\\dsh-ABM\\armorbreak","hash":"d5053c833d3371630c29270ac4276d6d41aff4e28b5362ef7d9b897e143a242d"} |
| 984 | 2026-10-22T10:42:47.415Z | finding.record | {"seq":984,"at":"2026-10-22T10:42:47.415Z","prevHash":"d5053c833d3371630c29270ac4276d6d41aff4e28b5362ef7d9b897e143a242d","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewusu_b991a246","severity":"medium","verification":"hypothesis","title":"[deps-known-risky] requests 2.19.0 低于已知修复版本 2.31.0","hash":"94863dcfb20427fc0c3900729f518cd3b467c2adc17684a9fe9ce986c7533ee6"} |
| 985 | 2026-10-22T10:42:47.427Z | finding.record | {"seq":985,"at":"2026-10-22T10:42:47.427Z","prevHash":"94863dcfb20427fc0c3900729f518cd3b467c2adc17684a9fe9ce986c7533ee6","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewut6_941dfb35","severity":"info","verification":"observed","title":"[deps-no-lockfile] 未发现锁文件：package.json","hash":"e4fde193d6bf261f0b068f58e1c63b2bb5a446aafccc20719571817d7c87a8e1"} |
| 986 | 2026-10-22T10:42:47.442Z | finding.record | {"seq":986,"at":"2026-10-22T10:42:47.442Z","prevHash":"e4fde193d6bf261f0b068f58e1c63b2bb5a446aafccc20719571817d7c87a8e1","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewuti_36fbdb57","severity":"info","verification":"observed","title":"[deps-no-lockfile] 未发现锁文件：package.json","hash":"038ad08cc99eb779f70c96dc91ecf97c4337d1817a1fcf2a9f93c57efad3b98f"} |
| 987 | 2026-10-22T10:42:47.454Z | finding.record | {"seq":987,"at":"2026-10-22T10:42:47.454Z","prevHash":"038ad08cc99eb779f70c96dc91ecf97c4337d1817a1fcf2a9f93c57efad3b98f","action":"finding.record","taskId":"task_mvjewuhz_6d0bc96f","findingId":"fnd_mvjewutx_1126bc91","severity":"info","verification":"observed","title":"[deps-no-lockfile] 未发现锁文件：package.json","hash":"1c644ca02713765bd2e38d6c6b49a4756b4f68a799a25f8b0d29944e1fbc67d8"} |
| 988 | 2026-10-22T10:42:47.471Z | capability.run.end | {"seq":988,"at":"2026-10-22T10:42:47.471Z","prevHash":"1c644ca02713765bd2e38d6c6b49a4756b4f68a799a25f8b0d29944e1fbc67d8","action":"capability.run.end","taskId":"task_mvjewuhz_6d0bc96f","capability":"sast.deps","status":"ok","durationMs":376,"evidence":2,"findings":13,"targetSha256":null,"hash":"bc7682c3e956c3f95a6b751fd5be6df0a7e0019da619aedaf7c5d37dc0475c1c"} |
| 989 | 2026-10-22T10:42:47.484Z | task.transition | {"seq":989,"at":"2026-10-22T10:42:47.484Z","prevHash":"bc7682c3e956c3f95a6b751fd5be6df0a7e0019da619aedaf7c5d37dc0475c1c","action":"task.transition","taskId":"task_mvjewuhz_6d0bc96f","to":"VERIFYING","reason":"all steps settled","hash":"d51f660d81d4c77ec7eb7945ee1819f9e04571a3b7ccb5bf017855e9d4b6541b"} |
| 990 | 2026-10-22T10:42:47.507Z | task.transition | {"seq":990,"at":"2026-10-22T10:42:47.507Z","prevHash":"d51f660d81d4c77ec7eb7945ee1819f9e04571a3b7ccb5bf017855e9d4b6541b","action":"task.transition","taskId":"task_mvjewuhz_6d0bc96f","to":"REPORTING","reason":"generating report","hash":"59ff0eb42065dc9fbd7762dbd37822b671d2012b2402e943ad8ff7761f104d74"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v22.22.2，DSH unknown，Profile n/a。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (12 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
