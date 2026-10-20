# ArmorBreak 安全研究报告 — Gate B - real Semgrep/Trivy CLI through Stage B adapters

- 报告 ID：`task_mvgptyn7_8a3bfeab`
- 生成时间：2026-10-20T13:25:14.588Z
- 任务状态：**REPORTING**
- 工作区：`D:\dsh-ABM\armorbreak`
- 目标：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample`
- 操作者：local-user
- 证据链：校验通过，150 条记录

## 1. 摘要

共 73 条发现：critical 16 · high 57 · medium 0 · low 0 · info 0。留档证据 150 条。

| # | 严重程度 | 标题 | 验证状态 | CWE | 位置 |
|---|---|---|---|---|---|
| 1 | critical | [semgrep] Dynamic eval() executes user-controlled code (CWE-95). | hypothesis | CWE-95 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:9 |
| 2 | critical | [semgrep] child_process.exec() with a concatenated command string allows command injection (CWE-78). | hypothesis | CWE-78 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:14 |
| 3 | critical | [trivy] CVE-2022-29078 in ejs | hypothesis | CWE-94 | package-lock.json (ejs) |
| 4 | critical | [trivy] CVE-2021-44906 in minimist | hypothesis | CWE-1321 | package-lock.json (minimist) |
| 5 | critical | [trivy] CVE-2026-59873 in tar | hypothesis | CWE-770 | package-lock.json (tar) |
| 6 | critical | [trivy] CVE-2019-14234 in Django | hypothesis | CWE-89 | requirements.txt (Django) |
| 7 | critical | [trivy] CVE-2019-19844 in Django | hypothesis | CWE-640 | requirements.txt (Django) |
| 8 | critical | [trivy] CVE-2020-7471 in Django | hypothesis | CWE-89 | requirements.txt (Django) |
| 9 | critical | [trivy] CVE-2022-28346 in Django | hypothesis | CWE-89 | requirements.txt (Django) |
| 10 | critical | [trivy] CVE-2022-28347 in Django | hypothesis | CWE-89 | requirements.txt (Django) |
| 11 | critical | [trivy] CVE-2025-64459 in Django | hypothesis | CWE-89 | requirements.txt (Django) |
| 12 | critical | [trivy] CVE-2019-20477 in PyYAML | hypothesis | CWE-502 | requirements.txt (PyYAML) |
| 13 | critical | [trivy] CVE-2020-14343 in PyYAML | hypothesis | CWE-20 | requirements.txt (PyYAML) |
| 14 | critical | [trivy] CVE-2020-1747 in PyYAML | hypothesis | CWE-20 | requirements.txt (PyYAML) |
| 15 | critical | [trivy] secret aws-access-key-id in src/config.js | hypothesis | - | src/config.js |
| 16 | critical | [trivy] secret github-pat in src/config.js | hypothesis | - | src/config.js |
| 17 | high | [semgrep] SQL query built by string concatenation allows SQL injection (CWE-89). | hypothesis | CWE-89 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:21 |
| 18 | high | [semgrep] Hardcoded AWS access key ID (CWE-798). | hypothesis | CWE-798 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:25 |
| 19 | high | [semgrep] Hardcoded AWS access key ID (CWE-798). | hypothesis | CWE-798 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\config.js:5 |
| 20 | high | [semgrep] MD5 is a weak hash and must not be used for security decisions (CWE-327). | hypothesis | CWE-327 | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\crypto.js:8 |
| 21 | high | [trivy] CVE-2021-3749 in axios | hypothesis | CWE-1333 | package-lock.json (axios) |
| 22 | high | [trivy] CVE-2025-27152 in axios | hypothesis | CWE-918 | package-lock.json (axios) |
| 23 | high | [trivy] CVE-2026-25639 in axios | hypothesis | CWE-754 | package-lock.json (axios) |
| 24 | high | [trivy] CVE-2026-42033 in axios | hypothesis | CWE-1321 | package-lock.json (axios) |
| 25 | high | [trivy] CVE-2026-42035 in axios | hypothesis | CWE-113 | package-lock.json (axios) |
| 26 | high | [trivy] CVE-2026-42043 in axios | hypothesis | CWE-183 | package-lock.json (axios) |
| 27 | high | [trivy] CVE-2026-44486 in axios | hypothesis | CWE-200 | package-lock.json (axios) |
| 28 | high | [trivy] CVE-2026-44487 in axios | hypothesis | CWE-201 | package-lock.json (axios) |
| 29 | high | [trivy] CVE-2026-44492 in axios | hypothesis | CWE-918 | package-lock.json (axios) |
| 30 | high | [trivy] CVE-2026-44495 in axios | hypothesis | CWE-94 | package-lock.json (axios) |
| 31 | high | [trivy] CVE-2026-44496 in axios | hypothesis | CWE-400 | package-lock.json (axios) |
| 32 | high | [trivy] CVE-2024-45590 in body-parser | hypothesis | CWE-405 | package-lock.json (body-parser) |
| 33 | high | [trivy] CVE-2022-23539 in jsonwebtoken | hypothesis | CWE-327 | package-lock.json (jsonwebtoken) |
| 34 | high | [trivy] CVE-2020-8203 in lodash | hypothesis | CWE-770 | package-lock.json (lodash) |
| 35 | high | [trivy] CVE-2021-23337 in lodash | hypothesis | CWE-94 | package-lock.json (lodash) |
| 36 | high | [trivy] CVE-2026-4800 in lodash | hypothesis | CWE-94 | package-lock.json (lodash) |
| 37 | high | [trivy] NSWG-ECO-516 in lodash | hypothesis | - | package-lock.json (lodash) |
| 38 | high | [trivy] CVE-2022-0235 in node-fetch | hypothesis | CWE-200 | package-lock.json (node-fetch) |
| 39 | high | [trivy] CVE-2024-45296 in path-to-regexp | hypothesis | CWE-1333 | package-lock.json (path-to-regexp) |
| 40 | high | [trivy] CVE-2024-52798 in path-to-regexp | hypothesis | CWE-1333 | package-lock.json (path-to-regexp) |
| 41 | high | [trivy] CVE-2026-4867 in path-to-regexp | hypothesis | CWE-1333 | package-lock.json (path-to-regexp) |
| 42 | high | [trivy] CVE-2022-24999 in qs | hypothesis | CWE-1321 | package-lock.json (qs) |
| 43 | high | [trivy] CVE-2021-32803 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 44 | high | [trivy] CVE-2021-32804 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 45 | high | [trivy] CVE-2021-37701 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 46 | high | [trivy] CVE-2021-37712 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 47 | high | [trivy] CVE-2021-37713 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 48 | high | [trivy] CVE-2026-23745 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 49 | high | [trivy] CVE-2026-23950 in tar | hypothesis | CWE-176 | package-lock.json (tar) |
| 50 | high | [trivy] CVE-2026-24842 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 51 | high | [trivy] CVE-2026-26960 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 52 | high | [trivy] CVE-2026-29786 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 53 | high | [trivy] CVE-2026-31802 in tar | hypothesis | CWE-22 | package-lock.json (tar) |
| 54 | high | [trivy] CVE-2026-59874 in tar | hypothesis | CWE-835 | package-lock.json (tar) |
| 55 | high | [trivy] CVE-2026-73566 in tar | hypothesis | CWE-400 | package-lock.json (tar) |
| 56 | high | [trivy] CVE-2019-14232 in Django | hypothesis | CWE-400 | requirements.txt (Django) |
| 57 | high | [trivy] CVE-2019-14233 in Django | hypothesis | CWE-400 | requirements.txt (Django) |
| 58 | high | [trivy] CVE-2019-14235 in Django | hypothesis | CWE-674 | requirements.txt (Django) |
| 59 | high | [trivy] CVE-2019-19118 in Django | hypothesis | CWE-276 | requirements.txt (Django) |
| 60 | high | [trivy] CVE-2020-13254 in Django | hypothesis | CWE-295 | requirements.txt (Django) |
| 61 | high | [trivy] CVE-2020-24583 in Django | hypothesis | CWE-276 | requirements.txt (Django) |
| 62 | high | [trivy] CVE-2020-9402 in Django | hypothesis | CWE-89 | requirements.txt (Django) |
| 63 | high | [trivy] CVE-2021-31542 in Django | hypothesis | CWE-22 | requirements.txt (Django) |
| 64 | high | [trivy] CVE-2021-33571 in Django | hypothesis | CWE-918 | requirements.txt (Django) |
| 65 | high | [trivy] CVE-2021-45115 in Django | hypothesis | - | requirements.txt (Django) |
| 66 | high | [trivy] CVE-2021-45116 in Django | hypothesis | CWE-20 | requirements.txt (Django) |
| 67 | high | [trivy] CVE-2022-23833 in Django | hypothesis | CWE-835 | requirements.txt (Django) |
| 68 | high | [trivy] CVE-2022-36359 in Django | hypothesis | CWE-494 | requirements.txt (Django) |
| 69 | high | [trivy] CVE-2025-57833 in Django | hypothesis | CWE-89 | requirements.txt (Django) |
| 70 | high | [trivy] CVE-2025-64458 in Django | hypothesis | CWE-407 | requirements.txt (Django) |
| 71 | high | [trivy] CVE-2026-15307 in Django | hypothesis | CWE-73 | requirements.txt (Django) |
| 72 | high | [trivy] CVE-2019-10906 in Jinja2 | hypothesis | - | requirements.txt (Jinja2) |
| 73 | high | [trivy] CVE-2018-18074 in requests | hypothesis | CWE-522 | requirements.txt (requests) |

## 2. 授权与范围

- 本任务未使用跨工作区授权；分析限制在任务工作区内。

## 3. 任务与工作流

- 风险上限：L0
- 状态轨迹：CREATED(2026-10-20T13:25:09.667Z) → SCOPE_VALIDATION(2026-10-20T13:25:09.679Z) → ENVIRONMENT_CHECK(2026-10-20T13:25:09.685Z) → PLANNING(2026-10-20T13:25:09.691Z) → EXECUTING(2026-10-20T13:25:09.696Z) → COLLECTING_EVIDENCE(2026-10-20T13:25:12.997Z) → EXECUTING(2026-10-20T13:25:13.002Z) → COLLECTING_EVIDENCE(2026-10-20T13:25:14.157Z) → VERIFYING(2026-10-20T13:25:14.161Z) → REPORTING(2026-10-20T13:25:14.175Z)

| 步骤 | 能力 | 状态 | 耗时 | 摘要 |
|---|---|---|---|---|
| semgrep | sast.semgrep | DONE | 3285 ms | Semgrep（1.181.0）扫描 D:\dsh-ABM\armorbreak\fixtures\gate-b-sample：6 条结果，归一化 6 条 findings（全部 hypothesis） |
| trivy | sast.trivy | DONE | 1141 ms | Trivy 扫描 D:\dsh-ABM\armorbreak\fixtures\gate-b-sample：3 个结果集，归一化 67 条 findings（scanners=vuln,secret, severity=HIGH,CRITICAL，全部 hypothesis） |

## 4. 发现

### 4.1 [semgrep] Dynamic eval() executes user-controlled code (CWE-95).

- 编号：`fnd_mvgpu15o_a00d1ac4`
- 严重程度：**critical**（评分依据：严重程度映射 9.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-95 — https://cwe.mitre.org/data/definitions/95.html
- 检测方法：semgrep rule match (static pattern; no data-flow validation)
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:9`

**说明**：Dynamic eval() executes user-controlled code (CWE-95).

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Review the rule match against the actual data flow; do not report as a confirmed vulnerability without independent evidence.

**证据**：`ev_mvgpu15k_f2443a26`, `ev_mvgpu14h_d6bef425`

### 4.2 [semgrep] child_process.exec() with a concatenated command string allows command injection (CWE-78).

- 编号：`fnd_mvgpu15z_24066b8c`
- 严重程度：**critical**（评分依据：严重程度映射 9.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-78 — https://cwe.mitre.org/data/definitions/78.html
- 检测方法：semgrep rule match (static pattern; no data-flow validation)
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:14`

**说明**：child_process.exec() with a concatenated command string allows command injection (CWE-78).

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Review the rule match against the actual data flow; do not report as a confirmed vulnerability without independent evidence.

**证据**：`ev_mvgpu15t_34a7b0d4`, `ev_mvgpu14h_d6bef425`

### 4.3 [trivy] CVE-2022-29078 in ejs

- 编号：`fnd_mvgpu1ox_31843a09`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-94 — https://cwe.mitre.org/data/definitions/94.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (ejs)`

**说明**：ejs: server-side template injection in outputFunctionName

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade ejs to 3.1.7

**证据**：`ev_mvgpu1os_14527108`, `ev_mvgpu1d6_179a4ae9`

### 4.4 [trivy] CVE-2021-44906 in minimist

- 编号：`fnd_mvgpu1qm_30636a7f`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1321 — https://cwe.mitre.org/data/definitions/1321.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (minimist)`

**说明**：minimist: prototype pollution

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade minimist to 1.2.6, 0.2.4

**证据**：`ev_mvgpu1qh_628485a7`, `ev_mvgpu1d6_179a4ae9`

### 4.5 [trivy] CVE-2026-59873 in tar

- 编号：`fnd_mvgpu1sa_d0a96d01`
- 严重程度：**critical**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-770 — https://cwe.mitre.org/data/definitions/770.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：tar: node-tar: Denial of Service via crafted gzip bomb

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.19

**证据**：`ev_mvgpu1s5_df3d52c9`, `ev_mvgpu1d6_179a4ae9`

### 4.6 [trivy] CVE-2019-14234 in Django

- 编号：`fnd_mvgpu1w4_aaf1b018`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: SQL injection possibility in key and index lookups for JSONField/HStoreField

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade Django to 1.11.23, 2.1.11, 2.2.4

**证据**：`ev_mvgpu1vz_478ecbf0`, `ev_mvgpu1d6_179a4ae9`

### 4.7 [trivy] CVE-2019-19844 in Django

- 编号：`fnd_mvgpu1we_9bf6b921`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-640 — https://cwe.mitre.org/data/definitions/640.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: crafted email address allows account takeover

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade Django to 1.11.27, 2.2.9, 3.0.1

**证据**：`ev_mvgpu1w9_10addccc`, `ev_mvgpu1d6_179a4ae9`

### 4.8 [trivy] CVE-2020-7471 in Django

- 编号：`fnd_mvgpu1wo_38295916`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: potential SQL injection via StringAgg(delimiter)

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade Django to 1.11.28, 2.2.10, 3.0.3

**证据**：`ev_mvgpu1wj_8b3aa517`, `ev_mvgpu1d6_179a4ae9`

### 4.9 [trivy] CVE-2022-28346 in Django

- 编号：`fnd_mvgpu1wy_725a32ca`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: SQL injection in QuerySet.annotate(),aggregate() and extra()

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.28, 3.2.13, 4.0.4

**证据**：`ev_mvgpu1wt_6ba38e71`, `ev_mvgpu1d6_179a4ae9`

### 4.10 [trivy] CVE-2022-28347 in Django

- 编号：`fnd_mvgpu1x9_b77fe962`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: SQL injection via QuerySet.explain(options) on PostgreSQL

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.28, 3.2.13, 4.0.4

**证据**：`ev_mvgpu1x4_0a0fa2f4`, `ev_mvgpu1d6_179a4ae9`

### 4.11 [trivy] CVE-2025-64459 in Django

- 编号：`fnd_mvgpu1xk_02be882e`
- 严重程度：**critical**（评分依据：CVSS 8.3）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Django SQL injection

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade Django to 5.2.8, 5.1.14, 4.2.26

**证据**：`ev_mvgpu1xf_de743127`, `ev_mvgpu1d6_179a4ae9`

### 4.12 [trivy] CVE-2019-20477 in PyYAML

- 编号：`fnd_mvgpu224_9120b179`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-502 — https://cwe.mitre.org/data/definitions/502.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (PyYAML)`

**说明**：PyYAML: command execution through python/object/apply constructor in FullLoader

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade PyYAML to 5.2

**证据**：`ev_mvgpu220_f9a837a8`, `ev_mvgpu1d6_179a4ae9`

### 4.13 [trivy] CVE-2020-14343 in PyYAML

- 编号：`fnd_mvgpu22e_e82811f3`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-20 — https://cwe.mitre.org/data/definitions/20.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (PyYAML)`

**说明**：PyYAML: incomplete fix for CVE-2020-1747

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade PyYAML to 5.4

**证据**：`ev_mvgpu229_e38d2c55`, `ev_mvgpu1d6_179a4ae9`

### 4.14 [trivy] CVE-2020-1747 in PyYAML

- 编号：`fnd_mvgpu22m_ea4c045a`
- 严重程度：**critical**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-20 — https://cwe.mitre.org/data/definitions/20.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (PyYAML)`

**说明**：PyYAML: arbitrary command execution through python/object/new when FullLoader is used

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Upgrade PyYAML to 5.3.1

**证据**：`ev_mvgpu22i_9ace5922`, `ev_mvgpu1d6_179a4ae9`

### 4.15 [trivy] secret aws-access-key-id in src/config.js

- 编号：`fnd_mvgpu235_ed1b087e`
- 严重程度：**critical**（评分依据：严重程度映射 9.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：未映射
- 检测方法：trivy secret pattern match (may be a test fixture or example)
- 定位：`src/config.js`

**说明**：AWS Access Key ID

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Confirm the value is a live credential; rotate it if so. Ignore documented test/example values.

**证据**：`ev_mvgpu230_be8b2e63`, `ev_mvgpu1d6_179a4ae9`

### 4.16 [trivy] secret github-pat in src/config.js

- 编号：`fnd_mvgpu23c_42e4088d`
- 严重程度：**critical**（评分依据：严重程度映射 9.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：未映射
- 检测方法：trivy secret pattern match (may be a test fixture or example)
- 定位：`src/config.js`

**说明**：GitHub Personal Access Token

**影响**：基于 critical 级别的影响评估

**修复/复核建议**：Confirm the value is a live credential; rotate it if so. Ignore documented test/example values.

**证据**：`ev_mvgpu239_5fc20afd`, `ev_mvgpu1d6_179a4ae9`

### 4.17 [semgrep] SQL query built by string concatenation allows SQL injection (CWE-89).

- 编号：`fnd_mvgpu168_b5b1cf32`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：semgrep rule match (static pattern; no data-flow validation)
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:21`

**说明**：SQL query built by string concatenation allows SQL injection (CWE-89).

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Review the rule match against the actual data flow; do not report as a confirmed vulnerability without independent evidence.

**证据**：`ev_mvgpu164_68ee2725`, `ev_mvgpu14h_d6bef425`

### 4.18 [semgrep] Hardcoded AWS access key ID (CWE-798).

- 编号：`fnd_mvgpu16j_a63bf746`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-798 — https://cwe.mitre.org/data/definitions/798.html
- 检测方法：semgrep rule match (static pattern; no data-flow validation)
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:25`

**说明**：Hardcoded AWS access key ID (CWE-798).

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Review the rule match against the actual data flow; do not report as a confirmed vulnerability without independent evidence.

**证据**：`ev_mvgpu16e_e453fa50`, `ev_mvgpu14h_d6bef425`

### 4.19 [semgrep] Hardcoded AWS access key ID (CWE-798).

- 编号：`fnd_mvgpu16u_07cd1664`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-798 — https://cwe.mitre.org/data/definitions/798.html
- 检测方法：semgrep rule match (static pattern; no data-flow validation)
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\config.js:5`

**说明**：Hardcoded AWS access key ID (CWE-798).

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Review the rule match against the actual data flow; do not report as a confirmed vulnerability without independent evidence.

**证据**：`ev_mvgpu16p_cbc8c7eb`, `ev_mvgpu14h_d6bef425`

### 4.20 [semgrep] MD5 is a weak hash and must not be used for security decisions (CWE-327).

- 编号：`fnd_mvgpu173_9cf9047f`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-327 — https://cwe.mitre.org/data/definitions/327.html
- 检测方法：semgrep rule match (static pattern; no data-flow validation)
- 定位：`D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\crypto.js:8`

**说明**：MD5 is a weak hash and must not be used for security decisions (CWE-327).

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Review the rule match against the actual data flow; do not report as a confirmed vulnerability without independent evidence.

**证据**：`ev_mvgpu16z_4e132af8`, `ev_mvgpu14h_d6bef425`

### 4.21 [trivy] CVE-2021-3749 in axios

- 编号：`fnd_mvgpu1lo_8604af25`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1333 — https://cwe.mitre.org/data/definitions/1333.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：nodejs-axios: Regular expression denial of service in trim function

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 0.21.2

**证据**：`ev_mvgpu1lk_bd5ea7df`, `ev_mvgpu1d6_179a4ae9`

### 4.22 [trivy] CVE-2025-27152 in axios

- 编号：`fnd_mvgpu1ly_dbc761a7`
- 严重程度：**high**（评分依据：CVSS 5.3）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-918 — https://cwe.mitre.org/data/definitions/918.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Possible SSRF and Credential Leakage via Absolute URL in axios Requests

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.8.2, 0.30.0

**证据**：`ev_mvgpu1lt_af09ee2f`, `ev_mvgpu1d6_179a4ae9`

### 4.23 [trivy] CVE-2026-25639 in axios

- 编号：`fnd_mvgpu1m7_812cec37`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-754 — https://cwe.mitre.org/data/definitions/754.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios affected by Denial of Service via __proto__ Key in mergeConfig

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.13.5, 0.30.3

**证据**：`ev_mvgpu1m3_84a83411`, `ev_mvgpu1d6_179a4ae9`

### 4.24 [trivy] CVE-2026-42033 in axios

- 编号：`fnd_mvgpu1mh_4db6b72b`
- 严重程度：**high**（评分依据：CVSS 7.4）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1321 — https://cwe.mitre.org/data/definitions/1321.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: HTTP Transport Hijacking via Prototype Pollution

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.15.1, 0.31.1

**证据**：`ev_mvgpu1md_b23b08a9`, `ev_mvgpu1d6_179a4ae9`

### 4.25 [trivy] CVE-2026-42035 in axios

- 编号：`fnd_mvgpu1mq_5a16e73c`
- 严重程度：**high**（评分依据：CVSS 7.4）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-113 — https://cwe.mitre.org/data/definitions/113.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: Arbitrary HTTP header injection via prototype pollution

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.15.1, 0.31.1

**证据**：`ev_mvgpu1mm_7f968a6d`, `ev_mvgpu1d6_179a4ae9`

### 4.26 [trivy] CVE-2026-42043 in axios

- 编号：`fnd_mvgpu1mz_0c77e187`
- 严重程度：**high**（评分依据：CVSS 10）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-183 — https://cwe.mitre.org/data/definitions/183.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: NO_PROXY bypass via crafted URL

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.15.1, 0.31.1

**证据**：`ev_mvgpu1mv_a58f7fcb`, `ev_mvgpu1d6_179a4ae9`

### 4.27 [trivy] CVE-2026-44486 in axios

- 编号：`fnd_mvgpu1n9_95e6785b`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-200 — https://cwe.mitre.org/data/definitions/200.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: Information disclosure of proxy credentials via HTTP redirects

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.16.0, 0.32.0

**证据**：`ev_mvgpu1n5_c56bf238`, `ev_mvgpu1d6_179a4ae9`

### 4.28 [trivy] CVE-2026-44487 in axios

- 编号：`fnd_mvgpu1nj_bfca1c1e`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-201 — https://cwe.mitre.org/data/definitions/201.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: Information disclosure of proxy credentials via redirect flows

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.16.0, 0.32.0

**证据**：`ev_mvgpu1ne_01545826`, `ev_mvgpu1d6_179a4ae9`

### 4.29 [trivy] CVE-2026-44492 in axios

- 编号：`fnd_mvgpu1ns_8a98b87c`
- 严重程度：**high**（评分依据：CVSS 8.6）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-918 — https://cwe.mitre.org/data/definitions/918.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: Proxy bypass via IPv4-mapped IPv6 address non-normalization

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.16.0, 0.32.0

**证据**：`ev_mvgpu1no_fb8b8aa1`, `ev_mvgpu1d6_179a4ae9`

### 4.30 [trivy] CVE-2026-44495 in axios

- 编号：`fnd_mvgpu1o2_d60c1366`
- 严重程度：**high**（评分依据：CVSS 7.7）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-94 — https://cwe.mitre.org/data/definitions/94.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: Information disclosure due to prototype pollution vulnerability

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.15.2, 0.31.1

**证据**：`ev_mvgpu1ny_884ef7f0`, `ev_mvgpu1d6_179a4ae9`

### 4.31 [trivy] CVE-2026-44496 in axios

- 编号：`fnd_mvgpu1oc_3dd629ce`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-400 — https://cwe.mitre.org/data/definitions/400.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (axios)`

**说明**：axios: Axios: Client-side Denial of Service via unescaped regex metacharacters in XSRF cookie name

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade axios to 1.16.0, 0.32.0

**证据**：`ev_mvgpu1o8_c2a79bc9`, `ev_mvgpu1d6_179a4ae9`

### 4.32 [trivy] CVE-2024-45590 in body-parser

- 编号：`fnd_mvgpu1om_41252eea`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-405 — https://cwe.mitre.org/data/definitions/405.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (body-parser)`

**说明**：body-parser: Denial of Service Vulnerability in body-parser

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade body-parser to 1.20.3

**证据**：`ev_mvgpu1oi_d012ce93`, `ev_mvgpu1d6_179a4ae9`

### 4.33 [trivy] CVE-2022-23539 in jsonwebtoken

- 编号：`fnd_mvgpu1p7_a5da0087`
- 严重程度：**high**（评分依据：CVSS 8.1）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-327 — https://cwe.mitre.org/data/definitions/327.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (jsonwebtoken)`

**说明**：jsonwebtoken: Unrestricted key type could lead to legacy keys usagen

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade jsonwebtoken to 9.0.0

**证据**：`ev_mvgpu1p2_83a671cf`, `ev_mvgpu1d6_179a4ae9`

### 4.34 [trivy] CVE-2020-8203 in lodash

- 编号：`fnd_mvgpu1pg_24600351`
- 严重程度：**high**（评分依据：CVSS 7.4）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-770 — https://cwe.mitre.org/data/definitions/770.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (lodash)`

**说明**：nodejs-lodash: prototype pollution in zipObjectDeep function

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade lodash to 4.17.19

**证据**：`ev_mvgpu1pc_684fc366`, `ev_mvgpu1d6_179a4ae9`

### 4.35 [trivy] CVE-2021-23337 in lodash

- 编号：`fnd_mvgpu1pq_4d05e6dc`
- 严重程度：**high**（评分依据：CVSS 7.2）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-94 — https://cwe.mitre.org/data/definitions/94.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (lodash)`

**说明**：nodejs-lodash: command injection via template

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade lodash to 4.17.21

**证据**：`ev_mvgpu1pm_a41c2223`, `ev_mvgpu1d6_179a4ae9`

### 4.36 [trivy] CVE-2026-4800 in lodash

- 编号：`fnd_mvgpu1q1_72ac94f0`
- 严重程度：**high**（评分依据：CVSS 9.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-94 — https://cwe.mitre.org/data/definitions/94.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (lodash)`

**说明**：lodash: lodash: Arbitrary code execution via untrusted input in template imports

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade lodash to 4.18.0

**证据**：`ev_mvgpu1pw_f3540a3a`, `ev_mvgpu1d6_179a4ae9`

### 4.37 [trivy] NSWG-ECO-516 in lodash

- 编号：`fnd_mvgpu1qb_2d4b7aac`
- 严重程度：**high**（评分依据：严重程度映射 8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：未映射
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (lodash)`

**说明**：Allocation of Resources Without Limits or Throttling

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade lodash to >=4.17.19

**证据**：`ev_mvgpu1q7_72425433`, `ev_mvgpu1d6_179a4ae9`

### 4.38 [trivy] CVE-2022-0235 in node-fetch

- 编号：`fnd_mvgpu1qw_bb403702`
- 严重程度：**high**（评分依据：CVSS 6.1）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-200 — https://cwe.mitre.org/data/definitions/200.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (node-fetch)`

**说明**：node-fetch: exposure of sensitive information to an unauthorized actor

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade node-fetch to 3.1.1, 2.6.7

**证据**：`ev_mvgpu1qr_c1c03438`, `ev_mvgpu1d6_179a4ae9`

### 4.39 [trivy] CVE-2024-45296 in path-to-regexp

- 编号：`fnd_mvgpu1r5_570d216b`
- 严重程度：**high**（评分依据：CVSS 5.3）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1333 — https://cwe.mitre.org/data/definitions/1333.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (path-to-regexp)`

**说明**：path-to-regexp: Backtracking regular expressions cause ReDoS

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade path-to-regexp to 1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0

**证据**：`ev_mvgpu1r1_dd3a32a1`, `ev_mvgpu1d6_179a4ae9`

### 4.40 [trivy] CVE-2024-52798 in path-to-regexp

- 编号：`fnd_mvgpu1rg_fb91d9f4`
- 严重程度：**high**（评分依据：CVSS 5.3）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1333 — https://cwe.mitre.org/data/definitions/1333.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (path-to-regexp)`

**说明**：path-to-regexp: path-to-regexp Unpatched `path-to-regexp` ReDoS in 0.1.x

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade path-to-regexp to 0.1.12

**证据**：`ev_mvgpu1rb_9fcb7ac0`, `ev_mvgpu1d6_179a4ae9`

### 4.41 [trivy] CVE-2026-4867 in path-to-regexp

- 编号：`fnd_mvgpu1rq_1bdc95d6`
- 严重程度：**high**（评分依据：CVSS 5.3）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1333 — https://cwe.mitre.org/data/definitions/1333.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (path-to-regexp)`

**说明**：path-to-regexp: path-to-regexp: Denial of Service via catastrophic backtracking from malformed URL parameters

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade path-to-regexp to 0.1.13

**证据**：`ev_mvgpu1rl_1b525f44`, `ev_mvgpu1d6_179a4ae9`

### 4.42 [trivy] CVE-2022-24999 in qs

- 编号：`fnd_mvgpu1s0_f891e410`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-1321 — https://cwe.mitre.org/data/definitions/1321.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (qs)`

**说明**：express: "qs" prototype poisoning causes the hang of the node process

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade qs to 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4

**证据**：`ev_mvgpu1rv_765b9517`, `ev_mvgpu1d6_179a4ae9`

### 4.43 [trivy] CVE-2021-32803 in tar

- 编号：`fnd_mvgpu1sk_b1809cee`
- 严重程度：**high**（评分依据：CVSS 8.1）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：nodejs-tar: Insufficient symlink protection allowing arbitrary file creation and overwrite

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 3.2.3, 4.4.15, 5.0.7, 6.1.2

**证据**：`ev_mvgpu1sf_93ca166a`, `ev_mvgpu1d6_179a4ae9`

### 4.44 [trivy] CVE-2021-32804 in tar

- 编号：`fnd_mvgpu1st_a5ad6e06`
- 严重程度：**high**（评分依据：CVSS 8.1）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：nodejs-tar: Insufficient absolute path sanitization allowing arbitrary file creation and overwrite

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 3.2.2, 4.4.14, 5.0.6, 6.1.1

**证据**：`ev_mvgpu1sp_cc1b1a66`, `ev_mvgpu1d6_179a4ae9`

### 4.45 [trivy] CVE-2021-37701 in tar

- 编号：`fnd_mvgpu1t3_e08aaea0`
- 严重程度：**high**（评分依据：CVSS 8.6）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：nodejs-tar: Insufficient symlink protection due to directory cache poisoning using symbolic links allowing arbitrary file creation and overwrite

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 4.4.16, 5.0.8, 6.1.7

**证据**：`ev_mvgpu1sy_53afe874`, `ev_mvgpu1d6_179a4ae9`

### 4.46 [trivy] CVE-2021-37712 in tar

- 编号：`fnd_mvgpu1td_2366402a`
- 严重程度：**high**（评分依据：CVSS 8.6）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：nodejs-tar: Insufficient symlink protection due to directory cache poisoning using symbolic links allowing arbitrary file creation and overwrite

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 4.4.18, 5.0.10, 6.1.9

**证据**：`ev_mvgpu1t9_b0fcdd58`, `ev_mvgpu1d6_179a4ae9`

### 4.47 [trivy] CVE-2021-37713 in tar

- 编号：`fnd_mvgpu1tn_79ead8b5`
- 严重程度：**high**（评分依据：CVSS 8.6）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：nodejs-tar: Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 4.4.18, 5.0.10, 6.1.9

**证据**：`ev_mvgpu1tj_f42e831e`, `ev_mvgpu1d6_179a4ae9`

### 4.48 [trivy] CVE-2026-23745 in tar

- 编号：`fnd_mvgpu1tx_6430c2ba`
- 严重程度：**high**（评分依据：CVSS 6.1）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：node-tar: tar: node-tar: Arbitrary file overwrite and symlink poisoning via unsanitized linkpaths in archives

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.3

**证据**：`ev_mvgpu1tt_3da73604`, `ev_mvgpu1d6_179a4ae9`

### 4.49 [trivy] CVE-2026-23950 in tar

- 编号：`fnd_mvgpu1u7_7dbe0703`
- 严重程度：**high**（评分依据：CVSS 5.9）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-176 — https://cwe.mitre.org/data/definitions/176.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：node-tar: tar: node-tar: Arbitrary file overwrite via Unicode path collision race condition

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.4

**证据**：`ev_mvgpu1u3_e6a03877`, `ev_mvgpu1d6_179a4ae9`

### 4.50 [trivy] CVE-2026-24842 in tar

- 编号：`fnd_mvgpu1ui_670b5147`
- 严重程度：**high**（评分依据：CVSS 8.2）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：node-tar: tar: node-tar: Arbitrary file creation via path traversal bypass in hardlink security check

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.7

**证据**：`ev_mvgpu1ud_381a6aed`, `ev_mvgpu1d6_179a4ae9`

### 4.51 [trivy] CVE-2026-26960 in tar

- 编号：`fnd_mvgpu1us_80f40e77`
- 严重程度：**high**（评分依据：CVSS 7.1）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：node-tar: node-tar: Arbitrary file read/write via malicious archive hardlink creation

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.8

**证据**：`ev_mvgpu1un_dd58f4e5`, `ev_mvgpu1d6_179a4ae9`

### 4.52 [trivy] CVE-2026-29786 in tar

- 编号：`fnd_mvgpu1v2_40029811`
- 严重程度：**high**（评分依据：CVSS 6.3）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：node-tar: hardlink path traversal via drive-relative linkpath

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.10

**证据**：`ev_mvgpu1ux_e084b4e7`, `ev_mvgpu1d6_179a4ae9`

### 4.53 [trivy] CVE-2026-31802 in tar

- 编号：`fnd_mvgpu1vc_8742458b`
- 严重程度：**high**（评分依据：CVSS 5.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：tar: tar: File overwrite via drive-relative symlink traversal

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.11

**证据**：`ev_mvgpu1v7_de998830`, `ev_mvgpu1d6_179a4ae9`

### 4.54 [trivy] CVE-2026-59874 in tar

- 编号：`fnd_mvgpu1vl_fe6f87da`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-835 — https://cwe.mitre.org/data/definitions/835.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：tar: Node-tar: Denial of Service via malformed tar archive header

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.18

**证据**：`ev_mvgpu1vh_88e902e8`, `ev_mvgpu1d6_179a4ae9`

### 4.55 [trivy] CVE-2026-73566 in tar

- 编号：`fnd_mvgpu1vu_81690038`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-400 — https://cwe.mitre.org/data/definitions/400.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`package-lock.json (tar)`

**说明**：tar: node-tar: Denial of Service via crafted long-path tar archive

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade tar to 7.5.21

**证据**：`ev_mvgpu1vq_64edad04`, `ev_mvgpu1d6_179a4ae9`

### 4.56 [trivy] CVE-2019-14232 in Django

- 编号：`fnd_mvgpu1xt_2e468c37`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-400 — https://cwe.mitre.org/data/definitions/400.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: backtracking in a regular expression in django.utils.text.Truncator leads to DoS

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 1.11.23, 2.1.11, 2.2.4

**证据**：`ev_mvgpu1xp_9f05b68d`, `ev_mvgpu1d6_179a4ae9`

### 4.57 [trivy] CVE-2019-14233 in Django

- 编号：`fnd_mvgpu1y3_09d9acea`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-400 — https://cwe.mitre.org/data/definitions/400.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: the behavior of the underlying HTMLParser leading to DoS

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 1.11.23, 2.1.11, 2.2.4

**证据**：`ev_mvgpu1xz_14075573`, `ev_mvgpu1d6_179a4ae9`

### 4.58 [trivy] CVE-2019-14235 in Django

- 编号：`fnd_mvgpu1ye_f1baf85e`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-674 — https://cwe.mitre.org/data/definitions/674.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: Potential memory exhaustion in django.utils.encoding.uri_to_iri()

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 1.11.23, 2.1.11, 2.2.4

**证据**：`ev_mvgpu1y9_5fd498f8`, `ev_mvgpu1d6_179a4ae9`

### 4.59 [trivy] CVE-2019-19118 in Django

- 编号：`fnd_mvgpu1yn_bf584c24`
- 严重程度：**high**（评分依据：CVSS 6.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-276 — https://cwe.mitre.org/data/definitions/276.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: privilege escalation in the django admin

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.1.15, 2.2.8

**证据**：`ev_mvgpu1yj_a871bdce`, `ev_mvgpu1d6_179a4ae9`

### 4.60 [trivy] CVE-2020-13254 in Django

- 编号：`fnd_mvgpu1yx_f116fc43`
- 严重程度：**high**（评分依据：CVSS 5.9）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-295 — https://cwe.mitre.org/data/definitions/295.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: potential data leakage via malformed memcached keys

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.13, 3.0.7

**证据**：`ev_mvgpu1yt_8b0ba49e`, `ev_mvgpu1d6_179a4ae9`

### 4.61 [trivy] CVE-2020-24583 in Django

- 编号：`fnd_mvgpu1z7_2728b2d0`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-276 — https://cwe.mitre.org/data/definitions/276.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: incorrect permissions on intermediate-level directories on Python 3.7+

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.16, 3.0.10, 3.1.1

**证据**：`ev_mvgpu1z2_3519e8ed`, `ev_mvgpu1d6_179a4ae9`

### 4.62 [trivy] CVE-2020-9402 in Django

- 编号：`fnd_mvgpu1zh_8acceeef`
- 严重程度：**high**（评分依据：CVSS 8.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: potential SQL injection via "tolerance" parameter in GIS functions and aggregates on Oracle

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 1.11.29, 2.2.11, 3.0.4

**证据**：`ev_mvgpu1zd_8a23658b`, `ev_mvgpu1d6_179a4ae9`

### 4.63 [trivy] CVE-2021-31542 in Django

- 编号：`fnd_mvgpu1zr_437024a7`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-22 — https://cwe.mitre.org/data/definitions/22.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Potential directory-traversal via uploaded files

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.21, 3.1.9, 3.2.1

**证据**：`ev_mvgpu1zm_a9d6d302`, `ev_mvgpu1d6_179a4ae9`

### 4.64 [trivy] CVE-2021-33571 in Django

- 编号：`fnd_mvgpu201_67df97d4`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-918 — https://cwe.mitre.org/data/definitions/918.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Possible indeterminate SSRF, RFI, and LFI attacks since validators accepted leading zeros in IPv4 addresses

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.24, 3.1.12, 3.2.4

**证据**：`ev_mvgpu1zw_e54a5bf2`, `ev_mvgpu1d6_179a4ae9`

### 4.65 [trivy] CVE-2021-45115 in Django

- 编号：`fnd_mvgpu20a_185b9350`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：未映射
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Denial-of-service possibility in UserAttributeSimilarityValidator

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.26, 3.2.11, 4.0.1

**证据**：`ev_mvgpu206_5df084e0`, `ev_mvgpu1d6_179a4ae9`

### 4.66 [trivy] CVE-2021-45116 in Django

- 编号：`fnd_mvgpu20i_09498b7b`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-20 — https://cwe.mitre.org/data/definitions/20.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Potential information disclosure in dictsort template filter

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.26, 3.2.11, 4.0.1

**证据**：`ev_mvgpu20f_0a3e7b6b`, `ev_mvgpu1d6_179a4ae9`

### 4.67 [trivy] CVE-2022-23833 in Django

- 编号：`fnd_mvgpu20q_51f6ffd3`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-835 — https://cwe.mitre.org/data/definitions/835.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Denial-of-service possibility in file uploads

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 2.2.27, 3.2.12, 4.0.2

**证据**：`ev_mvgpu20m_181173ab`, `ev_mvgpu1d6_179a4ae9`

### 4.68 [trivy] CVE-2022-36359 in Django

- 编号：`fnd_mvgpu20y_0fcb2ffa`
- 严重程度：**high**（评分依据：CVSS 8.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-494 — https://cwe.mitre.org/data/definitions/494.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：An issue was discovered in the HTTP FileResponse class in Django 3.2 b ...

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 3.2.15, 4.0.7

**证据**：`ev_mvgpu20u_b0da21f8`, `ev_mvgpu1d6_179a4ae9`

### 4.69 [trivy] CVE-2025-57833 in Django

- 编号：`fnd_mvgpu216_42d6bdc6`
- 严重程度：**high**（评分依据：CVSS 8.1）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-89 — https://cwe.mitre.org/data/definitions/89.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Django SQL injection in FilteredRelation column aliases

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 4.2.24, 5.1.12, 5.2.6

**证据**：`ev_mvgpu212_ce5d455a`, `ev_mvgpu1d6_179a4ae9`

### 4.70 [trivy] CVE-2025-64458 in Django

- 编号：`fnd_mvgpu21g_006caa5d`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-407 — https://cwe.mitre.org/data/definitions/407.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：Django: Denial-of-service vulnerability in Django on Windows

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 5.2.8, 5.1.14, 4.2.26

**证据**：`ev_mvgpu21c_93190ed5`, `ev_mvgpu1d6_179a4ae9`

### 4.71 [trivy] CVE-2026-15307 in Django

- 编号：`fnd_mvgpu21o_1d77b62b`
- 严重程度：**high**（评分依据：CVSS 8.8）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-73 — https://cwe.mitre.org/data/definitions/73.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Django)`

**说明**：django: Django: Remote code execution via GeoDjango spatial lookups

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Django to 5.2.17, 6.0.8

**证据**：`ev_mvgpu21l_f6c45c9c`, `ev_mvgpu1d6_179a4ae9`

### 4.72 [trivy] CVE-2019-10906 in Jinja2

- 编号：`fnd_mvgpu21w_853bd305`
- 严重程度：**high**（评分依据：CVSS 8.6）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：未映射
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (Jinja2)`

**说明**：python-jinja2: str.format_map allows sandbox escape

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade Jinja2 to 2.10.1

**证据**：`ev_mvgpu21t_22073ac1`, `ev_mvgpu1d6_179a4ae9`

### 4.73 [trivy] CVE-2018-18074 in requests

- 编号：`fnd_mvgpu22v_089f285c`
- 严重程度：**high**（评分依据：CVSS 7.5）
- 验证状态：**hypothesis**（observed=直接观测；corroborated=多源印证；hypothesis=假设；unverified=未验证）
- CWE：CWE-522 — https://cwe.mitre.org/data/definitions/522.html
- 检测方法：trivy vulnerability DB match (version range; no exploit validation)
- 定位：`requirements.txt (requests)`

**说明**：python-requests: Redirect from HTTPS to HTTP does not remove Authorization header

**影响**：基于 high 级别的影响评估

**修复/复核建议**：Upgrade requests to 2.20.0

**证据**：`ev_mvgpu22q_b5f7ecdc`, `ev_mvgpu1d6_179a4ae9`

## 5. 证据附录

| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |
|---|---|---|---|---|---|
| 1 | `ev_mvgpu14h_d6bef425` | execution | sast.semgrep | - | Semgrep（1.181.0）扫描 D:\dsh-ABM\armorbreak\fixtures\gate-b-sample：6 条结果，归一化 6 条 findings（全部 hypothesis） |
| 2 | `ev_mvgpu14n_ed46bd4b` | external-tool | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:9-9 severity=ERROR message=Dynamic eval() executes user-controlled code (CWE-95). |
| 3 | `ev_mvgpu14s_32b2a308` | external-tool | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:14-16 severity=ERROR message=child_process.exec() with a concatenated command string allows command injection (CWE-78). |
| 4 | `ev_mvgpu14w_487a2657` | external-tool | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:21-21 severity=WARNING message=SQL query built by string concatenation allows SQL injection (CWE-89). |
| 5 | `ev_mvgpu151_d5fd294b` | external-tool | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:25-25 severity=WARNING message=Hardcoded AWS access key ID (CWE-798). |
| 6 | `ev_mvgpu155_ff55cf06` | external-tool | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\config.js:5-5 severity=WARNING message=Hardcoded AWS access key ID (CWE-798). |
| 7 | `ev_mvgpu15a_bb633453` | external-tool | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\crypto.js:8-8 severity=WARNING message=MD5 is a weak hash and must not be used for security decisions (CWE-327). |
| 8 | `ev_mvgpu15f_678013f8` | external-tool | sast.semgrep | - | command=semgrep scan --json --config D:\dsh-ABM\armorbreak\fixtures\gate-b-rules\armorbreak-local.yml D:\dsh-ABM\armorbreak\fixtures\gate-b-sample sha256(stdout)=93e4ffe64935bc5f968562c8573b87e3931b36e14596f3b0035137eee8fa00c2 |
| 9 | `ev_mvgpu15k_f2443a26` | finding-evidence | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:9 requires login |
| 10 | `ev_mvgpu15t_34a7b0d4` | finding-evidence | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:14 requires login |
| 11 | `ev_mvgpu164_68ee2725` | finding-evidence | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:21 requires login |
| 12 | `ev_mvgpu16e_e453fa50` | finding-evidence | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\app.js:25 requires login |
| 13 | `ev_mvgpu16p_cbc8c7eb` | finding-evidence | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\config.js:5 requires login |
| 14 | `ev_mvgpu16z_4e132af8` | finding-evidence | sast.semgrep | - | D:\dsh-ABM\armorbreak\fixtures\gate-b-sample\src\crypto.js:8 requires login |
| 15 | `ev_mvgpu1d6_179a4ae9` | execution | sast.trivy | - | Trivy 扫描 D:\dsh-ABM\armorbreak\fixtures\gate-b-sample：3 个结果集，归一化 67 条 findings（scanners=vuln,secret, severity=HIGH,CRITICAL，全部 hypothesis） |
| 16 | `ev_mvgpu1db_2c93c53d` | external-tool | sast.trivy | - | package-lock.json CVE-2021-3749 axios 0.21.1 -> 0.21.2 |
| 17 | `ev_mvgpu1dg_237a52f9` | external-tool | sast.trivy | - | package-lock.json CVE-2025-27152 axios 0.21.1 -> 1.8.2, 0.30.0 |
| 18 | `ev_mvgpu1dk_700aa011` | external-tool | sast.trivy | - | package-lock.json CVE-2026-25639 axios 0.21.1 -> 1.13.5, 0.30.3 |
| 19 | `ev_mvgpu1dp_5c63eb15` | external-tool | sast.trivy | - | package-lock.json CVE-2026-42033 axios 0.21.1 -> 1.15.1, 0.31.1 |
| 20 | `ev_mvgpu1dt_b6891970` | external-tool | sast.trivy | - | package-lock.json CVE-2026-42035 axios 0.21.1 -> 1.15.1, 0.31.1 |
| 21 | `ev_mvgpu1dx_30403c56` | external-tool | sast.trivy | - | package-lock.json CVE-2026-42043 axios 0.21.1 -> 1.15.1, 0.31.1 |
| 22 | `ev_mvgpu1e2_9a8d5024` | external-tool | sast.trivy | - | package-lock.json CVE-2026-44486 axios 0.21.1 -> 1.16.0, 0.32.0 |
| 23 | `ev_mvgpu1e6_08ad99b8` | external-tool | sast.trivy | - | package-lock.json CVE-2026-44487 axios 0.21.1 -> 1.16.0, 0.32.0 |
| 24 | `ev_mvgpu1ea_ad04b59c` | external-tool | sast.trivy | - | package-lock.json CVE-2026-44492 axios 0.21.1 -> 1.16.0, 0.32.0 |
| 25 | `ev_mvgpu1ef_d36ab6e2` | external-tool | sast.trivy | - | package-lock.json CVE-2026-44495 axios 0.21.1 -> 1.15.2, 0.31.1 |
| 26 | `ev_mvgpu1ej_214eae9f` | external-tool | sast.trivy | - | package-lock.json CVE-2026-44496 axios 0.21.1 -> 1.16.0, 0.32.0 |
| 27 | `ev_mvgpu1eo_cd4fe81d` | external-tool | sast.trivy | - | package-lock.json CVE-2024-45590 body-parser 1.18.2 -> 1.20.3 |
| 28 | `ev_mvgpu1es_e2a023ac` | external-tool | sast.trivy | - | package-lock.json CVE-2022-29078 ejs 3.1.6 -> 3.1.7 |
| 29 | `ev_mvgpu1ew_21175a5a` | external-tool | sast.trivy | - | package-lock.json CVE-2022-23539 jsonwebtoken 8.5.1 -> 9.0.0 |
| 30 | `ev_mvgpu1f1_be0d2379` | external-tool | sast.trivy | - | package-lock.json CVE-2020-8203 lodash 4.17.15 -> 4.17.19 |
| 31 | `ev_mvgpu1f5_38c797cb` | external-tool | sast.trivy | - | package-lock.json CVE-2021-23337 lodash 4.17.15 -> 4.17.21 |
| 32 | `ev_mvgpu1f9_dfe09611` | external-tool | sast.trivy | - | package-lock.json CVE-2026-4800 lodash 4.17.15 -> 4.18.0 |
| 33 | `ev_mvgpu1fe_dbdb0db7` | external-tool | sast.trivy | - | package-lock.json NSWG-ECO-516 lodash 4.17.15 -> >=4.17.19 |
| 34 | `ev_mvgpu1fi_0f1f7eec` | external-tool | sast.trivy | - | package-lock.json CVE-2021-44906 minimist 1.2.5 -> 1.2.6, 0.2.4 |
| 35 | `ev_mvgpu1fm_b00051dd` | external-tool | sast.trivy | - | package-lock.json CVE-2022-0235 node-fetch 2.6.0 -> 3.1.1, 2.6.7 |
| 36 | `ev_mvgpu1fr_1eb7c6bc` | external-tool | sast.trivy | - | package-lock.json CVE-2024-45296 path-to-regexp 0.1.7 -> 1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0 |
| 37 | `ev_mvgpu1fv_be56327f` | external-tool | sast.trivy | - | package-lock.json CVE-2024-52798 path-to-regexp 0.1.7 -> 0.1.12 |
| 38 | `ev_mvgpu1fz_7154d495` | external-tool | sast.trivy | - | package-lock.json CVE-2026-4867 path-to-regexp 0.1.7 -> 0.1.13 |
| 39 | `ev_mvgpu1g3_f7d919f7` | external-tool | sast.trivy | - | package-lock.json CVE-2022-24999 qs 6.5.1 -> 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4 |
| 40 | `ev_mvgpu1g7_299a92a9` | external-tool | sast.trivy | - | package-lock.json CVE-2026-59873 tar 4.4.13 -> 7.5.19 |
| 41 | `ev_mvgpu1gb_972f9b4c` | external-tool | sast.trivy | - | package-lock.json CVE-2021-32803 tar 4.4.13 -> 3.2.3, 4.4.15, 5.0.7, 6.1.2 |
| 42 | `ev_mvgpu1gf_0b46b390` | external-tool | sast.trivy | - | package-lock.json CVE-2021-32804 tar 4.4.13 -> 3.2.2, 4.4.14, 5.0.6, 6.1.1 |
| 43 | `ev_mvgpu1gk_fdbca747` | external-tool | sast.trivy | - | package-lock.json CVE-2021-37701 tar 4.4.13 -> 4.4.16, 5.0.8, 6.1.7 |
| 44 | `ev_mvgpu1go_ef3761c2` | external-tool | sast.trivy | - | package-lock.json CVE-2021-37712 tar 4.4.13 -> 4.4.18, 5.0.10, 6.1.9 |
| 45 | `ev_mvgpu1gs_e234e56e` | external-tool | sast.trivy | - | package-lock.json CVE-2021-37713 tar 4.4.13 -> 4.4.18, 5.0.10, 6.1.9 |
| 46 | `ev_mvgpu1gx_ce7c87c7` | external-tool | sast.trivy | - | package-lock.json CVE-2026-23745 tar 4.4.13 -> 7.5.3 |
| 47 | `ev_mvgpu1h1_8eb93c86` | external-tool | sast.trivy | - | package-lock.json CVE-2026-23950 tar 4.4.13 -> 7.5.4 |
| 48 | `ev_mvgpu1h5_add7b304` | external-tool | sast.trivy | - | package-lock.json CVE-2026-24842 tar 4.4.13 -> 7.5.7 |
| 49 | `ev_mvgpu1h9_1b61dc6d` | external-tool | sast.trivy | - | package-lock.json CVE-2026-26960 tar 4.4.13 -> 7.5.8 |
| 50 | `ev_mvgpu1hd_5edda89f` | external-tool | sast.trivy | - | package-lock.json CVE-2026-29786 tar 4.4.13 -> 7.5.10 |
| 51 | `ev_mvgpu1hi_15608eb7` | external-tool | sast.trivy | - | package-lock.json CVE-2026-31802 tar 4.4.13 -> 7.5.11 |
| 52 | `ev_mvgpu1hm_b2d4c665` | external-tool | sast.trivy | - | package-lock.json CVE-2026-59874 tar 4.4.13 -> 7.5.18 |
| 53 | `ev_mvgpu1hq_a4e6e4c7` | external-tool | sast.trivy | - | package-lock.json CVE-2026-73566 tar 4.4.13 -> 7.5.21 |
| 54 | `ev_mvgpu1hu_2aec2536` | external-tool | sast.trivy | - | requirements.txt CVE-2019-14234 Django 2.2.0 -> 1.11.23, 2.1.11, 2.2.4 |
| 55 | `ev_mvgpu1i0_9624f1cc` | external-tool | sast.trivy | - | requirements.txt CVE-2019-19844 Django 2.2.0 -> 1.11.27, 2.2.9, 3.0.1 |
| 56 | `ev_mvgpu1i4_4bb5aa13` | external-tool | sast.trivy | - | requirements.txt CVE-2020-7471 Django 2.2.0 -> 1.11.28, 2.2.10, 3.0.3 |
| 57 | `ev_mvgpu1i8_ddb03880` | external-tool | sast.trivy | - | requirements.txt CVE-2022-28346 Django 2.2.0 -> 2.2.28, 3.2.13, 4.0.4 |
| 58 | `ev_mvgpu1id_ea273330` | external-tool | sast.trivy | - | requirements.txt CVE-2022-28347 Django 2.2.0 -> 2.2.28, 3.2.13, 4.0.4 |
| 59 | `ev_mvgpu1ih_26fb1a45` | external-tool | sast.trivy | - | requirements.txt CVE-2025-64459 Django 2.2.0 -> 5.2.8, 5.1.14, 4.2.26 |
| 60 | `ev_mvgpu1im_4ab2dfd7` | external-tool | sast.trivy | - | requirements.txt CVE-2019-14232 Django 2.2.0 -> 1.11.23, 2.1.11, 2.2.4 |
| 61 | `ev_mvgpu1ir_d4b71887` | external-tool | sast.trivy | - | requirements.txt CVE-2019-14233 Django 2.2.0 -> 1.11.23, 2.1.11, 2.2.4 |
| 62 | `ev_mvgpu1iv_267ae37e` | external-tool | sast.trivy | - | requirements.txt CVE-2019-14235 Django 2.2.0 -> 1.11.23, 2.1.11, 2.2.4 |
| 63 | `ev_mvgpu1iz_b907e3f2` | external-tool | sast.trivy | - | requirements.txt CVE-2019-19118 Django 2.2.0 -> 2.1.15, 2.2.8 |
| 64 | `ev_mvgpu1j4_654feef7` | external-tool | sast.trivy | - | requirements.txt CVE-2020-13254 Django 2.2.0 -> 2.2.13, 3.0.7 |
| 65 | `ev_mvgpu1j8_28cb5d79` | external-tool | sast.trivy | - | requirements.txt CVE-2020-24583 Django 2.2.0 -> 2.2.16, 3.0.10, 3.1.1 |
| 66 | `ev_mvgpu1jd_64f1bb60` | external-tool | sast.trivy | - | requirements.txt CVE-2020-9402 Django 2.2.0 -> 1.11.29, 2.2.11, 3.0.4 |
| 67 | `ev_mvgpu1jh_820d287b` | external-tool | sast.trivy | - | requirements.txt CVE-2021-31542 Django 2.2.0 -> 2.2.21, 3.1.9, 3.2.1 |
| 68 | `ev_mvgpu1jl_942720fa` | external-tool | sast.trivy | - | requirements.txt CVE-2021-33571 Django 2.2.0 -> 2.2.24, 3.1.12, 3.2.4 |
| 69 | `ev_mvgpu1jp_3a7efb33` | external-tool | sast.trivy | - | requirements.txt CVE-2021-45115 Django 2.2.0 -> 2.2.26, 3.2.11, 4.0.1 |
| 70 | `ev_mvgpu1ju_7387813e` | external-tool | sast.trivy | - | requirements.txt CVE-2021-45116 Django 2.2.0 -> 2.2.26, 3.2.11, 4.0.1 |
| 71 | `ev_mvgpu1jy_69ef0250` | external-tool | sast.trivy | - | requirements.txt CVE-2022-23833 Django 2.2.0 -> 2.2.27, 3.2.12, 4.0.2 |
| 72 | `ev_mvgpu1k2_b3b77566` | external-tool | sast.trivy | - | requirements.txt CVE-2022-36359 Django 2.2.0 -> 3.2.15, 4.0.7 |
| 73 | `ev_mvgpu1k6_538ccdae` | external-tool | sast.trivy | - | requirements.txt CVE-2025-57833 Django 2.2.0 -> 4.2.24, 5.1.12, 5.2.6 |
| 74 | `ev_mvgpu1ka_8d92bd19` | external-tool | sast.trivy | - | requirements.txt CVE-2025-64458 Django 2.2.0 -> 5.2.8, 5.1.14, 4.2.26 |
| 75 | `ev_mvgpu1kf_133b73af` | external-tool | sast.trivy | - | requirements.txt CVE-2026-15307 Django 2.2.0 -> 5.2.17, 6.0.8 |
| 76 | `ev_mvgpu1kj_57fb5184` | external-tool | sast.trivy | - | requirements.txt CVE-2019-10906 Jinja2 2.10 -> 2.10.1 |
| 77 | `ev_mvgpu1ko_246ad8dd` | external-tool | sast.trivy | - | requirements.txt CVE-2019-20477 PyYAML 5.1 -> 5.2 |
| 78 | `ev_mvgpu1kt_5a3ccaf2` | external-tool | sast.trivy | - | requirements.txt CVE-2020-14343 PyYAML 5.1 -> 5.4 |
| 79 | `ev_mvgpu1kx_945abc08` | external-tool | sast.trivy | - | requirements.txt CVE-2020-1747 PyYAML 5.1 -> 5.3.1 |
| 80 | `ev_mvgpu1l2_27700c57` | external-tool | sast.trivy | - | requirements.txt CVE-2018-18074 requests 2.19.0 -> 2.20.0 |
| 81 | `ev_mvgpu1l6_c8cb9277` | external-tool | sast.trivy | - | src/config.js aws-access-key-id line=5 (value redacted) |
| 82 | `ev_mvgpu1lb_dd247376` | external-tool | sast.trivy | - | src/config.js github-pat line=6 (value redacted) |
| 83 | `ev_mvgpu1lg_3856b6ce` | external-tool | sast.trivy | - | command=trivy fs --format json --quiet --scanners vuln,secret --severity HIGH,CRITICAL --skip-db-update D:\dsh-ABM\armorbreak\fixtures\gate-b-sample sha256(stdout)=ef024a5e106e2db1fd7c3e9a141cb18613efcdf05cc92bb43c513f45c9afd4f2 |
| 84 | `ev_mvgpu1lk_bd5ea7df` | finding-evidence | sast.trivy | - | CVE-2021-3749 axios 0.21.1 |
| 85 | `ev_mvgpu1lt_af09ee2f` | finding-evidence | sast.trivy | - | CVE-2025-27152 axios 0.21.1 |
| 86 | `ev_mvgpu1m3_84a83411` | finding-evidence | sast.trivy | - | CVE-2026-25639 axios 0.21.1 |
| 87 | `ev_mvgpu1md_b23b08a9` | finding-evidence | sast.trivy | - | CVE-2026-42033 axios 0.21.1 |
| 88 | `ev_mvgpu1mm_7f968a6d` | finding-evidence | sast.trivy | - | CVE-2026-42035 axios 0.21.1 |
| 89 | `ev_mvgpu1mv_a58f7fcb` | finding-evidence | sast.trivy | - | CVE-2026-42043 axios 0.21.1 |
| 90 | `ev_mvgpu1n5_c56bf238` | finding-evidence | sast.trivy | - | CVE-2026-44486 axios 0.21.1 |
| 91 | `ev_mvgpu1ne_01545826` | finding-evidence | sast.trivy | - | CVE-2026-44487 axios 0.21.1 |
| 92 | `ev_mvgpu1no_fb8b8aa1` | finding-evidence | sast.trivy | - | CVE-2026-44492 axios 0.21.1 |
| 93 | `ev_mvgpu1ny_884ef7f0` | finding-evidence | sast.trivy | - | CVE-2026-44495 axios 0.21.1 |
| 94 | `ev_mvgpu1o8_c2a79bc9` | finding-evidence | sast.trivy | - | CVE-2026-44496 axios 0.21.1 |
| 95 | `ev_mvgpu1oi_d012ce93` | finding-evidence | sast.trivy | - | CVE-2024-45590 body-parser 1.18.2 |
| 96 | `ev_mvgpu1os_14527108` | finding-evidence | sast.trivy | - | CVE-2022-29078 ejs 3.1.6 |
| 97 | `ev_mvgpu1p2_83a671cf` | finding-evidence | sast.trivy | - | CVE-2022-23539 jsonwebtoken 8.5.1 |
| 98 | `ev_mvgpu1pc_684fc366` | finding-evidence | sast.trivy | - | CVE-2020-8203 lodash 4.17.15 |
| 99 | `ev_mvgpu1pm_a41c2223` | finding-evidence | sast.trivy | - | CVE-2021-23337 lodash 4.17.15 |
| 100 | `ev_mvgpu1pw_f3540a3a` | finding-evidence | sast.trivy | - | CVE-2026-4800 lodash 4.17.15 |
| 101 | `ev_mvgpu1q7_72425433` | finding-evidence | sast.trivy | - | NSWG-ECO-516 lodash 4.17.15 |
| 102 | `ev_mvgpu1qh_628485a7` | finding-evidence | sast.trivy | - | CVE-2021-44906 minimist 1.2.5 |
| 103 | `ev_mvgpu1qr_c1c03438` | finding-evidence | sast.trivy | - | CVE-2022-0235 node-fetch 2.6.0 |
| 104 | `ev_mvgpu1r1_dd3a32a1` | finding-evidence | sast.trivy | - | CVE-2024-45296 path-to-regexp 0.1.7 |
| 105 | `ev_mvgpu1rb_9fcb7ac0` | finding-evidence | sast.trivy | - | CVE-2024-52798 path-to-regexp 0.1.7 |
| 106 | `ev_mvgpu1rl_1b525f44` | finding-evidence | sast.trivy | - | CVE-2026-4867 path-to-regexp 0.1.7 |
| 107 | `ev_mvgpu1rv_765b9517` | finding-evidence | sast.trivy | - | CVE-2022-24999 qs 6.5.1 |
| 108 | `ev_mvgpu1s5_df3d52c9` | finding-evidence | sast.trivy | - | CVE-2026-59873 tar 4.4.13 |
| 109 | `ev_mvgpu1sf_93ca166a` | finding-evidence | sast.trivy | - | CVE-2021-32803 tar 4.4.13 |
| 110 | `ev_mvgpu1sp_cc1b1a66` | finding-evidence | sast.trivy | - | CVE-2021-32804 tar 4.4.13 |
| 111 | `ev_mvgpu1sy_53afe874` | finding-evidence | sast.trivy | - | CVE-2021-37701 tar 4.4.13 |
| 112 | `ev_mvgpu1t9_b0fcdd58` | finding-evidence | sast.trivy | - | CVE-2021-37712 tar 4.4.13 |
| 113 | `ev_mvgpu1tj_f42e831e` | finding-evidence | sast.trivy | - | CVE-2021-37713 tar 4.4.13 |
| 114 | `ev_mvgpu1tt_3da73604` | finding-evidence | sast.trivy | - | CVE-2026-23745 tar 4.4.13 |
| 115 | `ev_mvgpu1u3_e6a03877` | finding-evidence | sast.trivy | - | CVE-2026-23950 tar 4.4.13 |
| 116 | `ev_mvgpu1ud_381a6aed` | finding-evidence | sast.trivy | - | CVE-2026-24842 tar 4.4.13 |
| 117 | `ev_mvgpu1un_dd58f4e5` | finding-evidence | sast.trivy | - | CVE-2026-26960 tar 4.4.13 |
| 118 | `ev_mvgpu1ux_e084b4e7` | finding-evidence | sast.trivy | - | CVE-2026-29786 tar 4.4.13 |
| 119 | `ev_mvgpu1v7_de998830` | finding-evidence | sast.trivy | - | CVE-2026-31802 tar 4.4.13 |
| 120 | `ev_mvgpu1vh_88e902e8` | finding-evidence | sast.trivy | - | CVE-2026-59874 tar 4.4.13 |
| 121 | `ev_mvgpu1vq_64edad04` | finding-evidence | sast.trivy | - | CVE-2026-73566 tar 4.4.13 |
| 122 | `ev_mvgpu1vz_478ecbf0` | finding-evidence | sast.trivy | - | CVE-2019-14234 Django 2.2.0 |
| 123 | `ev_mvgpu1w9_10addccc` | finding-evidence | sast.trivy | - | CVE-2019-19844 Django 2.2.0 |
| 124 | `ev_mvgpu1wj_8b3aa517` | finding-evidence | sast.trivy | - | CVE-2020-7471 Django 2.2.0 |
| 125 | `ev_mvgpu1wt_6ba38e71` | finding-evidence | sast.trivy | - | CVE-2022-28346 Django 2.2.0 |
| 126 | `ev_mvgpu1x4_0a0fa2f4` | finding-evidence | sast.trivy | - | CVE-2022-28347 Django 2.2.0 |
| 127 | `ev_mvgpu1xf_de743127` | finding-evidence | sast.trivy | - | CVE-2025-64459 Django 2.2.0 |
| 128 | `ev_mvgpu1xp_9f05b68d` | finding-evidence | sast.trivy | - | CVE-2019-14232 Django 2.2.0 |
| 129 | `ev_mvgpu1xz_14075573` | finding-evidence | sast.trivy | - | CVE-2019-14233 Django 2.2.0 |
| 130 | `ev_mvgpu1y9_5fd498f8` | finding-evidence | sast.trivy | - | CVE-2019-14235 Django 2.2.0 |
| 131 | `ev_mvgpu1yj_a871bdce` | finding-evidence | sast.trivy | - | CVE-2019-19118 Django 2.2.0 |
| 132 | `ev_mvgpu1yt_8b0ba49e` | finding-evidence | sast.trivy | - | CVE-2020-13254 Django 2.2.0 |
| 133 | `ev_mvgpu1z2_3519e8ed` | finding-evidence | sast.trivy | - | CVE-2020-24583 Django 2.2.0 |
| 134 | `ev_mvgpu1zd_8a23658b` | finding-evidence | sast.trivy | - | CVE-2020-9402 Django 2.2.0 |
| 135 | `ev_mvgpu1zm_a9d6d302` | finding-evidence | sast.trivy | - | CVE-2021-31542 Django 2.2.0 |
| 136 | `ev_mvgpu1zw_e54a5bf2` | finding-evidence | sast.trivy | - | CVE-2021-33571 Django 2.2.0 |
| 137 | `ev_mvgpu206_5df084e0` | finding-evidence | sast.trivy | - | CVE-2021-45115 Django 2.2.0 |
| 138 | `ev_mvgpu20f_0a3e7b6b` | finding-evidence | sast.trivy | - | CVE-2021-45116 Django 2.2.0 |
| 139 | `ev_mvgpu20m_181173ab` | finding-evidence | sast.trivy | - | CVE-2022-23833 Django 2.2.0 |
| 140 | `ev_mvgpu20u_b0da21f8` | finding-evidence | sast.trivy | - | CVE-2022-36359 Django 2.2.0 |
| 141 | `ev_mvgpu212_ce5d455a` | finding-evidence | sast.trivy | - | CVE-2025-57833 Django 2.2.0 |
| 142 | `ev_mvgpu21c_93190ed5` | finding-evidence | sast.trivy | - | CVE-2025-64458 Django 2.2.0 |
| 143 | `ev_mvgpu21l_f6c45c9c` | finding-evidence | sast.trivy | - | CVE-2026-15307 Django 2.2.0 |
| 144 | `ev_mvgpu21t_22073ac1` | finding-evidence | sast.trivy | - | CVE-2019-10906 Jinja2 2.10 |
| 145 | `ev_mvgpu220_f9a837a8` | finding-evidence | sast.trivy | - | CVE-2019-20477 PyYAML 5.1 |
| 146 | `ev_mvgpu229_e38d2c55` | finding-evidence | sast.trivy | - | CVE-2020-14343 PyYAML 5.1 |
| 147 | `ev_mvgpu22i_9ace5922` | finding-evidence | sast.trivy | - | CVE-2020-1747 PyYAML 5.1 |
| 148 | `ev_mvgpu22q_b5f7ecdc` | finding-evidence | sast.trivy | - | CVE-2018-18074 requests 2.19.0 |
| 149 | `ev_mvgpu230_be8b2e63` | finding-evidence | sast.trivy | - | aws-access-key-id AWS Access Key ID line=5 |
| 150 | `ev_mvgpu239_5fc20afd` | finding-evidence | sast.trivy | - | github-pat GitHub Personal Access Token line=6 |

## 6. 审计记录（脱敏）

| 序号 | 时间 | 动作 | 详情 |
|---|---|---|---|
| 656 | 2026-10-20T13:25:13.883Z | evidence.add | {"seq":656,"at":"2026-10-20T13:25:13.883Z","prevHash":"fc0f775d618c25ca6c140f244bc77be4cf1e10ee24c2e0a2bdecb368eb7258a6","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1w9_10addccc","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"14b31dea029ece5adab6d602f72cfb2b5337be38d9b7e2c83c18a33cf57e9101"} |
| 657 | 2026-10-20T13:25:13.889Z | finding.record | {"seq":657,"at":"2026-10-20T13:25:13.889Z","prevHash":"14b31dea029ece5adab6d602f72cfb2b5337be38d9b7e2c83c18a33cf57e9101","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1we_9bf6b921","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2019-19844 in Django","hash":"14af5192147914e9e6cf358287205751517085514d9296646918100f491c09c0"} |
| 658 | 2026-10-20T13:25:13.893Z | evidence.add | {"seq":658,"at":"2026-10-20T13:25:13.893Z","prevHash":"14af5192147914e9e6cf358287205751517085514d9296646918100f491c09c0","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1wj_8b3aa517","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"0e67daac64c655faa1a94f5aa0be7b8ff6cb6c9a36c3e352c7da7241fdefa1ec"} |
| 659 | 2026-10-20T13:25:13.899Z | finding.record | {"seq":659,"at":"2026-10-20T13:25:13.899Z","prevHash":"0e67daac64c655faa1a94f5aa0be7b8ff6cb6c9a36c3e352c7da7241fdefa1ec","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1wo_38295916","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2020-7471 in Django","hash":"8fddf4ed1de64bc1abb36dd3ae53cddee338e9d651cfb530eec9dc721f763f5e"} |
| 660 | 2026-10-20T13:25:13.903Z | evidence.add | {"seq":660,"at":"2026-10-20T13:25:13.903Z","prevHash":"8fddf4ed1de64bc1abb36dd3ae53cddee338e9d651cfb530eec9dc721f763f5e","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1wt_6ba38e71","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"051a9ee2c30f4194df82d4980347bcfdce6b7d2ccc98f2e09503200679d5c045"} |
| 661 | 2026-10-20T13:25:13.909Z | finding.record | {"seq":661,"at":"2026-10-20T13:25:13.909Z","prevHash":"051a9ee2c30f4194df82d4980347bcfdce6b7d2ccc98f2e09503200679d5c045","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1wy_725a32ca","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2022-28346 in Django","hash":"654d6352bf6239a2b3002841347fdaa9f76c9df78c5083907c2d1118b3b7dbaa"} |
| 662 | 2026-10-20T13:25:13.914Z | evidence.add | {"seq":662,"at":"2026-10-20T13:25:13.914Z","prevHash":"654d6352bf6239a2b3002841347fdaa9f76c9df78c5083907c2d1118b3b7dbaa","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1x4_0a0fa2f4","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"38ca30f1cff9c00c149c40930271b37f6179d5f1314f5f9b3506ca6bc9165dcb"} |
| 663 | 2026-10-20T13:25:13.920Z | finding.record | {"seq":663,"at":"2026-10-20T13:25:13.920Z","prevHash":"38ca30f1cff9c00c149c40930271b37f6179d5f1314f5f9b3506ca6bc9165dcb","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1x9_b77fe962","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2022-28347 in Django","hash":"064cc5d8834b9ec7956d5e7e1d5e89eeffdd24ad5d74a13ffa93a5c5a23fff3a"} |
| 664 | 2026-10-20T13:25:13.926Z | evidence.add | {"seq":664,"at":"2026-10-20T13:25:13.926Z","prevHash":"064cc5d8834b9ec7956d5e7e1d5e89eeffdd24ad5d74a13ffa93a5c5a23fff3a","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1xf_de743127","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"1fd52960befe49e0d5c08ddf9197379b3ac2a1094eb9d3345b6153d40d5b6ea0"} |
| 665 | 2026-10-20T13:25:13.931Z | finding.record | {"seq":665,"at":"2026-10-20T13:25:13.931Z","prevHash":"1fd52960befe49e0d5c08ddf9197379b3ac2a1094eb9d3345b6153d40d5b6ea0","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1xk_02be882e","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2025-64459 in Django","hash":"b6b24149b51d6e02660ab8d416793b4ad50c3bf6b8b4962decec8cfd0246adbe"} |
| 666 | 2026-10-20T13:25:13.935Z | evidence.add | {"seq":666,"at":"2026-10-20T13:25:13.935Z","prevHash":"b6b24149b51d6e02660ab8d416793b4ad50c3bf6b8b4962decec8cfd0246adbe","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1xp_9f05b68d","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"757552b9e50429fcfc4d298c8851599911db05843cce35ff75056dd3a8e992ed"} |
| 667 | 2026-10-20T13:25:13.940Z | finding.record | {"seq":667,"at":"2026-10-20T13:25:13.940Z","prevHash":"757552b9e50429fcfc4d298c8851599911db05843cce35ff75056dd3a8e992ed","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1xt_2e468c37","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2019-14232 in Django","hash":"a9eac3c096127f3a53ace3f72c43ae2fda4b7e76fdcc57b23f9c0ce944a41780"} |
| 668 | 2026-10-20T13:25:13.945Z | evidence.add | {"seq":668,"at":"2026-10-20T13:25:13.945Z","prevHash":"a9eac3c096127f3a53ace3f72c43ae2fda4b7e76fdcc57b23f9c0ce944a41780","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1xz_14075573","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"7d69b978799002d456d658ed0a20682f4a2045dc915eda7e32a3e814e1cc6210"} |
| 669 | 2026-10-20T13:25:13.950Z | finding.record | {"seq":669,"at":"2026-10-20T13:25:13.950Z","prevHash":"7d69b978799002d456d658ed0a20682f4a2045dc915eda7e32a3e814e1cc6210","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1y3_09d9acea","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2019-14233 in Django","hash":"232e7dd6de9c84ed48bc6c8ef85787e6d6bab8c517cd6b293d1bdd276e4a4757"} |
| 670 | 2026-10-20T13:25:13.955Z | evidence.add | {"seq":670,"at":"2026-10-20T13:25:13.955Z","prevHash":"232e7dd6de9c84ed48bc6c8ef85787e6d6bab8c517cd6b293d1bdd276e4a4757","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1y9_5fd498f8","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"275d8032d61d187afa9177cec1c1ce58403d64e93c56d9517e53d93ec0a2e56a"} |
| 671 | 2026-10-20T13:25:13.961Z | finding.record | {"seq":671,"at":"2026-10-20T13:25:13.961Z","prevHash":"275d8032d61d187afa9177cec1c1ce58403d64e93c56d9517e53d93ec0a2e56a","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1ye_f1baf85e","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2019-14235 in Django","hash":"10e1c6fea29407a2eca40acd00037e515f15019dfda12d01c2dc01bbc82b2961"} |
| 672 | 2026-10-20T13:25:13.965Z | evidence.add | {"seq":672,"at":"2026-10-20T13:25:13.965Z","prevHash":"10e1c6fea29407a2eca40acd00037e515f15019dfda12d01c2dc01bbc82b2961","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1yj_a871bdce","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"a96bb327bde9604f37c12cf35c8b968a5047c3c578ac386a66fdb6a227785535"} |
| 673 | 2026-10-20T13:25:13.970Z | finding.record | {"seq":673,"at":"2026-10-20T13:25:13.970Z","prevHash":"a96bb327bde9604f37c12cf35c8b968a5047c3c578ac386a66fdb6a227785535","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1yn_bf584c24","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2019-19118 in Django","hash":"5f46ccbd367448b28933d525293336951295b55e6780651ca3dba9a519955d81"} |
| 674 | 2026-10-20T13:25:13.975Z | evidence.add | {"seq":674,"at":"2026-10-20T13:25:13.975Z","prevHash":"5f46ccbd367448b28933d525293336951295b55e6780651ca3dba9a519955d81","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1yt_8b0ba49e","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"2d6b3d9c89adfd56d39a5e3da5d579cebf081994fa9e165f11f9457a7bfa277b"} |
| 675 | 2026-10-20T13:25:13.980Z | finding.record | {"seq":675,"at":"2026-10-20T13:25:13.980Z","prevHash":"2d6b3d9c89adfd56d39a5e3da5d579cebf081994fa9e165f11f9457a7bfa277b","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1yx_f116fc43","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2020-13254 in Django","hash":"425fadbcd6bcff62fe7fab07c5dc44a9f9c11ac3bfd77cb4f014404837b5a58c"} |
| 676 | 2026-10-20T13:25:13.985Z | evidence.add | {"seq":676,"at":"2026-10-20T13:25:13.985Z","prevHash":"425fadbcd6bcff62fe7fab07c5dc44a9f9c11ac3bfd77cb4f014404837b5a58c","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1z2_3519e8ed","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"68e772997a941649385846c9202aaa4027d0908f4d2901e7a7b53b98361eda17"} |
| 677 | 2026-10-20T13:25:13.990Z | finding.record | {"seq":677,"at":"2026-10-20T13:25:13.990Z","prevHash":"68e772997a941649385846c9202aaa4027d0908f4d2901e7a7b53b98361eda17","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1z7_2728b2d0","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2020-24583 in Django","hash":"836da0a583feac39c6cddb9a4e7e21e52bfec67ee25ef7b88db3c18f163b68d0"} |
| 678 | 2026-10-20T13:25:13.995Z | evidence.add | {"seq":678,"at":"2026-10-20T13:25:13.995Z","prevHash":"836da0a583feac39c6cddb9a4e7e21e52bfec67ee25ef7b88db3c18f163b68d0","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1zd_8a23658b","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"1601197af141ba05eca0fe285b5f48910b33644fc3419e240a1bd9f61bcc4f4e"} |
| 679 | 2026-10-20T13:25:14.000Z | finding.record | {"seq":679,"at":"2026-10-20T13:25:14.000Z","prevHash":"1601197af141ba05eca0fe285b5f48910b33644fc3419e240a1bd9f61bcc4f4e","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1zh_8acceeef","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2020-9402 in Django","hash":"d2f16d2fd4605fd1888efc5e895a495f5524c81cea082715d8e6ee7f5a1fd62d"} |
| 680 | 2026-10-20T13:25:14.005Z | evidence.add | {"seq":680,"at":"2026-10-20T13:25:14.005Z","prevHash":"d2f16d2fd4605fd1888efc5e895a495f5524c81cea082715d8e6ee7f5a1fd62d","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1zm_a9d6d302","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"c3ed138edd9253572537d5d937d7de69ae320caafc9ff40939618bfe50b82a81"} |
| 681 | 2026-10-20T13:25:14.010Z | finding.record | {"seq":681,"at":"2026-10-20T13:25:14.010Z","prevHash":"c3ed138edd9253572537d5d937d7de69ae320caafc9ff40939618bfe50b82a81","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu1zr_437024a7","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2021-31542 in Django","hash":"525058615d4b5ea9eebe907eb4c8ee3fd462d2b69cb2a36a7948a13f473fcb5c"} |
| 682 | 2026-10-20T13:25:14.014Z | evidence.add | {"seq":682,"at":"2026-10-20T13:25:14.014Z","prevHash":"525058615d4b5ea9eebe907eb4c8ee3fd462d2b69cb2a36a7948a13f473fcb5c","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu1zw_e54a5bf2","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"88550c6b28c55a41c3c4ab7ad8cbda5df0cfdeadf8a8f1ece07ab97989ecaae1"} |
| 683 | 2026-10-20T13:25:14.020Z | finding.record | {"seq":683,"at":"2026-10-20T13:25:14.020Z","prevHash":"88550c6b28c55a41c3c4ab7ad8cbda5df0cfdeadf8a8f1ece07ab97989ecaae1","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu201_67df97d4","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2021-33571 in Django","hash":"08bd8bfd62a882902112a820a6efb7ec3c8655389d25885530d00a63ef28ad92"} |
| 684 | 2026-10-20T13:25:14.024Z | evidence.add | {"seq":684,"at":"2026-10-20T13:25:14.024Z","prevHash":"08bd8bfd62a882902112a820a6efb7ec3c8655389d25885530d00a63ef28ad92","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu206_5df084e0","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"3b576003fb995808751aca085a84dc185f70bb2b03f5746d6836002b588db75f"} |
| 685 | 2026-10-20T13:25:14.028Z | finding.record | {"seq":685,"at":"2026-10-20T13:25:14.028Z","prevHash":"3b576003fb995808751aca085a84dc185f70bb2b03f5746d6836002b588db75f","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu20a_185b9350","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2021-45115 in Django","hash":"37a4c1feaa94593a581741535cdaf3608fed86b10c3e75206e8ecca61ba5601e"} |
| 686 | 2026-10-20T13:25:14.032Z | evidence.add | {"seq":686,"at":"2026-10-20T13:25:14.032Z","prevHash":"37a4c1feaa94593a581741535cdaf3608fed86b10c3e75206e8ecca61ba5601e","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu20f_0a3e7b6b","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"33a5e573dc4a40a7bf1ab77fcf7dbd2e948b39fe7db61572674fa063301f50c9"} |
| 687 | 2026-10-20T13:25:14.036Z | finding.record | {"seq":687,"at":"2026-10-20T13:25:14.036Z","prevHash":"33a5e573dc4a40a7bf1ab77fcf7dbd2e948b39fe7db61572674fa063301f50c9","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu20i_09498b7b","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2021-45116 in Django","hash":"58e1e225860f90e452f335a5a5c2b7ae34b764582a5032809fa83de9289c6351"} |
| 688 | 2026-10-20T13:25:14.040Z | evidence.add | {"seq":688,"at":"2026-10-20T13:25:14.040Z","prevHash":"58e1e225860f90e452f335a5a5c2b7ae34b764582a5032809fa83de9289c6351","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu20m_181173ab","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"0e0fd98d736999e0ad58865ba4abb36164a43ee589aeed8c3316de58cbbace26"} |
| 689 | 2026-10-20T13:25:14.044Z | finding.record | {"seq":689,"at":"2026-10-20T13:25:14.044Z","prevHash":"0e0fd98d736999e0ad58865ba4abb36164a43ee589aeed8c3316de58cbbace26","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu20q_51f6ffd3","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2022-23833 in Django","hash":"b3bb7583a392dbe64675ef5e80f886fc7656290c5fa86f66ab948cd4b339a12e"} |
| 690 | 2026-10-20T13:25:14.048Z | evidence.add | {"seq":690,"at":"2026-10-20T13:25:14.048Z","prevHash":"b3bb7583a392dbe64675ef5e80f886fc7656290c5fa86f66ab948cd4b339a12e","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu20u_b0da21f8","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"a0e559326f993ad7dc45135c2a5e9058f42eebb1b157e3056a348aa58c503d81"} |
| 691 | 2026-10-20T13:25:14.052Z | finding.record | {"seq":691,"at":"2026-10-20T13:25:14.052Z","prevHash":"a0e559326f993ad7dc45135c2a5e9058f42eebb1b157e3056a348aa58c503d81","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu20y_0fcb2ffa","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2022-36359 in Django","hash":"8a854f2977fb5f82c74337a20e56bb61bf5da267ef022984fe18969188fee506"} |
| 692 | 2026-10-20T13:25:14.055Z | evidence.add | {"seq":692,"at":"2026-10-20T13:25:14.055Z","prevHash":"8a854f2977fb5f82c74337a20e56bb61bf5da267ef022984fe18969188fee506","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu212_ce5d455a","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"756f5f9036251d6a77f31a8ac806c2c2f8e8e08b4a7e87d770c01905f2bcb02a"} |
| 693 | 2026-10-20T13:25:14.062Z | finding.record | {"seq":693,"at":"2026-10-20T13:25:14.062Z","prevHash":"756f5f9036251d6a77f31a8ac806c2c2f8e8e08b4a7e87d770c01905f2bcb02a","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu216_42d6bdc6","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2025-57833 in Django","hash":"e40ed91eddddf23516cf18328cf766e14cb4c39c2083d9eff6c8a7c0a2849cc6"} |
| 694 | 2026-10-20T13:25:14.066Z | evidence.add | {"seq":694,"at":"2026-10-20T13:25:14.066Z","prevHash":"e40ed91eddddf23516cf18328cf766e14cb4c39c2083d9eff6c8a7c0a2849cc6","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu21c_93190ed5","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"82ee185655322bc0b2335bd5d1a3ed3a62d66cd87f73487e8ca9eb25528e33ee"} |
| 695 | 2026-10-20T13:25:14.071Z | finding.record | {"seq":695,"at":"2026-10-20T13:25:14.071Z","prevHash":"82ee185655322bc0b2335bd5d1a3ed3a62d66cd87f73487e8ca9eb25528e33ee","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu21g_006caa5d","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2025-64458 in Django","hash":"f0da54dbd7cd17c2336cca573c80e2dc3f39ede34c89eac2f1ba3edf0518fcfd"} |
| 696 | 2026-10-20T13:25:14.074Z | evidence.add | {"seq":696,"at":"2026-10-20T13:25:14.074Z","prevHash":"f0da54dbd7cd17c2336cca573c80e2dc3f39ede34c89eac2f1ba3edf0518fcfd","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu21l_f6c45c9c","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"3a877d8aacb8c038447fbe3f548b54389e7a3f80f25eead7ae9a11b8dce3855b"} |
| 697 | 2026-10-20T13:25:14.078Z | finding.record | {"seq":697,"at":"2026-10-20T13:25:14.078Z","prevHash":"3a877d8aacb8c038447fbe3f548b54389e7a3f80f25eead7ae9a11b8dce3855b","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu21o_1d77b62b","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2026-15307 in Django","hash":"b6415ec1f1ba161eb1298f26842f9d18d93eb3c2f983d757c24c56ba8f4e53c4"} |
| 698 | 2026-10-20T13:25:14.083Z | evidence.add | {"seq":698,"at":"2026-10-20T13:25:14.083Z","prevHash":"b6415ec1f1ba161eb1298f26842f9d18d93eb3c2f983d757c24c56ba8f4e53c4","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu21t_22073ac1","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"df1892857a9531bcab39fc5580304e044c71c7be33bc910c3d156b79aa271bb7"} |
| 699 | 2026-10-20T13:25:14.086Z | finding.record | {"seq":699,"at":"2026-10-20T13:25:14.086Z","prevHash":"df1892857a9531bcab39fc5580304e044c71c7be33bc910c3d156b79aa271bb7","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu21w_853bd305","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2019-10906 in Jinja2","hash":"82f5f3ce29736430d2a9fb929fc35faa35e083e1e859472faddf4919206600bc"} |
| 700 | 2026-10-20T13:25:14.090Z | evidence.add | {"seq":700,"at":"2026-10-20T13:25:14.090Z","prevHash":"82f5f3ce29736430d2a9fb929fc35faa35e083e1e859472faddf4919206600bc","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu220_f9a837a8","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"55a5f3c38febb764d5acd8e0f887306b241b285d73609a9d85f72fc54443643c"} |
| 701 | 2026-10-20T13:25:14.095Z | finding.record | {"seq":701,"at":"2026-10-20T13:25:14.095Z","prevHash":"55a5f3c38febb764d5acd8e0f887306b241b285d73609a9d85f72fc54443643c","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu224_9120b179","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2019-20477 in PyYAML","hash":"66a09815762c4ecee173af2550655d22143c2b329dca07bc648f42a237c4b79a"} |
| 702 | 2026-10-20T13:25:14.099Z | evidence.add | {"seq":702,"at":"2026-10-20T13:25:14.099Z","prevHash":"66a09815762c4ecee173af2550655d22143c2b329dca07bc648f42a237c4b79a","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu229_e38d2c55","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"38c72932caa63496a85899883070f22055cb5b05c89beee96dfb15eb1d2e1443"} |
| 703 | 2026-10-20T13:25:14.104Z | finding.record | {"seq":703,"at":"2026-10-20T13:25:14.104Z","prevHash":"38c72932caa63496a85899883070f22055cb5b05c89beee96dfb15eb1d2e1443","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu22e_e82811f3","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2020-14343 in PyYAML","hash":"15d17ed216ae8fe6ffb2f24cc8ff7ae72107f44a2deeeb07a2e683f4c89c9ecd"} |
| 704 | 2026-10-20T13:25:14.108Z | evidence.add | {"seq":704,"at":"2026-10-20T13:25:14.108Z","prevHash":"15d17ed216ae8fe6ffb2f24cc8ff7ae72107f44a2deeeb07a2e683f4c89c9ecd","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu22i_9ace5922","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"bafe3538867e5d5b4c77c2b0fdd76d1afbf86afea82acda03f7c7b06ffa617a6"} |
| 705 | 2026-10-20T13:25:14.112Z | finding.record | {"seq":705,"at":"2026-10-20T13:25:14.112Z","prevHash":"bafe3538867e5d5b4c77c2b0fdd76d1afbf86afea82acda03f7c7b06ffa617a6","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu22m_ea4c045a","severity":"critical","verification":"hypothesis","title":"[trivy] CVE-2020-1747 in PyYAML","hash":"4632e07d9a012733b90cd5dfc34cbebffffdaafc7ff0b84d321a38e3473d2b77"} |
| 706 | 2026-10-20T13:25:14.117Z | evidence.add | {"seq":706,"at":"2026-10-20T13:25:14.117Z","prevHash":"4632e07d9a012733b90cd5dfc34cbebffffdaafc7ff0b84d321a38e3473d2b77","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu22q_b5f7ecdc","title":"trivy vulnerability","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"969eff21b051285e54fd77e9bb96fca408ed08cf6e2909637387a4e9cf58480c"} |
| 707 | 2026-10-20T13:25:14.122Z | finding.record | {"seq":707,"at":"2026-10-20T13:25:14.122Z","prevHash":"969eff21b051285e54fd77e9bb96fca408ed08cf6e2909637387a4e9cf58480c","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu22v_089f285c","severity":"high","verification":"hypothesis","title":"[trivy] CVE-2018-18074 in requests","hash":"385291cdd6764b6ec422c6f653ead5df0f6d8c96c0b151f6f5908f719cdb1c6a"} |
| 708 | 2026-10-20T13:25:14.127Z | evidence.add | {"seq":708,"at":"2026-10-20T13:25:14.127Z","prevHash":"385291cdd6764b6ec422c6f653ead5df0f6d8c96c0b151f6f5908f719cdb1c6a","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu230_be8b2e63","title":"trivy secret","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"f362a967ef85cde8b4b69f3dfcd2bb82f50a15a279d7c661fa29954e94de4ae9"} |
| 709 | 2026-10-20T13:25:14.131Z | finding.record | {"seq":709,"at":"2026-10-20T13:25:14.131Z","prevHash":"f362a967ef85cde8b4b69f3dfcd2bb82f50a15a279d7c661fa29954e94de4ae9","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu235_ed1b087e","severity":"critical","verification":"hypothesis","title":"[trivy] secret aws-access-key-id in src/config.js","hash":"d5180151ba316b115bad53e6e0c7388000d3babb5975f63884dfaedba60d5679" |
| 710 | 2026-10-20T13:25:14.135Z | evidence.add | {"seq":710,"at":"2026-10-20T13:25:14.135Z","prevHash":"d5180151ba316b115bad53e6e0c7388000d3babb5975f63884dfaedba60d5679","action":"evidence.add","taskId":"task_mvgptyn7_8a3bfeab","evidenceId":"ev_mvgpu239_5fc20afd","title":"trivy secret","target":"D:\\dsh-ABM\\armorbreak\\fixtures\\gate-b-sample","hash":"3f15e5bb7375a26b9d7881a0fb501e3f731d55684260dc02290326db171e1dbb"} |
| 711 | 2026-10-20T13:25:14.140Z | finding.record | {"seq":711,"at":"2026-10-20T13:25:14.140Z","prevHash":"3f15e5bb7375a26b9d7881a0fb501e3f731d55684260dc02290326db171e1dbb","action":"finding.record","taskId":"task_mvgptyn7_8a3bfeab","findingId":"fnd_mvgpu23c_42e4088d","severity":"critical","verification":"hypothesis","title":"[trivy] secret github-pat in src/config.js","hash":"135a79bbf03846858e4c7b43d0c67533bcda8702b9de0c3a995378887fab7441"} |
| 712 | 2026-10-20T13:25:14.148Z | capability.run.end | {"seq":712,"at":"2026-10-20T13:25:14.148Z","prevHash":"135a79bbf03846858e4c7b43d0c67533bcda8702b9de0c3a995378887fab7441","action":"capability.run.end","taskId":"task_mvgptyn7_8a3bfeab","capability":"sast.trivy","status":"ok","durationMs":1137,"evidence":69,"findings":67,"targetSha256":null,"hash":"cd5d7e712c5a394eeca3dc4b18d741159a093e4d86c905a26ec7df79405b3f5a"} |
| 713 | 2026-10-20T13:25:14.160Z | task.transition | {"seq":713,"at":"2026-10-20T13:25:14.160Z","prevHash":"cd5d7e712c5a394eeca3dc4b18d741159a093e4d86c905a26ec7df79405b3f5a","action":"task.transition","taskId":"task_mvgptyn7_8a3bfeab","to":"COLLECTING_EVIDENCE","reason":"step evidence collected","hash":"9a8b26e783e3e6ff8e589aa8d4c2965fee1ccd7f39b3b664d65641bcd1d7f9cd"} |
| 714 | 2026-10-20T13:25:14.164Z | task.transition | {"seq":714,"at":"2026-10-20T13:25:14.164Z","prevHash":"9a8b26e783e3e6ff8e589aa8d4c2965fee1ccd7f39b3b664d65641bcd1d7f9cd","action":"task.transition","taskId":"task_mvgptyn7_8a3bfeab","to":"VERIFYING","reason":"all steps settled","hash":"753a40aa6cb65dc5765e26f251f193c67a84a4fced81f95cff6461191f5bacf1"} |
| 715 | 2026-10-20T13:25:14.179Z | task.transition | {"seq":715,"at":"2026-10-20T13:25:14.179Z","prevHash":"753a40aa6cb65dc5765e26f251f193c67a84a4fced81f95cff6461191f5bacf1","action":"task.transition","taskId":"task_mvgptyn7_8a3bfeab","to":"REPORTING","reason":"generating report","hash":"8589264cfbab48ff83758176342203973567fdee20d921cbeb6f0cd7ba58f23c"} |

## 7. 复现条件、限制与不确定性

- 运行环境：win32/x64，Node v24.16.0，DSH unknown，Profile desktop。
- 隔离提供者：docker。
- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。
- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。
- evidence chain verified (150 records)

---

由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。
