# 使用指南

## 1. 选择模式

新建会话 → 模式选择 → **破甲模式**。该模式自带专业 persona、**10 个 DSH 模型工具**（`armorbreak_*`）与
**7 个内置技能**；文件/Shell 等标准工具由宿主提供，不计入 ArmorBreak 工具数。不要把它与 MCP Server 的 **7 个工具**混为一个数字。
输入框下方会出现 ArmorBreak 状态卡，展开可看能力数量、隔离状态与最近任务。

## 2. 第一个任务（推荐顺序）

```
1. armorbreak_health                                   # 先看真实环境与能力
2. armorbreak_scope action=authorize ...               # 仅当目标在工作区外，或要做 L1/L2 时
3. armorbreak_workflow action=start workflow=... target=<绝对路径> workspace=<绝对路径>
4. armorbreak_workflow action=run taskId=<id>
5. armorbreak_report taskId=<id> format=markdown|html|json|sarif|pdf
```

也可以不用工作流，直接单能力执行：

```
armorbreak_analyze capability=binary.identify target="D:\samples\a.exe" workspace="D:\work"
```

`armorbreak_analyze` 不传 `taskId` 时会自动创建临时任务；传 `taskId` 则把结果并入已有任务。

## 3. 典型场景

### 3.1 样本初筛（离线，不执行）

- `armorbreak_workflow BinaryStaticAnalysis` + `target=<样本路径>`
- 关注：格式/架构、节表、导入组合、字符串线索、熵（加壳假设）、IOC、哈希。
- 报告中的 verification：结构事实 `observed`，加壳/恶意性判断 `hypothesis`。

### 3.2 APK 安全审计

- `armorbreak_workflow AndroidAPKReview`
- 关注：导出组件、权限、`debuggable`/`allowBackup`、cleartext、签名证书、DEX 概况。

### 3.3 抓包取证

- `armorbreak_workflow PCAPInvestigation`
- 关注：会话表、DNS、TLS SNI、明文 HTTP、IOC、异常模式（heuristic）。

### 3.4 代码/供应链审计

- `armorbreak_workflow WebCodeSecurityReview target=<代码目录>`（目录型目标）
- 重点：危险 sink、密钥泄漏、依赖盘点/SBOM；扫描告警必须复核后才算漏洞。

### 3.5 CTF / 靶场

- `armorbreak_analyze capability=ctf.classify`，按需 `ctf.decode`（options.transforms）→ `ctf.crypto_basics` → `ctf.flag_scan`。
- 或者 `armorbreak_workflow CTFArtifactAnalysis`。

### 3.6 授权主动验证（L2，默认拒绝）

只有当目标被授权记录覆盖且平台审批通过时才会执行：

```
armorbreak_scope action=authorize purpose="..." operator="..." networkTargets=["10.20.0.0/16"] riskCeiling=L2
armorbreak_analyze capability=live.http_probe options={"url":"http://10.20.0.5/health"} taskId=<id>
```

没有授权/审批会得到结构化拒绝；**不要换用 shell 或其它工具绕过**——那同样违反范围策略。

## 4. 任务与证据

- 任务数据在 `<workspace>/.armorbreak/tasks/<taskId>/`：`task.json`、`evidence.jsonl`、`findings.json`、`artifacts/`、`reports/`。
- `armorbreak_evidence action=list` 查看证据/发现；`action=chain` 校验哈希链；`action=verify` 更新验证状态
  （必须基于新证据，不能把 hypothesis 直接改成 observed）。
- 报告时间戳命名，不覆盖历史报告。

## 5. 结果可信度约定

| verification | 含义 | 报告中的处理 |
|---|---|---|
| observed | 工具直接解析/观测到的事实 | 可作为结论引用 |
| corroborated | 多个独立来源相互印证 | 结论较强，仍注明来源 |
| hypothesis | 启发式推断（加壳、beaconing、危险模式） | 必须人工复核 |
| unverified | 未验证线索 | 只能进"待验证" |

## 6. 常见问题

- **L1 被拒绝**：本机没有可用的 Docker 守护进程，或没有通过平台审批——这是默认设计。
- **`armorbreak_capabilities` 显示某外部工具缺失**：内置纯 JS 能力仍可完成对应分析的一部分；安装外部工具后重试可获得更完整结果（当前版本外部工具用于探测与指引，尚未把 Ghidra/JADX 等输出接入 report——见 known-issues）。
- **报告 PDF 失败**：安装 LibreOffice 或改用 `format=html`。
- **跨目录分析被拒**：传 `workspace` 参数指向目标所在目录，或用 `armorbreak_scope` 授权其路径。
