# ArmorBreak V2.0 Threat Model (M1-02)

> 基线：v1.2.0 / `1c8a1c5`。本模型只覆盖已存在或本版将要实现的入口；未实现入口标注 `NOT_IMPLEMENTED`，不写成已受控。
> 所有者：Lead（安全策略）。复审周期：每个 M1 任务完成时、每次新增工具/UI/安装入口时、每次 DSH 升级后。

## 1. 资产

| 资产 | 说明 | 最高影响 |
|---|---|---|
| 工作区样本与证据 | 原始工件、`evidence.jsonl`、报告、哈希链 | 数据泄露/证据不可信 |
| 授权与审批记录 | `.armorbreak/policy.json`、approval records | 越权执行 |
| 宿主机 | DSH Host 进程、workspace、环境变量、容器/VM | RCE/宿主逃逸 |
| 外部工具执行 | TShark/Syft/JADX/Ghidra/Docker | 命令执行/供应链 |
| 模型上下文 | 工具结果、RAG/文档、文件内容 | Prompt Injection/权限提升 |
| 安装器与目录 | 未来 Catalog/Installer | 供应链投毒/任意代码执行 |
| 审计与日志 | `audit.jsonl`、报告 | 篡改/敏感信息泄漏 |

## 2. 入口与信任边界

| 入口 | 风险 | Owner | 现有/计划 Guard | 测试 |
|---|---|---|---|---|
| 模型工具调用（10 个 armorbreak_*） | 参数注入、越权、模型自批 | Lead | `scope.js` + runner approval + L3 hard deny；M1-03 PolicyGateway 统一路由 | 本任务新增 gateway 覆盖测试；runner-gates |
| UI loopback routes `/armorbreak/*` | CSRF/跨源/目录枚举 | UI Lead | loopback guard、GET/POST、`x-armorbreak-ui`、仅 L0 actions | `ui-api.test.mjs`；M1-06 负向测试 |
| Agent preset / persona | 系统提示注入、工具边界 | Lead | preset 不含 shell/web 通用工具；prompt 把工件当不可信数据 | preset 检查 + M1-03 |
| 外部工具 argv | 参数注入/PATH 污染/输出投毒 | Lead | argv 数组、白名单、无 shell、bounded output、missing-tool guidance | external-adapters-v2 |
| Docker/Podman L1 | 逃逸、宿主挂载、网络 | Lead | digest pin、no network、read-only、non-root、pids/mem/cpu、approval+self-test | verify-l1-provider；M1-03 |
| 授权/审批文件 | 本地伪造、重放、跨会话 | Lead | 平台 approval callback、任务/目标匹配、哈希链；M1-04 加身份绑定 | core-policy/hardening；M1-04 |
| 外部工具/组件安装 | 供应链/自动执行 | Lead | **尚无自动安装器**；M2 前一律人工审批，模型禁止自批 | gateway 的 `supplychain.install` 拒绝测试 |
| 知识/RAG/文档 | Prompt Injection、版权/敏感数据 | Knowledge Lead | 内容当不可信数据；M2 采集中；不因文档内容升权 | M2 知识安全测试（未实现） |
| 模型端点/API key | 未授权端点、密钥泄漏 | Lead | 仅用户配置，不进入工具输出；无自动第三方账号收集 | 环境/凭据纪律 review |
| macOS/Linux/VM | 平台差异、隔离能力 | Platform Lead | **未实测**；不得声称支持 | 发布时标 NOT_RUN |

## 3. 关键滥用场景与反制

1. **模型尝试给自己授权**：`armorbreak_scope` 属 operator-only action；PolicyGateway 对 `identity.kind==='model'` 恒拒绝并审计。M1-04 再引入不可伪造的 approval token。
2. **工具输出注入**：所有文件/PCAP/网页内容只作为 data；不得触发 scope/安装/网络动作。现有 preset persona + 工具边界；M1-03 gateway 只接受结构化 action，不接受自然语言授权。
3. **L3 绕过**：L3 能力不存在且 runner 先拒绝；新增外部适配器均为 L0；L1 必须 provider self-test + approval。
4. **跨工作区读取**：scope.checkFile 使用 realpath 包含检查；M1-06 增 loopback/CSRF/会话绑定测试。
5. **PATH 污染/伪造工具**：适配器解析固定安装路径或显式 env override（仍要求 operator 配置），版本探测只是提示，不构成信任。
6. **安装即执行**：M2 前无自动安装；catalog/installer 必须 dry-run → 审批 → staging → verify → activate；模型不能批准。
7. **本地授权伪造**：本机写权限用户仍可改 policy.json；这是剩余风险，M1-04 通过身份绑定/签名提高门槛，但不能宣称绝对防伪造。

## 4. 安全不变量

- 模型不能铸造授权、批准安装、改变 L1/L2 审批结果或关闭审计。
- 未知 action 默认拒绝；L3 无执行通道。
- 所有外部代码执行需要 operator identity + precise plan；自动下载/安装/启用是三个独立动作。
- 证据链必须可校验；迁移/回滚不得丢失旧记录。
