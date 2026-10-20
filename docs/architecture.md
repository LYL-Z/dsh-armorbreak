# 架构设计（ArmorBreak）

## 1. 分层与职责

```
┌──────────────────────────────────────────────────────────────────────────┐
│ H. UI Integration        client.js → conversation.composer.dock 状态卡    │
│                          GET /armorbreak/state（只读、脱敏、同源）          │
├──────────────────────────────────────────────────────────────────────────┤
│ A. Agent Persona         @deepseek-ai/dsh-persona（preset 作用域）          │
│ B. Skills                7 个内置技能，ctx.skills.register（preset 层）    │
│ C. Capability Registry   lib/core/capabilities.js + 各域 manifest.js       │
│ D. Tool Adapter Layer    lib/analyzers/<domain>/*（统一 run(input) 契约）   │
│ E. Workflow Orchestrator lib/core/workflows.js + tasks.js（显式状态机）     │
│ F. Execution & Isolation lib/core/runner.js + scope.js + health.js         │
│ G. Evidence & Reporting  evidence.js + audit.js + reports.js               │
└──────────────────────────────────────────────────────────────────────────┘
```

**耦合规则**：`lib/core/*` 不 import 任何 `@deepseek-ai/*` 或第三方包；能力实现只依赖 `node:*`；
工具层是唯一把 Cordis 上下文（`ctx.tools` / `ctx.get('approval')`）与核心运行时连接起来的薄层。
因此核心可脱离 Harness 单测（见 `tests/core-*.test.mjs`）。

## 2. Cordis 组合

`cordis.patch.yml` 只做两件事（不覆盖任何既有行）：

```yaml
- insert:
    - id: armorbreak            # Host 行：bundle 根插件（状态路由 + 浏览器插件 id）
      name: 'dsh-armorbreak'
    - id: preset-armorbreak     # 模式声明
      name: '@deepseek-ai/dsh-agent-preset'
      config:
        id: armorbreak
        plugins: [persona, 标准文件/Shell 工具, 压缩组, tool-skill,
                  dsh-armorbreak/tools, dsh-armorbreak/skills]
```

- 浏览器半通过 `package.json` 的 `dsh.client` 挂到同一个包 id；`dsh-client-modules` 把它编入
  `window.__DSH_BOOT__` 的插件 bundle 列表。
- `dsh-armorbreak/tools` 与 `dsh-armorbreak/skills` 是同一包的子路径导出，只在该 preset 的作用域内注册：
  工具进入该 preset 的 tools 层，技能进入该 preset 的 skills 层；标准模式看不到它们。
- Host 行声明 `inject: ['webServer']`：在无 Web 服务端的组合（headless/tui）里保持 pending，
  不会拖垮整个插件树；preset 行在无 `agentPresets` 的组合里同样保持 pending（已验证）。

## 3. 运行时单例

`lib/core/runtime.js` 用 `globalThis[Symbol.for('dsh.armorbreak.runtime')]` 持有进程级单例，
避免 HMR/重复模块代际导致两个运行时（两份任务/策略状态）。单例包含：

- `CapabilityRegistry`：扫描 `lib/analyzers/*/manifest.js`，校验契约，收集诊断；
- `HealthService`：外部工具探测（PATH + GHIDRA_HOME）、Docker/隔离探测、环境快照；
- `ScopePolicy`：授权记录（签名）与审批记录，持久化在 `$DSH_HOME/armorbreak/policy.json`；
- `workspaces`：每个工作区一个 `TaskStore` + `AuditLog`，数据写在工作区内 `<workspace>/.armorbreak/`；
- `ExecutionRunner`：唯一执行入口。

## 4. 执行管线

```
armorbreak_analyze / armorbreak_workflow / runner.runCapability
  │
  ├─ 1. 能力解析（registry）        ── 未知能力 → 可操作错误
  ├─ 2. 任务状态机推进              CREATED→SCOPE_VALIDATION→ENVIRONMENT_CHECK→PLANNING
  ├─ 3. 策略门（scope.check*）      L0 路径 / L1 隔离+审批 / L2 授权+审批+限速 / L3 拒绝
  │       └─ 平台审批桥：ctx.approval.request({agent, toolName, callId, reason, signal})
  ├─ 4. 输入读取（有界）            readBounded(maxInputBytes=32MiB)，目录型给 listFiles/readFile
  ├─ 5. 能力执行（超时/取消）        AbortSignal 协作 + 60s 默认预算（可调，上限 5min）
  ├─ 6. 结果归一化                  summary/data/findings/evidence/artifacts，256KiB 截断
  ├─ 7. 证据落盘（哈希链）           执行证据 + 能力证据 + 发现证据；findings 去重/合并
  ├─ 8. 审计（哈希链、脱敏）          capability.run.start/end、policy.denied、approval…
  └─ 9. 任务收尾                     VERIFYING→REPORTING→COMPLETED/PARTIAL_SUCCESS
```

异常路径：策略拒绝 → `PolicyDeniedError`（任务 REJECTED，不执行）；能力失败 → 步骤 FAILED，
继续执行其余独立步骤，最终 `PARTIAL_SUCCESS` 并保留已有证据；超时 → `TIMEOUT`；取消 → `CANCELLED`。

## 5. 数据模型

```
<workspace>/.armorbreak/
  audit.jsonl                  # 工作区级审计日志（哈希链）
  tasks/<taskId>/
    task.json                  # 任务、状态轨迹、步骤、统计、报告引用
    evidence.jsonl             # 证据（哈希链，含目标 SHA-256）
    findings.json              # 发现（指纹去重、验证状态、CWE/CVSS）
    artifacts/                 # 能力产物
    reports/                   # 生成的报告（时间戳命名，不覆盖）
```

`$DSH_HOME/armorbreak/policy.json`：授权记录（签名）与审批记录（短时效、使用次数上限）。
所有写入均为原子写（temp + rename），审计/证据为追加 JSONL。

## 6. 能力契约

每个 `lib/analyzers/<domain>/manifest.js` 导出：
`{ domain, capabilities: [{ id, title, description, riskLevel, targetKind?, externalTools?, params, networkTarget?, run(input) }] }`。
`run(input)` 接收 `{targetPath, buffer, text, options, limits, env}`，返回
`{summary, data, findings?, evidence?, artifacts?, meta?}`。完整契约见 [CONTRACT.md](CONTRACT.md)。

核心对能力的保证：路径已校验、字节已限定、signal 可取消、输出已归一化、证据已落盘；
能力自身必须：纯离线（除 L1/L2）、不执行样本、不拼 shell、有界、确定性、不可信内容不当指令。

## 7. 已知架构约束

- **预设子插件解析**：模式声明里的子插件按包名解析，因此 bundle 必须安装到 profile
  （开发期可用 `link:` 安装到测试 profile）。
- **代码更新需要新模块代际**：替换已安装 bundle 的 JS 后需要重启 Harness；新增 bundle 可热激活。
- **状态路由无鉴权**：`/armorbreak/state` 只在本机 loopback 上提供**脱敏只读**快照（无摘录/无凭据）；
  这不是权限边界，真正的权限边界在 runner/scope 内。
- **工作区默认值**：缺省为进程 cwd；跨目录分析必须显式传 `workspace` 参数（工具描述已说明）。
