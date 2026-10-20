# ArmorBreak「破甲模式」环境与架构审计报告（Phase 0）

- 项目代号：ARMORBREAK
- 审计时间：2026-10-20（America/Los_Angeles）
- 审计对象：本机正在运行的 DeepSeek Harness Desktop 及其 Desktop profile
- 结论口径：本报告只写**已从运行中的安装产物读取/验证**的事实，与“推断”“未验证”分开列示。

---

## 1. 运行环境（已验证）

| 项 | 值 | 证据 |
|---|---|---|
| 操作系统 | Windows（win32, x64） | `process.platform` / 运行时 `runtime.json` |
| Harness 形态 | Electron 桌面应用「DeepSeek Harness」 | 安装目录 `%LOCALAPPDATA%\Programs\DeepSeek Harness` |
| Harness 运行时版本 | **0.2.1-rc.2**（desktop runtime） | `resources/app.asar/dsh/package.json` → `@deepseek-ai/dsh-desktop-runtime@0.2.1-rc.2`；CLI wrapper `--version` 输出 `0.2.1-rc.2` |
| 本次会话使用的 CLI | `resources/runtime/cli/bin/dsh.cmd` → `ELECTRON_RUN_AS_NODE=1 "DeepSeek Harness.exe" .../app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js` | 直接读取 `dsh.cmd` 内容并执行成功 |
| 独立 npm CLI（另一份安装） | `@deepseek-ai/dsh@0.1.0-rc.6`（全局 npm） | `C:\Users\Lenovo\AppData\Roaming\npm\node_modules\@deepseek-ai\dsh\package.json`。**不是**本 GUI 的运行时，不作为目标基线 |
| Node（应用内置） | 24.21.0 | `resources/runtime/versions.json` |
| pnpm（应用内置） | 11.28.5 | 同上 |
| Python（应用内置） | 3.12.14（含 numpy/pandas/openpyxl/python-docx 等） | `runtime.json` |
| 系统 node | v24.16.0 | `node --version` |
| DSH_HOME | `C:\Users\Lenovo\.dsh` | 环境变量 |
| Profile | `desktop`，目录 `C:\Users\Lenovo\.dsh\profiles\desktop` | 环境变量 `DSH_PROFILE` / `DSH_PROFILE_DIR` |
| 当前会话 | `session-224350ad-81a1-459b-a85c-afb34f22a051`，模型 `deepseek-flash` | 运行时上下文 |
| Web GUI | `http://127.0.0.1:53824` | 运行时上下文 |
| 文件策略 | `danger-full-access`；本会话审批提示被禁用 | 运行时上下文 |
| 工作区 | `D:\dsh-ABM`（空目录起步） | `Get-Location` |

## 2. Profile 组成（已验证）

`profiles/desktop/package.json` 选择的 bundle 层（顺序即 patch 叠加顺序）：

1. `@deepseek-ai/dsh-base`
2. `@deepseek-ai/dsh-web-app`
3. `@deepseek-ai/dsh-experimental-voice-input-bundle`
4. `@deepseek-ai/dsh-experimental-agent-team-profile`
5. `@deepseek-ai/dsh-experimental-auto-review`
6. `dsh-codex-effort-slider`（第三方 bundle，已在 profile 中安装，可作为第三方插件的真实样板）
7. `@deepseek-ai/dsh-experimental-inspector-profile`

`profiles/desktop/cordis.patch.yml` 是用户覆盖层（主题、权限预设、模型选择等）。
`profiles/desktop/cordis.yml` 固定为空 `[]`：profile 树完全由 bundle patch 叠加生成。
pnpm 落盘形态（`node_modules/.modules.yaml`）：`nodeLinker: hoisted`，`hoistPattern: ["*"]`，`autoInstallPeers: false`。

## 3. 插件与组合机制（已验证的接口事实）

### 3.1 Bundle（组合包）

- 一个包只要在 `package.json` 里声明 `dsh.bundle.patch`（字符串或字符串数组）即成为可安装 bundle；安装后其 patch 层参与 Loader 组合。
- 当前版本（0.2.1）的官方 `@deepseek-ai/dsh-web-app` 的 patch 列表为：
  `./cordis.patch.yml` + `./presets/{standard,ptc,minimal,cordis}.patch.yml`。
- 已核查 `dsh-base` / `dsh-web-app` 的完整 patch，确认：`insert`、按 `id` 覆盖（整段 `config` 替换）、`group: true` + `isolate`、`!!js` 表达式、`disabled` 布尔/表达式均为现行方言。

### 3.2 Agent preset（模式）

- 模式声明 = 一条 `@deepseek-ai/dsh-agent-preset` Loader 行：
  `config: { id, name, description, order, plugins: [<子插件行>] }`。
- 模式注册表 `@deepseek-ai/dsh-agent-preset-registry` 由 `dsh-web-app` patch 插入（`config.default: standard`），registry 自身不扫描目录；**新模式只能由 bundle patch 插行提供**（这正是官方 README 的说明）。
- 已读取 shipped 的 `presets/standard.patch.yml` 与 `presets/minimal.patch.yml`，得到子插件行的权威写法（persona / 工具 / group+isolate）。
- 模式子插件中提供 Service 时必须 `isolate`，仅注册工具/提示词段的插件不需要 isolate（官方 patch 注释明确）。
- 模式激活审计：导入失败、缺服务、全局泄漏服务都会导致该定义不可用；等待 Host 服务的行会保持挂载并重审计。

### 3.3 Host 插件与服务

- Host 插件导出形式：`export function apply(ctx, config)` + 可选 `export const inject` / `export const Config`，或默认导出 Service 类。
- 服务契约由 `cordis_inspect_query`（Host `Service` provider）读取；已确认本机存在 `tools`、`skills`、`agentPresets`、`agentTeams`、`subagents`、`workingDirectory`、`webServer`、`approval` 等 100+ 服务。
- 工具注册：`ctx.tools.register(ToolDefinition)`。`ToolDefinition` = `{ name, description, parameters(JSON Schema), output:{ schema, render }, execute(args, exec), ... }`（已从 `dsh-tools` 类型声明核对；`exec.signal` 用于协作取消）。
- 技能注册：`ctx.skills.register({ name, description, content, whenToUse?, resourceBase?, invocation? })`（已从 `dsh-skill` 类型声明核对）；文件系统 provider 亦可由 `skill-filesystem` 的 `customSkillDirs` 提供。
- 客户端（浏览器）插件：包内声明 `dsh.client`，导出一个 `./client` 模块；`client.js` 以 `window.__ModuleLoader__.load({ id, factory(require){...} })` 形式注册，`inject: ['slots']` 后向 Slot 注册 React 组件。已读取官方 `decoration` 模板与一个已在用第三方 UI 插件（`dsh-codex-effort-slider`）核实此形态。

### 3.4 安装 / 启用 / 卸载

- 会话内 `plugin_manager` 工具：`install_bundle`（target 为本地包目录绝对路径）、`list_bundles`、`set_bundle`、`remove_bundle`。安装会修改 profile 的 `package.json`（dependencies + `dsh.profile.bundles`）并执行 pnpm 安装。
- 非 desktop profile 可用 CLI：`dsh plugin --profile <p> add link:<绝对路径>`（`desktop` profile 被 Electron 独占，CLI 拒绝管理 —— 已从第三方插件 README 核实；本次开发用独立的 `abmtest` 测试 profile 迭代）。
- 从 `dsh-web-app` 模板成功创建了测试 profile `C:\Users\Lenovo\.dsh\profiles\abmtest`（`dsh --profile abmtest --from-default-profile web --dump-config` 通过）。
- 新增 bundle 可能通过 HMR 热激活；**替换已安装包的代码需要重启进程**才能加载新的 JS 模块代际。

## 4. 运行时策略与安全相关能力（已验证）

| 能力 | 事实 | 对 ArmorBreak 的意义 |
|---|---|---|
| 文件策略 | 本会话 `danger-full-access`，审批禁用 | 插件可以读写工作区；但 ArmorBreak 自己的 L0/L1/L2/L3 必须**在代码层**强制，不能继承这个宽松策略 |
| 沙箱 | `dsh-sandbox-local` + `dsh-sandbox-policy`（base patch 可覆盖 mode/workspaceRoot） | 本模式不依赖外层沙箱，自带 ScopePolicy |
| 审批 | `dsh-user-approval`（`ctx.approval`）+ `dsh-permission-presets` | L2 审批优先接入 ctx.approval；v1 以“人工输入确认码”作为可执行的人工闸门 |
| 子进程 | `ctx.subprocess` 服务（`spawn(spec)`）与 node `child_process.execFile` 均可用 | 外部工具适配器只允许**参数数组**（无 shell），加超时/输出上限/环境变量清洗 |
| 网络 | `ctx.web`（搜索/抓取）+ 插件内 fetch 均可用 | 主动网络探测必须被 ScopePolicy 拦截；离线分析不得联网 |
| 技能 | `ctx.skills.register` 支持运行时注册（无需落盘目录） | ArmorBreak 的 6 个专业技能随包内置注册，规避安装路径问题 |
| UI Slot | Client `Slots.listSubTree` 可枚举实时 Slot；`Theme.listTokens` 可读主题 token | Phase 5 的面板必须注册到现有 Slot，不替换 app root |
| HMR | `dsh-hmr` 行存在；默认只热重载 profile 配置，模块根需显式 opt-in | 开发期用测试 profile + CLI 重启验证；最终安装后可能需要用户重启一次 |

## 5. 与任务书假设的差异（必须修正的地方）

1. **运行时版本**：任务书示例是 `@deepseek-ai/dsh-agent-preset` 的 `config.plugins` 写法，本机 0.2.1-rc.2 完全支持；但任务书引用的 GitHub README 路径（`packages/preset/agent-preset`）与**本机桌面产物布局**不同，实际以 `resources/app.asar/dsh/node_modules/@deepseek-ai/*/README.md` 与 `lib/types` 为准。
2. **npm 全局 CLI 0.1.0-rc.6 不是目标运行时**；它缺少 `dsh-agent-preset` 等 0.2.1 包。任何兼容性结论必须以桌面 0.2.1-rc.2 为准。
3. **app.asar 不可被 shell 遍历**：只有 Host 的 read 工具能读取 asar 内文件；shell/glob/grep 无法访问。本项目的测试与构建一律在 `D:\dsh-ABM` 内完成，不依赖 asar 路径。
4. **Desktop profile 只能由 Electron 应用自身管理**：CLI 明确拒绝 `--profile desktop`。因此最终安装走会话内 `plugin_manager.install_bundle`；开发迭代走 `abmtest` 测试 profile。
5. **任务书提到“Ghidra/JADX/Semgrep/TSHark 等工具”并非本机现成能力**：本机是否安装这些外部工具需由依赖探测决定；缺失时适配器必须返回“缺少什么/为什么需要/如何安装/替代方案”，核心能力必须有零依赖的纯 Node 回退实现（离线解析），不得把缺失工具伪装成已运行。
6. **PDF 报告**：应用内置 Python 无 PDF 生成库；PDF 导出将经由可探测的 LibreOffice（soffice）转换，缺失时明确报错并提供 Markdown/HTML/JSON/SARIF 替代，不伪造 PDF。

## 6. 兼容性基线（供实现使用）

| 依赖面 | 基线 | 使用方式 |
|---|---|---|
| Cordis Loader patch | 0.2.1-rc.2 方言 | `insert` + `preset-<id>` 行 + `cordis:group`/`isolate` |
| Agent preset | `@deepseek-ai/dsh-agent-preset@0.2.1-rc.2` | 一条声明行，`config.id = armorbreak` |
| 工具注册 | `ToolDefinition`（name/description/parameters JSON Schema/output/execute） | 纯 JS 对象，不 import `@deepseek-ai/*`，保证 profile 内可解析 |
| 技能注册 | `ctx.skills.register(SkillRegistration)` | 预设子插件内注册，落入该 preset 的 skill 层 |
| 浏览器扩展 | `dsh.client` + `window.__ModuleLoader__.load` | 同一 bundle 根插件作为 client id |
| 安装 | `plugin_manager.install_bundle`（本地目录） | 零依赖包，无构建步骤、无安装脚本 |
| 测试 | 系统 node v24.16 `node --test` | 纯函数模块直接单测；集成用 `abmtest` profile 启动真实运行时 |

## 7. 结论

- 目标运行时 **0.2.1-rc.2** 的原生扩展点足以实现「破甲模式」：bundle patch 声明 preset、Host 插件提供服务、preset 子插件注册工具与技能、`dsh.client` 提供 UI 面板。
- 本项目采用**零运行时依赖、无构建步骤**的纯 ESM JavaScript 实现，避免 profile 安装时的依赖/网络/构建风险；所有 `@deepseek-ai/*` 能力只通过 `ctx` 服务与 Loader 组合获得，不直接 import。
- Phase 0 的假设已全部落到可核对的产物与命令上；后续实现中如发现新差异，将更新本报告与兼容性矩阵，而不是修改结论。
