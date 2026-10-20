# 兼容性矩阵

## 1. 运行时

| 项 | 基线 | 状态 | 验证方式 |
|---|---|---|---|
| DeepSeek Harness Desktop | 0.2.1-rc.2 | ✅ 目标平台 | 桌面 `app.asar/dsh/package.json`；`dsh --version` |
| Cordis | 4.0.x | ✅ 使用稳定 API | `ctx.tools.register` / `ctx.skills.register` / `ctx.webServer.register` / `ctx.approval.request` / `ctx.get` |
| Node.js（应用内置） | 24.21.0 | ✅ | `runtime/versions.json` |
| Node.js（系统，测试用） | v24.16.0 | ✅ 单元/集成测试通过 | `node --test` |
| pnpm（应用内置） | 11.28.5 | ✅ 安装器使用 | `dsh plugin ... add` 实测 |
| 操作系统 | Windows 11 x64 | ✅ 已验证 | 本机 |
| 操作系统 | macOS / Linux 桌面 | ⚠️ 未实测（代码只使用 Node 标准能力，理论上可用；外部工具探测按 PATH 工作） | 未验证 |
| 平台 | Desktop profile（`desktop`） | ✅ 已安装并实测：`applied`、live Loader 两行、`/armorbreak/state` 200 | `plugin_manager install_bundle/list_bundles` + HTTP 探测 |
| 平台 | CLI `web` profile（同运行时） | ✅ 实测启动 + 状态路由 + preset 激活 | `dsh --profile abmtest ...` |
| 平台 | CLI `headless` profile | ⚠️ 部分：bundle 行中 Host 状态路由保持 pending（等待 `webServer`），preset 行等待 `agentPresets`；工具可在 overlay 挂为全局行使用 | 实测 |
| 平台 | TUI profile | ⚠️ 未实测 | — |

## 2. 使用的 Harness API（全部已从安装产物核对）

| API | 用途 | 兼容性 |
|---|---|---|
| `@deepseek-ai/dsh-agent-preset` 行（`config.id/plugins`） | 注册「破甲模式」 | ✅ 0.2.1-rc.2 官方格式（与 shipped `presets/*.patch.yml` 一致） |
| `@deepseek-ai/dsh-persona`（`prefix`） | 专业 persona | ✅ |
| `ctx.tools.register(ToolDefinition)` | 9 个模型工具 | ✅ `{name, description, parameters(JSON Schema), output, execute}` |
| `ctx.skills.register(SkillRegistration)` | 7 个技能 | ✅ `{name, description, content, whenToUse, resourceBase}` |
| `ctx.webServer.register({kind, path, handler})` | `/armorbreak/state` | ✅ 0.2.1 路由契约；旧版/未来版如变更会在 apply 中降级（不阻断插件） |
| `ctx.approval.request({agent, toolName, callId, reason, signal})` | L1/L2 平台审批 | ✅ 审批服务存在时启用；不存在时 fail-closed |
| `ctx.get(name)` | 可选服务探测（approval） | ✅ |
| `package.json dsh.bundle.patch` | 组合包声明 | ✅ |
| `package.json dsh.client` | 浏览器半扫描 | ✅ `dsh-client-modules` 已把 `dsh-armorbreak/client.js` 编入启动图 |
| 浏览器模块格式 `window.__ModuleLoader__.load({id, factory})` | UI 状态卡 | ✅ 与官方模板一致 |
| Client Slot `conversation.composer.dock` | 状态卡挂载点 | ✅ 实测 Slot 存在且注册成功（注入 `slots`） |
| Client locale / theme token | UI 文案与配色 | ⚠️ 可选：locale 服务存在时使用，否则中文默认；主题用 `--dsw-alias-*` token |

## 3. 外部工具矩阵（可选依赖，缺失不阻断内置能力）

| 工具 | 用途 | 检测方式 | 接入状态 |
|---|---|---|---|
| Ghidra / Rizin / radare2 | 反汇编/反编译 | PATH + `GHIDRA_HOME` | 探测 + 安装指引（输出尚未接入报告） |
| YARA | 规则匹配 | PATH | 探测；内置简化规则匹配替代 |
| JADX / apktool / adb / Frida | Android | PATH | 探测；内置 APK/AXML/DEX/签名解析替代 |
| Semgrep / CodeQL / Trivy / Syft / Gitleaks | SAST/供应链 | PATH | 探测；内置规则/盘点/SBOM 替代 |
| TShark / Zeek / Suricata / Nmap | 网络 | PATH | 探测；内置 PCAP 解析替代；Nmap 未接入 L2 |
| Volatility3 / capa / FLOSS | 取证 | PATH | 探测；内置文件级取证替代 |
| Docker | L1 隔离 | PATH + `docker info` | 实际用于容器执行（L1，需审批） |
| LibreOffice (`soffice`) | PDF 报告 | PATH | 实际用于 HTML→PDF 转换 |

## 4. 能力与风险级别

| 域 | 能力数 | 风险 | 是否联网 |
|---|---|---|---|
| binary | 5 | L0 | 否 |
| forensics | 6 | L0 | 否 |
| android | 5 | L0 | 否 |
| network | 7 | L0 | 否 |
| web | 4 | L0 | 否 |
| sast | 5 | L0 | 否 |
| ctf | 5 | L0 | 否 |
| live | 2 | L2 / L1 | 是（仅授权 + 审批后） |

合计 **39 个能力 / 8 个域**（`armorbreak_capabilities` 实时列出）。

## 5. 不兼容/降级行为

1. **旧版 Harness（如 npm `@deepseek-ai/dsh@0.1.0-rc.6`）**：没有 `dsh-agent-preset` 包，不能作为目标运行时；
   本 bundle 的 preset 行会因缺少 `@deepseek-ai/dsh-agent-preset` 而无法加载。
2. **缺少 `webServer` 的组合**：Host 状态路由保持 pending，不影响工具与 preset（已在 headless 实测）。
3. **缺少 `agentPresets` 的组合**：preset 行保持 pending，工具可作为全局行挂载（开发 overlay 已验证）。
4. **浏览器面板接口变更**：`overridden/restart-required` 以 `plugin_manager` 返回为准，不根据日志猜测。
