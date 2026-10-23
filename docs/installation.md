# 安装、启用、卸载与故障排查

## 目标环境

- DeepSeek Harness Desktop **0.2.1-rc.2**（Windows/macOS/Linux 桌面版；本机验证于 Windows 11 x64）
- 不要求 Node/pnpm 全局可用：安装由 Harness 自带的 pnpm 执行
- 本 bundle **零运行时依赖、无安装脚本**，因此不会触发 `approvedBuilds`

## 安装（推荐：插件面板 / plugin_manager）

1. 确认 bundle 目录存在：`<BUNDLE_PATH>`（含 `package.json`、`cordis.patch.yml`）。
2. 在 Harness 会话中让 Agent 执行：

   ```
   plugin_manager action=install_bundle target="<BUNDLE_PATH>"
   ```

   等价的手工路径：设置 → 插件 → 添加插件 → 输入该绝对目录。

3. 读取返回结果：`application` 与 `warnings` 才是结论。`applied` 表示已生效；
   若提示需要重启，**完全退出并重新打开** DeepSeek Harness（不是只关窗口）。
4. 新建会话 → 模式选择 → **破甲模式**。
5. 验证：
   - 模式列表出现「破甲模式」；
   - 输入框下方出现 ArmorBreak 状态卡（可展开）；
   - 对话中 `armorbreak_health` 返回环境与能力清单。

### 安装做了什么

- 在 profile 的 `package.json` 中新增依赖 `dsh-armorbreak`（本地目录 link/拷贝）；
- 把 `dsh-armorbreak` 追加到 `dsh.profile.bundles`；
- 安装后下一层 patch 插入两行：`armorbreak`（Host 状态路由 + 浏览器半）与 `preset-armorbreak`（模式声明）；
- 不修改 Harness 核心、不改既有 preset、不改用户其它插件。

> 通用 MCP 宿主（Claude/Cursor/Codex/Hermes 等）与独立 Core 接入不在本文范围。
> 见 README 的 Quick Start B/C、[通用 MCP 适配器](v2/host-generic.md) 和
> [Core Public API](v2/core/public-api.md)。

## 开发/测试 profile 安装（命令行）

`desktop` profile 由 Electron 独占管理，CLI 拒绝操作。开发时使用独立 profile：

```powershell
$dsh = "$env:LOCALAPPDATA\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd"
& $dsh --profile abmtest --from-default-profile web --dump-config   # 创建测试 profile
& $dsh plugin --profile abmtest add link:"<REPO_PATH>"                  # 安装（自动加入 bundles）
& $dsh --profile abmtest --port 3099 --no-open                        # 启动测试 Web UI
# 打开打印出的带 token URL，然后新建会话选择破甲模式
```

## 卸载

```
plugin_manager action=remove_bundle target="dsh-armorbreak"
```

或：设置 → 插件 → 移除。随后重启 Harness。卸载不会删除工作区内的 `.armorbreak/` 任务数据
（证据/报告保留，属于用户资产）；需要清理时手动删除各工作区的 `.armorbreak/` 与
`$DSH_HOME/armorbreak/policy.json`。

## 故障排查

| 现象 | 排查 |
|---|---|
| 模式列表没有「破甲模式」 | 确认 bundle 已安装且**已选择**（`dsh.profile.bundles` 含 `dsh-armorbreak`）；确认安装返回 `applied` 或已重启；`plugin_manager list_bundles` 查看。 |
| 状态卡不显示 | 打开浏览器开发者工具看 `/armorbreak/state` 是否 200；Host 行在非 Web 组合（headless/tui）会保持 pending，这是预期。 |
| `armorbreak_health` 报能力加载诊断 | 看返回中的「能力诊断」；通常是某个域 manifest 文件缺失/语法错误（安装不完整）。 |
| L1/L2 操作被拒绝 | 这是默认行为：L1 需要 Docker 守护进程 + 平台审批；L2 需要授权记录 + 平台审批。按拒绝信息中的指引操作。 |
| 报告 PDF 失败 | PDF 需要本机 LibreOffice（`soffice`）；安装它，或改用 `format=html`/`markdown`。 |
| 安装/替换代码后行为没变 | 替换已安装包的 JS 需要重启 Harness 才能加载新的模块代际；新增 bundle 可热激活。 |
| 插件行显示 `overridden` | 有更高优先级 patch 层覆盖了同一行；检查 profile 的 `cordis.patch.yml`。 |
| Windows 上路径相关报错 | 传绝对路径（`D:\...`）；工作区必须显式传 `workspace` 参数；任务数据写入 `<workspace>\.armorbreak\`。 |

## 运行环境要求

- 离线能力：无额外依赖。
- 外部工具（可选）：Ghidra / Rizin / radare2 / YARA / JADX / apktool / adb / Frida / Semgrep / CodeQL /
  Trivy / Syft / Gitleaks / TShark / Zeek / Suricata / Nmap / Volatility3 / capa / FLOSS / Docker / LibreOffice。
  未安装时工具会在 `armorbreak_capabilities` / `armorbreak_health` 中明确标注，并给出安装建议与内置替代。
- 动态分析（L1）：Docker Desktop（或兼容的隔离提供者）+ 平台审批。
- 主动测试（L2）：授权记录 + 平台审批；无 Docker 也可，但需要网络策略允许。
