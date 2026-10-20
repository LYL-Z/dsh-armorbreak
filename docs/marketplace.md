# DeepSeek Harness 生态、插件市场与分发指引

ArmorBreak 是一个 **DeepSeek Harness（DSH）原生 Cordis Bundle + Agent preset**，
不是独立应用。本页说明它如何进入 DSH 生态、如何安装、以及如何把仓库提交到
DSH 的插件市场/精选列表。

## 1. 上游项目与官方文档

| 资源 | 链接 |
|---|---|
| DeepSeek Harness 源码 | <https://github.com/deepseek-ai/deepseek-harness> |
| 官方文档（含插件/预设参考） | <https://deepseek-harness.github.io/deepseek-harness/en/reference/> |
| 官方插件打包与安装指南 | <https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/publish> |
| 官方教程（Cordis 入门） | <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cordis-tutorial/index.md> |
| Agent preset 包参考 | <https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/preset/agent-preset/README.md> |
| Bundle patch 示例 | <https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/bundle/web-app/presets/cordis.patch.yml> |

> 兼容基线：DSH Desktop **0.2.1-rc.2** / Cordis 4.0.x / Node 24。
> 低于该版本的运行时缺少 `@deepseek-ai/dsh-agent-preset`，本 preset 无法加载。

## 2. 安装本 Bundle（三种受支持路径）

### 2.1 面板安装（Desktop，推荐）

1. 克隆/下载本仓库到本地任意目录（保持目录即包根：`package.json` 与
   `cordis.patch.yml` 在顶层）。
2. DeepSeek Harness → 设置 → 插件（Plugins）→ 添加插件 → 选择该目录绝对路径，
   或输入 `github:LYL-Z/dsh-armorbreak`（网络可用时）。
3. 安装返回 `application: applied` 后，新建会话 → 模式选择 → **破甲模式**。
4. 若替换已安装源码（`link:` 安装），需完全退出并重开 Harness 以加载新模块代际。

### 2.2 plugin_manager（Agent 会话内）

```text
plugin_manager action=install_bundle target="<绝对路径或 github:LYL-Z/dsh-armorbreak>"
plugin_manager action=list_bundles      # 应看到 armorbreak / preset-armorbreak 两行
```

### 2.3 CLI（非 desktop profile）

```powershell
$dsh = "$env:LOCALAPPDATA\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd"
$dsh --profile abmtest --from-default-profile web --dump-config
$dsh plugin --profile abmtest add github:LYL-Z/dsh-armorbreak   # 或 add link:"<本地目录>"
$dsh --profile abmtest --port 3099 --no-open
```

`desktop` profile 由 Electron 独占管理，CLI 直接操作会被拒绝；请使用面板/plugin_manager。

## 3. 如何让本仓库出现在 DSH 插件市场

DSH 生态目前同时存在**官方发布渠道**与**社区市场/精选列表**。本项目的立场是：
只登记、不刷量；提交前确保 `node --test` 全绿、README 与实际能力一致。

### 3.1 官方发布渠道

- 按官方指南 `Package and install a plugin` 打包/校验（bundle patch、locale、
  icon、`files` 清单）。本仓库已是可安装包格式，发布时只需发布 GitHub Release
  的源码压缩包或 npm 包（如后续上架 npm）。
- 官方市场/发现页的收录入口以 DSH 发行说明为准；不以本 README 的描述代替官方登记。

### 3.2 社区市场与精选列表（第三方，非本项目背书）

| 生态项目 | 类型 | 链接 |
|---|---|---|
| awesome-deepseek-harness-plugins | 插件商店/搜索/API | <https://github.com/imsai-sh/awesome-deepseek-harness-plugins> |
| awesome-dsh-plugin | 精选插件列表 | <https://github.com/dngr2/awesome-dsh-plugin> |
| dsh-plugin-market | 可安装的市场浏览插件 | <https://github.com/Winnie-0721/dsh-plugin-market> |
| dshbase / dshplugin.store | 社区插件索引站 | <https://www.dshbase.com> · <https://www.dshplugin.store> |

提交方式：fork 对应列表仓库，按它的 CONTRIBUTING 添加一条记录，内容建议：

```markdown
- [dsh-armorbreak](https://github.com/LYL-Z/dsh-armorbreak) — Authorized reverse-engineering
  & security-research agent preset for DeepSeek Harness: 39 offline capabilities (PE/ELF/Mach-O,
  APK, PCAP, HAR/OpenAPI, SAST/SBOM, CTF, forensics), L0–L3 policy engine with platform approval,
  evidence-chain reports (MD/HTML/JSON/SARIF/PDF). MIT. DSH ≥ 0.2.1-rc.2.
```

### 3.3 让仓库可被市场抓取

本仓库已包含社区索引通常要求的数据：

- 顶层 `package.json`：`name`, `version`, `license`, `repository`, `homepage`,
  `bugs`, `keywords`, `dsh.bundle.patch`, `dsh.client`。
- 顶层 `cordis.patch.yml`、`README.md`、`LICENSE`、`SECURITY.md`、
  `docs/`、`icon.svg`、`locale/{en,zh}.json`。
- GitHub topics：`deepseek-harness`, `dsh`, `dsh-plugin`, `cordis`, `agent-preset`,
  `reverse-engineering`, `security-research`, `dfir`, `static-analysis`, `ctf`。

## 4. 版本与发布策略

- 语义化版本：`MAJOR.MINOR.PATCH`；安全修复走 PATCH，新能力走 MINOR。
- 每个 release 附带：变更摘要、验证命令与实际结果、兼容性说明、已知问题。
- 当前公开仓库从 **v1.0.2（累计源码）** 开始；v1.0.0 / v1.0.1 为交付里程碑，
  其修复已包含在 v1.0.2 中（见 `CHANGELOG.md` 与 `docs/releases/`）。
- 不发布“只有提示词、没有真实执行工具”的空壳版本；发布前必须通过 `node --test`。

## 5. 上游贡献

如果本仓库的能力适配器或安全策略对 DSH 上游有价值，优先以 issue/PR 形式向
`deepseek-ai/deepseek-harness` 提出，而不是 fork 后长期偏离。ArmorBreak 本身
不修改 Harness 核心：它只新增自己的 bundle 层与 preset。
