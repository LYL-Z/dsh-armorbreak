# 已知问题与限制（v1.1.0 Stage B 分支）

> 本清单只记录**已确认**的限制；未验证/未实现的项目不会写成已完成。

## 高优先级（影响功能完整性）

1. **外部工具输出尚未接入分析管线（部分解决）**：Ghidra / JADX / TShark / Syft 等仍未接入；v1.1.0 Stage B 首批已接入 **Semgrep** 与 **Trivy** 的 JSON 归一化（`sast.semgrep` / `sast.trivy`），但本机未安装这两个工具，真实 CLI 执行尚未验证，且语义仍是“工具命中 = hypothesis”，不自动升级为确认漏洞。
2. **L1 动态分析（Docker）已验证本机成功路径**：`scripts/verify-l1.mjs` 在 Docker 29.8.1 + digest-pinned busybox 上验证了非 root（uid 65534）、样本只读挂载、容器内无 eth 网络、超时/清理参数路径；仍**未**在 CI/其他主机验证，且 Podman/WSL2/VM provider 未实现。
3. **L2 主动测试未做真实网络验证**：只验证了策略拒绝分支（无授权 → `NETWORK_OUT_OF_SCOPE`，无审批
   → `NETWORK_APPROVAL_REQUIRED`）与 `live.http_probe` 实现；没有对真实授权目标发包（本机无授权实验室）。
4. **没有模型驱动的端到端会话验证**：CLI headless profile 缺少桌面账号的模型凭据
   （`MISSING_CREDENTIAL`），因此无法在会话外驱动一次完整 LLM 会话。已验证的是：
   preset 在真实运行时**激活成功**、工具定义/执行通过 direct-call 集成测试、Web 状态路由与浏览器模块加载。
   桌面 UI 中「新建会话 → 选择破甲模式 → 模型实际调用工具」需要用户在一个新会话里手动确认。
5. **工作流失败语义**：某一步失败后，后续独立步骤继续执行并保留证据；最终状态为 `PARTIAL_SUCCESS`。
   但步骤之间没有显式依赖图（依赖顺序由固定列表保证），暂不支持分支/并行编排。
6. **UI 只有状态卡**：任务工作台/工具中心/证据中心的完整页面尚未实现；当前状态卡显示能力数量、隔离、
   策略与最近任务摘要，不提供任务创建/报告预览等交互（这些通过对话内工具完成）。
7. **状态卡的工作区可能不是当前会话目录**：`/armorbreak/state` 默认使用 Host 进程 cwd（可被
   `ARMORBREAK_WORKSPACE` 覆盖）；会话级工作区映射尚未接入（`useSession` 的 cwd 未在客户端暴露给该插件）。
   因此状态卡里的"任务列表"可能与当前会话工作区不一致；这是显示问题，不影响工具执行（工具都显式接收 workspace）。

## 中优先级（安全/兼容）

8. **授权记录只做本地完整性签名**：能写 `$DSH_HOME/armorbreak/policy.json` 的本机用户可伪造授权；
   真正的闸门是平台审批 + 代码路径限制 + 审计可见性（见 security-model §7）。
9. **`/armorbreak/state` 无额外鉴权**：同源、loopback、只读、脱敏，不提供执行入口；若部署 bind 到非
   loopback 地址，该路由也会随 Web UI 暴露（与 Harness 其它非 API 路由一致）。
10. **敏感路径拒绝是固定清单**：`System32/SysWOW64/...` 等写死在代码里；无法通过配置扩展（避免被绕过）。
    用户需要分析这些位置的样本时，应复制到工作区。
11. **报告 PDF 依赖外部 LibreOffice**：缺失时明确报错；无内置 PDF 引擎。
12. **`.unknown` 输入类型**：二进制分析器对损坏/截断文件返回结构化诊断而非崩溃，但格式覆盖以常见 PE32/PE32+、
    ELF32/64、Mach-O 32/64 为主；DOS/NE/VxD、.NET 元数据、Go/Rust 符号等未做专门解析。
13. **大文件**：默认只读取前 32 MiB（可配置上限内），并标注 `truncated`；尚未做分段/流式解析。
14. **编码/输出**：中文报告为主；英文 UI 字典已提供基础项，但报告模板目前是中文（用户语言默认中文）。
15. **Windows 特有**：符号链接检查依赖 `realpath`；Windows 上创建符号链接需要权限，测试用敏感路径与越界路径覆盖；
    未覆盖 Windows junction/reparse point 的完整语义。

## 低优先级（体验）

16. `armorbreak_workflow action=run` 是同步执行，长工作流可能被工具超时截断（默认 5 分钟，最多 50 步）；
    可以分多次调用 `run`（每次 `maxSteps` 较小）推进。
17. 证据/发现查询结果直接进模型上下文，超大时依赖 harness 的 tool-result pruner 截断；报告不受影响。
18. 技能正文为中文；跨语言用户可读但有语言门槛。
19. 没有 i18n 的日期/数字格式本地化。
20. 外部工具版本探测最多 25 个工具、每个 1.5s 超时；在很慢的磁盘/网络工具上可能显示 `versionError`（不影响 found 状态）。
21. **浏览器状态卡的视觉呈现未验证**：本机没有可用的浏览器控制通道，只验证了 `/armorbreak/state` 返回 200、
    页面启动图包含 `dsh-armorbreak/client.js`、槽位注册代码与官方模板一致；实际渲染效果需用户在 GUI 中确认。
22. **安装后的代码更新**：Desktop 已通过 `install_bundle` 安装为 `link:`；新增 bundle 可 HMR 热激活（本机已验证），
    但替换已安装包的 JS 文件需要重启 Harness 才会加载新模块代际。
23. **扫描自身仓库时的规则自匹配/夹具误报**：`sast.scan` 会命中 `rules.js` 中规则定义自身的字符串
    （如 `eval`/`new Function` 标题），`sast.secrets` 会命中测试夹具里的公开示例密钥（如 `AKIAIOSFODNN7EXAMPLE`、
    占位 PEM）。这些在报告中保持 `hypothesis`/`observed` 并需人工复核，不属于可利用漏洞。
    **v1.0.3 起**可用可选参数 `excludePaths`（路径子串、大小写不敏感）排除规则文件/测试夹具/文档示例，
    且不降低其他文件覆盖，例如
    `options: { excludePaths: ["tests/", "lib/analyzers/sast/rules.js", "docs/known-issues.md"] }`。
    更通用的 allowlist（按内容/值）仍在路线图中。
24. **PDF 报告不是纯只读分析**：`armorbreak_report format=pdf` 会调用本地 LibreOffice（`soffice`）做格式转换，
    属报告生成阶段的本机进程调用（离线、无网络、参数固定无 shell）；`soffice` 缺失时会明确报错并提供其他格式。
25. **磁盘空间与清理**：测试会在 OS 临时目录留下 `abm-*`/`dbg-*` 目录（已提供 `scripts/clean-temp.mjs`）；
    `.armorbreak/` 任务数据会随任务增长（每任务报告/证据），需要时手动清理旧任务。磁盘紧张时不要安装
    Docker/LibreOffice 等重量级外部工具，L0 内置能力与 md/html/json/sarif 报告不受影响。

26. **工作台仍为只读**：三页签（概览/任务/工具）可查看任务、步骤、finding 元数据与报告指针，但不提供创建/取消/重试按钮；写操作仍需通过对话工具。浏览器视觉呈现未在真实浏览器中验证（无浏览器控制）。
27. **会话级工作区绑定未实现**：状态卡、任务/工具路由使用进程 MRU 工作区，UI 已明确标注；多会话并行切换工作区时，卡片可能显示另一个会话最近使用的目录。
28. **工具中心的外部工具状态未探测**：为避免状态路由阻塞，卡片只列外部工具名并标注“未探测”；真实安装/版本以 `armorbreak_health probeVersions=true` 为准。
29. **后台队列仅进程内有效**：租约/队列在进程重启后清空；重启恢复依赖任务状态与 resume，不保证自动继续执行。后台执行 L1/L2 时若无法获得当前会话审批，会 fail-closed 失败，建议同步运行。
30. **CI 的 live-docker job 依赖 GitHub runner 的 Docker 与网络**：失败会显式报错，不会静默跳过；Windows 与 Ubuntu 单测矩阵仍不包含真实 daemon。

31. **Stage D2 工作台仍有限制**：写操作仅支持 L0 工作流/任务（浏览器无平台审批通道），新建/取消/重试/恢复仅在同一进程内队列有效；证据/报告/工具探测路由只读且 loopback-only，但浏览器真实视觉与交互尚未验证。
32. **会话级工作区绑定为“首次工具调用后生效”**：状态卡/路由通过 `?session=` 使用该会话实际记录的工作区（仅来自 ArmorBreak 工具执行，不接受任意路径）；会话尚未调用任何工具时回退到进程 MRU 工作区，UI 会显示 sessionBound=false。未知/非法 session 一律回退 MRU，不能被用于枚举目录。
33. **报告预览是文本渲染**：Markdown/HTML 报告以纯文本展示（HTML 不注入 DOM），不提供富文本/PDF 预览；HTML 预览可能包含原始标签文本。

## v1.2.0-alpha.1 (2026-10-20)

- 34. 隔离提供者 manager 目前只用于 `armorbreak_environment` 诊断，runner 的 L1 门仍由 HealthService 的 Docker-only 检测控制；Podman/WSL2 不会因此获得执行许可。
- 35. `binary.behavior` 是静态导入/结构启发式，评分不代表恶意或漏洞；加壳/动态解析会降低覆盖。
- 36. 本增量未包含 Ghidra/JADX/TShark/Syft 适配器；UI 环境页/证据筛选/报告格式已接入但尚未在重启后的真实桌面做视觉复验。
