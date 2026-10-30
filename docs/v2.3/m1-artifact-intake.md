# M1 — 通用产物识别与安全清单

## 状态

`IMPLEMENTED_LOCAL_TESTED`，本地通过 M1 正/负/对抗样本和一次真实 Core Registry → PolicyGateway → Runner 调用。此状态不代表 CI、PR、其他操作系统或真实第三方应用样本验收。

能力由 `lib/analyzers/artifact/manifest.js` 注册：

- `artifact.identify`：文件级 S1 识别与候选输出。
- `artifact.inventory`：目录级 S1 文件/归档清单，使用 Core 注入的 `env.listFiles` 和 `env.readFile`。
- `UniversalArtifactTriage`：调用目录清单能力的离线工作流。

输出契约为 `docs/v2.3/schemas/artifact-identification.schema.json` 和 `artifact-graph.schema.json`。节点与关系保留 SHA-256、格式候选、物理/逻辑大小、层级、解析/拒绝状态和父子关系。常规归档成员的哈希只在数据解压并通过长度与 CRC 校验后生成；拒绝或未读成员的哈希为 `null`。

## 实现边界

- 内容魔数/结构候选覆盖 PE、ELF、Mach-O、ZIP、TAR、GZIP、PDF、PNG、JPEG、GIF、WebP、SQLite、DEX、JVM class 和 WebAssembly。源码/配置以 UTF-8 文本、shebang 与扩展名生成语言候选；扩展名候选明确标记 `extension_only`，没有 AST、符号或语义分析。
- ZIP 中的 Android 根 Manifest/DEX、JVM Manifest/class、AAB BundleConfig/base Manifest、IPA Payload/App/Info.plist 可提升为相应包候选。HAP 只标为 `hap-candidate`，不声称确认包语义。
- ZIP 解码只接受受限的单卷、非 ZIP64 中央目录。支持 Stored/Deflate 的普通成员；加密成员、未知压缩方法、ZIP64、多卷、损坏记录返回有原因的部分结果。
- ZIP 成员只接受已知安全通用标志；未知标志、强加密和其他加密方式拒绝展开。包类型只有在中央目录完整时才确认，结构不完整时保留为 ZIP/包候选。
- TAR 只接受校验通过的简单 header 与有界八进制大小。符号链接、硬链接、设备/特殊条目、PAX/GNU 扩展条目不会被跟随或展开；不支持的类型在清单中标记。
- TAR 必须有两个零结束块；缺失结束块、成员截断、缺少填充或结束后有非零数据会显示为部分结果。
- GZIP 仅在大小、扩展比预算内在内存中解压一层 payload，再按内容识别嵌套格式。
- 归档路径拒绝绝对路径、盘符/ADS、反斜杠、`..`、空路径分量、控制字符、Windows 保留设备名、尾随点/空格、大小写/Unicode 规范化碰撞和文件/目录冲突。ZIP 解析还核对本地头名称、方法、偏移、CRC 和逻辑长度。TAR 链接目标不会被访问。
- 不将样本解压写入宿主文件系统、不调用 Shell/子进程、不访问网络、不执行项目内容。所有成员只在内存中处理。

## 实际预算与覆盖限制

| 项目 | 当前值 | 说明 |
|---|---:|---|
| Core 单文件输入上限 | 32 MiB | 来自当前 Runtime；截断文件只报实际观测字节。 |
| 目录扫描总读取量 | 默认 16 MiB，最多 32 MiB | 小于 Core 默认单文件输入上限，避免将多文件读取无限放大。 |
| 单文件目录读取 | 默认最多 4 MiB | 等于 Core `maxFileReadBytes`。 |
| 节点/归档条目 | 默认最多 300 | 受 Runtime `maxItems=300` 限制，即使选项声明上限为 10,000 也不会突破 Core 上限。 |
| 递归深度 | 默认 5，最多 10 | 超限为 `PARTIAL`，并记录 `maxDepth`。 |
| 单成员展开 | 默认最多 4 MiB，最多 8 MiB | 压缩数据不会直接一次性展开到宿主磁盘。 |
| 总展开字节 | 默认 32 MiB，最多 64 MiB | 低于任务书建议的 512 MiB；这是为当前同步、内存内解压实现设置的保守上限，不能代表可扫描 512 MiB。 |
| 扩展比 | 默认 100:1，配置上限 1000:1 | 超限成员不展开；输出成员状态及警告。 |
| 序列化结果 | 最多 256 KiB | 超限时只保留图节点的确定性前缀，过滤悬空边，并同步更新计数；状态设为 `PARTIAL` 并标记 `maxResultBytes`。 |

Core 的目录枚举合同排除隐藏项（`.env` 除外）、符号链接及 `.git`、`node_modules`、构建/缓存等跳过目录。M1 不绕开该路径策略；这些对象不在本能力当前清单范围内。文件恰好读满上限时，Core 不提供该目录文件的独立总大小，因此哈希范围标记为 `observed_bytes_only`，完整性标为 `unknown_at_read_limit`。不得将其当成完整文件哈希。

## 验收证据

- `tests/program-intelligence-artifact.test.mjs` 调用生产检测器与索引器：40 组本地生成的正常/未知格式样本、22 组路径/链接/碰撞/压缩比/损坏/预算对抗样本，以及超大结果预算测试，共 70 个 Node 测试项（含父测试与集成测试）。这些是确定性结构夹具，不是 40 个真实第三方应用或完整可运行二进制。
- 真实集成测试经 `ArmorBreakRuntime` 注册表和 `ExecutionRunner` 的 L0 PolicyGateway 路径读取目录中的 ZIP；输出嵌套成员、证据 ID 与危险路径状态，并确认遍历成员没有被写到工作目录之外。
- 原始定向测试输出与退出码记录在 `evidence/m1/artifact-tests.log`（本地忽略的原始日志）和 `evidence/m1/test-results.json`（可提交的摘要）；提交态全量测试也保存在相同目录。
- 候选提交 `3135688b3a5cbea89798bc0c61a2a45abfa38312` 的全量 `npm test` 为 600/600、0 跳过、退出码 0；`npm run typecheck` 退出码 0。CI/PR 尚未运行，结果分别记录在 `evidence/m1/test-results.json` 与 `evidence/m1/current-registry.json`。

## 尚未实现或未验证

- S2+ AST/符号 IR、跨文件引用/数据流、native Ghidra 调用图、字节码详细解析、漏洞证据关联与行为差异测试尚未开始。
- 未实现 7z/RAR/BZIP2/XZ/Zstd 容器解码、ZIP64、分卷归档和复杂 TAR 扩展。它们可以被识别为候选或拒绝为部分结果，不会被宣称深度支持。
- 未对真实大型第三方软件包、真实恶意压缩炸弹、Mac/Linux 文件系统或并行压力做验收。现有样本用于验证结构路径和安全拒绝行为。
- 30+ 夹具通过不证明解析器无漏洞，也不代替独立安全审计、CI、GUI 或外部工具 E2E。
