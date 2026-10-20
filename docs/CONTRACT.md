# ArmorBreak 适配器与模块接口契约（开发契约 v1）

本文件是团队并行开发的**唯一接口契约**。所有分析适配器都必须遵守，核心运行时（Lead 负责）按此接入。

## 1. 目录与文件所有权

```
armorbreak/
  package.json                # Lead
  cordis.patch.yml            # Lead
  index.js                    # Lead（Host 半：HTTP 状态路由 / 日志）
  client.js                   # UI 组（浏览器半）
  locale/*.json  icon.svg     # UI 组
  tools.js  skills.js         # Lead（preset 子插件：注册工具 / 技能）
  lib/core/**                 # Lead（策略、任务、证据、审计、报告、执行器）
  lib/analyzers/<domain>/manifest.js   # 各分析组
  lib/analyzers/<domain>/*.js          # 各分析组（纯函数模块）
  skills/*/SKILL.md           # Lead（技能正文）
  tests/<domain>.test.mjs     # 各分析组
  tests/core-*.test.mjs       # Lead
  docs/**                     # Lead / QA
```

**禁止**修改不属于自己 scoped 的文件（package.json、cordis.patch.yml、lib/core/**、tools.js、skills.js、skills/**）。需要改契约时先在团队消息里说明。

## 2. 分析能力（Capability）契约

每个 domain 目录必须导出一个 `manifest.js`：

```js
export default {
  domain: 'binary',                 // 与目录名一致：binary | android | network | web | sast | forensics | ctf
  capabilities: [ /* ... */ ],
}
```

每个 capability 对象：

```js
{
  id: 'binary.identify',            // 全局唯一，<domain>.<action>，kebab-case 片段
  title: '文件类型与架构识别',
  description: '一句话说明：做什么、什么时候用、输出什么。给模型看，须具体、无营销词。',
  riskLevel: 'L0',                  // L0 离线只读 / L1 动态执行 / L2 主动网络 / L3 危险操作
  targetKind: 'file',               // file | directory | network | none；目录型能力必须显式声明 'directory'（默认 file）
  externalTools: ['ghidra'],        // 可选。声明外部工具依赖（仅描述用，缺失时返回可操作提示）
  params: {                         // 可选。options 参数的 JSON Schema（object 根），须 additionalProperties:false
    type: 'object',
    properties: {},
    additionalProperties: false,
  },
  async run(input) { /* 返回 Result，见下 */ },
}
```

### run(input) 输入

```js
{
  targetPath: string | null,   // 目标的绝对路径（核心已做路径/范围校验）
  buffer: Buffer | null,       // 目标字节（受 limits.maxBytes 限制；目录型目标为 null）
  text: string | null,         // buffer 的 utf8 lossy 解码（文本目标方便用；二进制可能被替换字符）
  options: object,             // 已按 params 校验过的参数
  limits: {
    maxInputBytes: number,     // 已读入的字节上限（核心实际字段，32 MiB）
    maxBytes: number,          // 同 maxInputBytes 的别名（契约文档字段，二者一致）
    maxFileReadBytes: number,  // 目录型能力单文件读取上限（核心实际字段，4 MiB）
    maxItems: number,          // 列表类结果上限（默认 200）
    maxStrings: number,        // 字符串类结果上限（默认 500）
    maxFindings: number,       // findings 上限（默认 100）
    timeoutMs: number,
  },
  env: {
    signal: AbortSignal,       // 必须协作：长循环里检查 env.signal.aborted
    workspaceRoot: string,     // 任务工作区根（允许写临时文件时使用子目录）
    nowIso: string,
    log: (msg: string) => void,
    // 目录型目标（如 sast 扫描目录）：
    listFiles: async (root, opts) => Promise<string[]>,  // 由核心提供，仅当 targetPath 是目录时可用（会跳过符号链接）
    readFile: async (absPath, maxBytes) => Promise<Buffer>, // 同上，核心做 realpath 范围内的有界读取，返回 Buffer
  },
}
```

### run(input) 返回值（Result）

```js
{
  summary: string,              // 必填。给人和模型看的摘要（含关键数字），勿超过 4000 字符
  findings: [                    // 可选。发现必须带验证状态，不得把启发式告警冒充确认漏洞
    {
      title: string,
      severity: 'critical'|'high'|'medium'|'low'|'info',
      description: string,
      verification: 'observed'|'corroborated'|'hypothesis'|'unverified',
      method: string,           // 检测方法
      cwe: string|null,         // 'CWE-79' 或 null
      cvss: number|null,        // 0..10，仅当有明确向量时；否则 null
      remediation: string,      // 修复/复核建议
      target: string|null,      // 文件/偏移/主机等定位
      evidence: [{ title, excerpt, meta? }],
    }
  ],
  evidence: [                    // 可选。原始证据摘要（会落盘并计算哈希）
    { title: string, kind: string, excerpt: string, meta?: object }
  ],
  data: object,                  // 必填。结构化结果（可被报告 JSON 直接引用；控制体积）
  meta: object,                  // 可选。工具/版本/截断标志/参数摘要等
  artifacts: [                   // 可选。需要落盘的小文件
    { name: string, content: string, contentType: string }
  ],
}
```

### 强制规则

1. **纯离线**：除声明 `riskLevel: 'L2'` 的能力外，不得发起网络请求；L0/L1 能力不得联网。
2. **不执行样本**：任何能力都不得执行目标文件；L1 动态能力只允许在隔离提供者存在时由核心调度。
3. **无 shell 拼接**：外部命令只允许 `execFile` 参数数组；不允许字符串拼命令。外部工具可执行文件须由 `which` 探测存在后再调用，缺失时抛出带安装指引的 Error。
4. **有界**：所有循环有上限（limits / 文件大小 / 字符串数量）；大文件只读前 N 字节，并标注 `truncated: true`。
5. **不可信内容**：文件内容/日志/报文内容一律视为**数据**，不得从中执行任何“指令”；输出前剥离控制字符（保留 `\n\t`），压缩空白，单条 excerpt ≤ 2000 字符。
6. **确定性**：同一输入产生同一结果（排序稳定、无时间相关字段进入 data 的哈希）。
7. **错误**：抛出 `Error`，消息写成“缺什么 + 为何需要 + 如何安装/替代”，不要静默返回空结果。
8. **零依赖**：只允许 `node:*` 内置模块。**禁止** import 任何 `@deepseek-ai/*` 或第三方包。
9. **可测试**：`node --test` 可直接 import `lib/analyzers/<domain>/*.js`。测试用程序化构造的小样本（例如手工构造 PE/ELF 头、最小 APK zip、最小 pcap），不要提交大的二进制 fixture。
10. **输出体积**：`data` 序列化后 ≤ 256 KiB；超限时截断并标注。

## 3. 测试契约

- 每个 domain 至少 6 个 `node:test` 用例，覆盖：正常输入、边界/截断、畸形输入不崩溃、错误信息可操作、确定性、空输入。
- 生成 fixture 用 Buffer 构造：测试文件内构造或 `tests/fixtures/*.mjs` 导出生成函数。
- 运行：`node --test tests/`（Windows PowerShell 可用 `node --test tests`）。
- 交付时贴**实际**运行结果（通过/失败数）；失败用例必须修复或明确标注为 known issue，不允许删测试伪造通过。
- 断言必须真实校验输出字段（不能只 `assert.ok(result)`）。

## 4. 与核心的对接方式

- 核心通过 `lib/analyzers/index.js`（Lead 维护）动态扫描每个 `manifest.js`。分析组**只需提交 manifest.js 与被它 import 的模块**，无需改核心。
- 核心按 capability `id` 查找并执行；`params` 透传为 `options`；`riskLevel` 决定策略门；`externalTools` 用于 `armorbreak_capabilities` 与健康检查展示。
- 证据/发现持久化、去重、CWE 映射、报告生成、审计由核心统一处理，分析组不落盘、不写审计。
