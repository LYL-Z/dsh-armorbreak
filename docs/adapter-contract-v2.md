# External Tool Adapter Contract v2 (design — not implemented in v1.0.4)

> 状态：**设计草案**。v1.0.4（Stage A）未实现任何外部工具适配器；现有 39 项能力仍为内置纯 JS 实现，外部工具仅做探测与安装指引。

## 1. 目标

把 Ghidra / JADX / Semgrep / TShark / Trivy / Syft 等工具的结构化输出接入发现与证据管线，同时保持：内置能力永远是无需外部依赖的基线；缺少工具只降低深度、不使任务整体失败；不同工具的严重度/置信度/验证状态分开。

## 2. 接口草案

```ts
interface ExternalToolAdapter {
  id: string;                       // e.g. "ghidra.headless"
  displayName: string;
  supportedPlatforms: string[];     // ["win32","linux","darwin"]
  supportedVersions: string[];      // tested CLI versions
  riskLevel: "L0" | "L1" | "L2";
  targetKinds: string[];            // ["file","directory"]

  detect(): Promise<ToolHealth>;    // installed? version? path?
  validate(input: unknown): ValidationResult;
  plan(input: unknown): ExecutionPlan; // argv (never shell), cwd, env allowlist, timeout
  execute(input: unknown, context: ExecutionContext): Promise<RawToolResult>;
  normalize(raw: RawToolResult): NormalizedResult;
  cancel(runId: string): Promise<void>;
}
```

## 3. 统一结果语义

- `NormalizedResult`：`resultId/toolId/toolVersion/targetId/targetHash/status/startedAt/finishedAt/findings[]/evidence[]/artifacts[]/diagnostics[]/truncated`。
- finding 增加：`verificationStatus`（observed/corroborated/hypothesis/unverified）、`confidence`、`location`、`sourceTool`、`sourceRule`、`evidenceRefs[]`、`remediation`。
- **严重度 ≠ 置信度 ≠ 验证状态**；外部工具命中默认 `hypothesis`，必须有独立证据才升级。

## 4. 约束

- argv 数组调用，`execFile`，禁止 shell 拼接；环境变量白名单；输出大小/耗时上限；超时与取消传导到子进程。
- 工具缺失/版本不兼容 → 回退内置能力，并在结果中输出 `capabilityGap`。
- 不得把低深度结果标记为高深度完成；不得凭版本猜测 CVE。
- 先逐个核查真实 CLI 参数与输出格式，再实现适配器（任务书要求）。

## 5. 实施顺序（建议）

1. `sast` 域：Semgrep JSON + Trivy JSON（输出稳定、易于本地验证）。
2. `network` 域：TShark `-T json`（字段归一化）。
3. `binary` 域：Ghidra headless（脚本导出 JSON；最重）。
4. `android` 域：JADX CLI（反编译 + 索引）。
5. SBOM：Syft（CycloneDX JSON）。

每步必须有正常/缺失/畸形输出/超时/取消五类测试，并在 Windows 与 Linux CI 上有明确 job。
