# External Tool Adapter Contract v2 (first batch implemented)

> 状态：**首批实现 + Gate B 真实运行通过**。v1.1.0 Stage B 首批实现了 Semgrep / Trivy 的 JSON 归一化与 L0 能力（`sast.semgrep` / `sast.trivy`）；本机已安装 Semgrep 1.181.0 / Trivy 0.76.0 并真实执行（见 §7）。Ghidra/JADX/TShark/Syft 仍未实现。

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

## 6. 首批实现状态（Stage B，已合并 main）

| 项 | 状态 | 证据 |
|---|---|---|
| `sast.semgrep` capability | ✅ 实现（L0/directory） | `lib/analyzers/sast/external-adapters.js`、`tests/external-adapters.test.mjs` |
| Semgrep JSON 归一化 | ✅ 测试通过（夹具） | results[] → severity/confidence/hypothesis/location/sourceRule/evidence |
| `sast.trivy` capability | ✅ 实现（L0/directory，默认 `--skip-db-update`） | 同上 |
| Trivy JSON 归一化 | ✅ 测试通过（夹具） | Vulnerabilities/Secrets/Misconfigurations 三类 |
| 畸形 JSON / 错误 schema | ✅ 明确拒绝 | `not a Semgrep report` / `not a Trivy report` |
| 工具缺失 | ✅ 明确安装指引（fail-closed） | `EXTERNAL_TOOL_GUIDANCE` + 测试 |
| 真实 Semgrep CLI 运行 | ✅ Gate B 通过（1.181.0） | `scripts/verify-gate-b.mjs`：本地 5 条规则 → 6 findings，全部 hypothesis |
| 真实 Trivy CLI 运行 | ✅ Gate B 通过（0.76.0） | 本地漏洞库离线扫描 → 67 findings（依赖 65 + 密钥 2） |
| 超时/取消子进程 | ⚠️ 依赖 execFile timeout；未做真实工具取消测试 | 后续补 |
| `network.tshark` | ✅ 实现 + 真实 Gate B 4.6.9 | `lib/analyzers/network/tshark.js` |
| `sast.syft` | ✅ 实现 + 真实 Gate B 1.54.1 | `lib/analyzers/sast/syft.js` |
| `android.jadx` | ✅ 实现 + 真实 Gate B 1.5.6 | `lib/analyzers/android/jadx.js` |
| `binary.ghidra` | ✅ 实现 + 真实 Gate B 12.1.4 | `lib/analyzers/binary/ghidra.js` + `scripts/ghidra/ExportSummary.java` |

执行前置条件：`semgrep` / `trivy` 在 PATH；Semgrep 需 `options.config` 本地规则；Trivy 需本地 DB（默认 `--skip-db-update`，除非显式 `downloadDb: true` 且允许联网）。

## 7. Gate B 真实运行结论（2026-10-20）

- 安装位置（C: 空间紧张，装在 D:）：Semgrep 1.181.0 → `D:\dsh-tools\semgrep-venv\Scripts\semgrep.exe`（Python venv）；Trivy 0.76.0 → `D:\dsh-tools\trivy\trivy.exe`；漏洞库 → `D:\dsh-tools\trivy-cache\db\trivy.db`（约 1.56 GB）。工具目录已加入用户 PATH，`%LOCALAPPDATA%\trivy` junction 指向 D: 缓存。
- capability 层（真实 CLI + 无测试 seam 的裸 env）：Semgrep 6 findings / 5 规则；Trivy 67 findings（high 53、critical 14），`offlineDb=true`。
- runner 层：L0 目录任务 `COMPLETED`，2/2 步 DONE，证据链 verified（150 条），报告生成。
- 真实执行修复两点：① 子进程环境白名单补 `LOCALAPPDATA`/`APPDATA`（否则 Trivy 无法定位本地 DB，`--skip-db-update` 报首启错误）；② `HealthService` 新增独立 `versionTimeoutMs`（默认 5s），避免 Semgrep 冷启动被 1.5s 超时误判。
- 证据：`docs/acceptance/gate-b-summary.json`、`gate-b-findings.json`、`gate-b-task.json`、`gate-b-report.md`；验收报告见 `docs/acceptance-v1.1.0.md` §2.2。
