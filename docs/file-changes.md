# 完整文件变更清单（v1.0.4）

- 生成方式：`node scripts/file-changes.mjs`（遍历交付目录，排除 node_modules/.armorbreak）
- 文件总数：**198**
- 总大小：**4183.1 KiB**
- 总行数：**58217**（含注释/文档）
- 运行时依赖：**0**（仅 Node 内置模块；无构建步骤）

## 能力清单（由 lib/analyzers/*/manifest.js 自动统计）

| 域 | 能力 |
|---|---|
| android | 6：`android.apk_structure`、`android.manifest`、`android.dex`、`android.signing`、`android.findings`、`android.jadx` |
| binary | 7：`binary.identify`、`binary.strings`、`binary.entropy`、`binary.headers`、`binary.structure`、`binary.behavior`、`binary.ghidra` |
| ctf | 5：`ctf.classify`、`ctf.decode`、`ctf.hash_id`、`ctf.crypto_basics`、`ctf.flag_scan` |
| forensics | 6：`forensics.hash`、`forensics.metadata`、`forensics.timeline`、`forensics.ioc`、`forensics.yara_lite`、`forensics.filetype` |
| live | 2：`live.http_probe`、`live.container_exec` |
| network | 8：`network.pcap_overview`、`network.flows`、`network.dns`、`network.tls`、`network.http`、`network.iocs`、`network.anomalies`、`network.tshark` |
| sast | 8：`sast.scan`、`sast.secrets`、`sast.deps`、`sast.sbom`、`sast.patch_suggestion`、`sast.semgrep`、`sast.trivy`、`sast.syft` |
| web | 4：`web.har`、`web.openapi`、`web.headers`、`web.http_message` |

## 文件清单

| 路径 | 字节 | 行数 | 说明 |
|---|---:|---:|---|
| `.gitattributes` | 167 | 11 |  |
| `.gitignore` | 394 | 19 |  |
| `benchmarks/bench.mjs` | 12112 | 265 | 零依赖可复现微基准脚本 |
| `benchmarks/results.json` | 4174 | 177 | 参考主机基准原始数据 |
| `CHANGELOG.md` | 19073 | 217 | 变更记录（1.0.4） |
| `client.js` | 32777 | 634 | 浏览器半：composer 状态卡（能力/隔离/策略/任务摘要） |
| `CODE_OF_CONDUCT.md` | 1478 | 35 | 社区行为准则 |
| `CONTRIBUTING.md` | 3078 | 69 | 贡献指南与能力适配器开发流程 |
| `cordis.patch.yml` | 6517 | 95 | 组合包 patch：Host 行 + preset-armorbreak 模式声明 |
| `docs/acceptance-v1.1.0.md` | 12622 | 172 |  |
| `docs/acceptance-v1.2.0.md` | 655 | 9 |  |
| `docs/acceptance.md` | 16196 | 235 | 验收报告（含实际测试与验证结果） |
| `docs/acceptance/adapter-v2-real.json` | 1556 | 45 |  |
| `docs/acceptance/gate-b-findings.json` | 97583 | 2757 |  |
| `docs/acceptance/gate-b-report.md` | 107463 | 1579 |  |
| `docs/acceptance/gate-b-summary.json` | 5038 | 180 |  |
| `docs/acceptance/gate-b-task.json` | 9160 | 296 |  |
| `docs/acceptance/gui-v12-verification.json` | 611 | 26 |  |
| `docs/acceptance/l1-docker-verification.json` | 1411 | 16 |  |
| `docs/acceptance/l1-provider.json` | 768 | 29 |  |
| `docs/acceptance/l2-loopback.json` | 319 | 12 |  |
| `docs/acceptance/model-e2e-v12.json` | 835 | 18 |  |
| `docs/acceptance/screenshots/gui-model-e2e.png` | 320347 | 1450 |  |
| `docs/acceptance/screenshots/gui-model-workflow-v12.png` | 385593 | 1315 |  |
| `docs/acceptance/screenshots/gui-status-card.png` | 394881 | 1418 |  |
| `docs/acceptance/screenshots/gui-tool-probe.png` | 257301 | 930 |  |
| `docs/acceptance/screenshots/gui-v12-workbench.png` | 421401 | 1229 |  |
| `docs/acceptance/v1.1.0-gui-verification.md` | 1666 | 12 |  |
| `docs/adapter-contract-v2.md` | 5658 | 79 |  |
| `docs/architecture.md` | 8825 | 130 | 架构设计（分层、Cordis 组合、执行管线、数据模型） |
| `docs/audit/environment-audit.md` | 11323 | 118 | Phase 0 环境与架构审计报告 |
| `docs/benchmarks.md` | 7753 | 154 | 性能基准：环境、数据、方法、复现 |
| `docs/compatibility-matrix.md` | 4965 | 71 | 运行时/API/外部工具/平台兼容性 |
| `docs/CONTRACT.md` | 7935 | 141 | 分析能力/适配器开发契约 |
| `docs/installation.md` | 4482 | 78 | 安装/启用/卸载/故障排查 |
| `docs/isolation-providers.md` | 2321 | 50 |  |
| `docs/known-issues.md` | 1276 | 21 | 已知问题与限制（诚实清单） |
| `docs/marketplace.md` | 5589 | 104 | DeepSeek Harness 生态、插件市场与分发指引 |
| `docs/media/report-deliverables.webp` | 125032 | 438 | 报告交付物真实截图 |
| `docs/media/status-card.png` | 96465 | 355 | 模式状态卡真实截图 |
| `docs/migration-v1.0.3-to-v1.1.0.md` | 3001 | 42 |  |
| `docs/releases/v1.0.0.md` | 1884 | 41 | v1.0.0 发布说明 |
| `docs/releases/v1.0.1.md` | 1463 | 36 | v1.0.1 发布说明 |
| `docs/releases/v1.0.2.md` | 3370 | 62 | v1.0.2 发布说明 |
| `docs/releases/v1.0.3.md` | 1765 | 51 |  |
| `docs/releases/v1.0.4.md` | 2561 | 33 |  |
| `docs/releases/v1.1.0.md` | 2029 | 22 |  |
| `docs/releases/v1.1.1.md` | 2478 | 50 |  |
| `docs/releases/v1.2.0-alpha.1.md` | 1815 | 36 |  |
| `docs/releases/v1.2.0.md` | 1315 | 13 |  |
| `docs/roadmap.md` | 2770 | 38 | 后续扩展路线图 |
| `docs/security-boundary-review.md` | 6464 | 53 |  |
| `docs/security-model.md` | 5950 | 78 | 四级能力控制、授权/审批、路径与命令、隔离、审计 |
| `docs/usage.md` | 4092 | 87 | 使用指南与场景 |
| `docs/workflow-engine-v2.md` | 2454 | 50 |  |
| `fixtures/gate-b-rules/armorbreak-local.yml` | 1757 | 65 |  |
| `fixtures/gate-b-sample/.env` | 192 | 4 |  |
| `fixtures/gate-b-sample/Dockerfile` | 168 | 7 |  |
| `fixtures/gate-b-sample/package-lock.json` | 34766 | 925 |  |
| `fixtures/gate-b-sample/package.json` | 447 | 18 |  |
| `fixtures/gate-b-sample/README.md` | 1997 | 34 |  |
| `fixtures/gate-b-sample/requirements.txt` | 144 | 6 |  |
| `fixtures/gate-b-sample/src/app.js` | 810 | 28 |  |
| `fixtures/gate-b-sample/src/config.js` | 352 | 9 |  |
| `fixtures/gate-b-sample/src/crypto.js` | 301 | 12 |  |
| `icon.svg` | 787 | 14 | 插件图标 |
| `index.js` | 20979 | 497 | Host 半：只读状态路由 /armorbreak/state，webServer 注入 |
| `lib/analyzers/android/axml.js` | 18654 | 498 | 分析能力实现（按域） |
| `lib/analyzers/android/dex.js` | 12033 | 324 | 分析能力实现（按域） |
| `lib/analyzers/android/jadx.js` | 7290 | 159 | 分析能力实现（按域） |
| `lib/analyzers/android/manifest.js` | 69984 | 1535 | 分析能力实现（按域） |
| `lib/analyzers/android/signature.js` | 19901 | 522 | 分析能力实现（按域） |
| `lib/analyzers/android/util.js` | 6534 | 180 | 分析能力实现（按域） |
| `lib/analyzers/android/zip.js` | 14373 | 367 | 分析能力实现（按域） |
| `lib/analyzers/binary/behavior.js` | 8734 | 170 | 分析能力实现（按域） |
| `lib/analyzers/binary/elf.js` | 24688 | 556 | 分析能力实现（按域） |
| `lib/analyzers/binary/entropy.js` | 6029 | 160 | 分析能力实现（按域） |
| `lib/analyzers/binary/ghidra.js` | 8821 | 175 | 分析能力实现（按域） |
| `lib/analyzers/binary/identify.js` | 22475 | 485 | 分析能力实现（按域） |
| `lib/analyzers/binary/macho.js` | 23829 | 553 | 分析能力实现（按域） |
| `lib/analyzers/binary/manifest.js` | 32305 | 609 | 分析能力实现（按域） |
| `lib/analyzers/binary/pe.js` | 35841 | 836 | 分析能力实现（按域） |
| `lib/analyzers/binary/strings.js` | 8719 | 168 | 分析能力实现（按域） |
| `lib/analyzers/binary/structure.js` | 13946 | 292 | 分析能力实现（按域） |
| `lib/analyzers/binary/util.js` | 15569 | 400 | 分析能力实现（按域） |
| `lib/analyzers/ctf/common.js` | 5732 | 159 | 分析能力实现（按域） |
| `lib/analyzers/ctf/crypto-basics.js` | 13640 | 326 | 分析能力实现（按域） |
| `lib/analyzers/ctf/encoding.js` | 13418 | 342 | 分析能力实现（按域） |
| `lib/analyzers/ctf/filetype.js` | 20490 | 483 | 分析能力实现（按域） |
| `lib/analyzers/ctf/flagscan.js` | 4985 | 137 | 分析能力实现（按域） |
| `lib/analyzers/ctf/hash_id.js` | 10973 | 284 | 分析能力实现（按域） |
| `lib/analyzers/ctf/manifest.js` | 22537 | 501 | 分析能力实现（按域） |
| `lib/analyzers/forensics/filetype.js` | 18532 | 295 | 分析能力实现（按域） |
| `lib/analyzers/forensics/formats.js` | 15383 | 369 | 分析能力实现（按域） |
| `lib/analyzers/forensics/hashes.js` | 2415 | 55 | 分析能力实现（按域） |
| `lib/analyzers/forensics/ioc.js` | 11443 | 243 | 分析能力实现（按域） |
| `lib/analyzers/forensics/manifest.js` | 16029 | 332 | 分析能力实现（按域） |
| `lib/analyzers/forensics/metadata.js` | 21317 | 446 | 分析能力实现（按域） |
| `lib/analyzers/forensics/timeline.js` | 12028 | 303 | 分析能力实现（按域） |
| `lib/analyzers/forensics/util.js` | 6113 | 148 | 分析能力实现（按域） |
| `lib/analyzers/forensics/yara-lite.js` | 11222 | 274 | 分析能力实现（按域） |
| `lib/analyzers/forensics/zip.js` | 12978 | 307 | 分析能力实现（按域） |
| `lib/analyzers/live/manifest.js` | 16398 | 332 | 分析能力实现（按域） |
| `lib/analyzers/network/anomalies.js` | 11829 | 269 | 分析能力实现（按域） |
| `lib/analyzers/network/capture.js` | 6682 | 157 | 分析能力实现（按域） |
| `lib/analyzers/network/dns.js` | 14844 | 381 | 分析能力实现（按域） |
| `lib/analyzers/network/flows.js` | 11619 | 303 | 分析能力实现（按域） |
| `lib/analyzers/network/http.js` | 14696 | 367 | 分析能力实现（按域） |
| `lib/analyzers/network/manifest.js` | 34113 | 734 | 分析能力实现（按域） |
| `lib/analyzers/network/packets.js` | 16313 | 484 | 分析能力实现（按域） |
| `lib/analyzers/network/pcap.js` | 4909 | 125 | 分析能力实现（按域） |
| `lib/analyzers/network/pcapng.js` | 11204 | 315 | 分析能力实现（按域） |
| `lib/analyzers/network/tls.js` | 18058 | 461 | 分析能力实现（按域） |
| `lib/analyzers/network/tshark.js` | 9160 | 168 | 分析能力实现（按域） |
| `lib/analyzers/network/util.js` | 13594 | 365 | 分析能力实现（按域） |
| `lib/analyzers/sast/common.js` | 14910 | 404 | 分析能力实现（按域） |
| `lib/analyzers/sast/deps.js` | 26481 | 626 | 分析能力实现（按域） |
| `lib/analyzers/sast/external-adapters.js` | 17501 | 341 | 分析能力实现（按域） |
| `lib/analyzers/sast/manifest.js` | 26431 | 562 | 分析能力实现（按域） |
| `lib/analyzers/sast/patch.js` | 15759 | 303 | 分析能力实现（按域） |
| `lib/analyzers/sast/rules.js` | 19545 | 591 | 分析能力实现（按域） |
| `lib/analyzers/sast/sbom.js` | 5851 | 157 | 分析能力实现（按域） |
| `lib/analyzers/sast/scanner.js` | 6265 | 174 | 分析能力实现（按域） |
| `lib/analyzers/sast/secrets.js` | 12526 | 379 | 分析能力实现（按域） |
| `lib/analyzers/sast/syft.js` | 6046 | 119 | 分析能力实现（按域） |
| `lib/analyzers/web/common.js` | 15455 | 439 | 分析能力实现（按域） |
| `lib/analyzers/web/har.js` | 23825 | 630 | 分析能力实现（按域） |
| `lib/analyzers/web/headers.js` | 27955 | 728 | 分析能力实现（按域） |
| `lib/analyzers/web/httpmsg.js` | 15429 | 397 | 分析能力实现（按域） |
| `lib/analyzers/web/manifest.js` | 8035 | 188 | 分析能力实现（按域） |
| `lib/analyzers/web/openapi.js` | 25876 | 615 | 分析能力实现（按域） |
| `lib/analyzers/web/yaml-lite.js` | 17529 | 557 | 分析能力实现（按域） |
| `lib/core/audit.js` | 3450 | 105 | 核心运行时模块 |
| `lib/core/capabilities.js` | 7148 | 179 | 核心运行时模块 |
| `lib/core/dag.js` | 5880 | 139 | 核心运行时模块 |
| `lib/core/evidence.js` | 7789 | 181 | 核心运行时模块 |
| `lib/core/externalTools.js` | 9187 | 238 | 核心运行时模块 |
| `lib/core/files.js` | 8638 | 219 | 核心运行时模块 |
| `lib/core/health.js` | 15282 | 287 | 核心运行时模块 |
| `lib/core/help.js` | 1019 | 19 | 核心运行时模块 |
| `lib/core/isolation.js` | 9867 | 211 | 核心运行时模块 |
| `lib/core/presentation.js` | 4598 | 107 | 核心运行时模块 |
| `lib/core/reports.js` | 21027 | 413 | 核心运行时模块 |
| `lib/core/runner.js` | 40628 | 872 | 核心运行时模块 |
| `lib/core/runtime.js` | 8548 | 227 | 核心运行时模块 |
| `lib/core/scope.js` | 27752 | 689 | 核心运行时模块 |
| `lib/core/taskQueue.js` | 8195 | 238 | 核心运行时模块 |
| `lib/core/tasks.js` | 12977 | 388 | 核心运行时模块 |
| `lib/core/util.js` | 12247 | 402 | 核心运行时模块 |
| `lib/core/workflows.js` | 7194 | 152 | 核心运行时模块 |
| `LICENSE` | 1062 | 22 | MIT 许可证 |
| `locale/en.json` | 228 | 7 | 插件显示元数据（英文） |
| `locale/zh.json` | 195 | 7 | 插件显示元数据（中文） |
| `package.json` | 1783 | 79 | Bundle 清单（dsh.bundle.patch + dsh.client + 零依赖声明） |
| `README.md` | 61657 | 1058 | 项目总览、安装、能力与安全模型摘要 |
| `scripts/clean-temp.mjs` | 1714 | 59 | 清理测试临时目录脚本 |
| `scripts/file-changes.mjs` | 6569 | 153 | 文件清单生成脚本 |
| `scripts/ghidra/ExportSummary.java` | 2987 | 64 | 开发/交付脚本 |
| `scripts/verify-gate-b-v2.mjs` | 4896 | 87 | 开发/交付脚本 |
| `scripts/verify-gate-b.mjs` | 13314 | 276 | 开发/交付脚本 |
| `scripts/verify-ghidra.mjs` | 1143 | 26 | 开发/交付脚本 |
| `scripts/verify-l1-provider.mjs` | 2423 | 45 | 开发/交付脚本 |
| `scripts/verify-l1.mjs` | 4389 | 95 | 开发/交付脚本 |
| `scripts/verify-l2-loopback.mjs` | 2092 | 38 | 开发/交付脚本 |
| `SECURITY.md` | 2049 | 54 | 安全政策与漏洞披露流程 |
| `skills.js` | 3861 | 84 | preset 子插件：注册 7 个内置技能 |
| `skills/android-apk-audit.md` | 1826 | 27 | 内置技能正文 |
| `skills/binary-static-analysis.md` | 2013 | 26 | 内置技能正文 |
| `skills/ctf-arena.md` | 1550 | 23 | 内置技能正文 |
| `skills/forensics-triage.md` | 1371 | 23 | 内置技能正文 |
| `skills/pcap-investigation.md` | 1721 | 25 | 内置技能正文 |
| `skills/report-writing.md` | 1936 | 32 | 内置技能正文 |
| `skills/sast-code-review.md` | 1630 | 24 | 内置技能正文 |
| `tests/acceptance.test.mjs` | 10527 | 228 | 自动化测试（node:test） |
| `tests/android.test.mjs` | 47570 | 1179 | 自动化测试（node:test） |
| `tests/binary.test.mjs` | 35423 | 800 | 自动化测试（node:test） |
| `tests/core-concurrency.test.mjs` | 3522 | 71 | 自动化测试（node:test） |
| `tests/core-policy.test.mjs` | 7974 | 152 | 自动化测试（node:test） |
| `tests/core-runtime.test.mjs` | 13332 | 298 | 自动化测试（node:test） |
| `tests/ctf.test.mjs` | 14890 | 309 | 自动化测试（node:test） |
| `tests/e2e-tool-flow.test.mjs` | 3940 | 88 | 自动化测试（node:test） |
| `tests/environment.test.mjs` | 5220 | 114 | 自动化测试（node:test） |
| `tests/external-adapters-v2.test.mjs` | 7111 | 169 | 自动化测试（node:test） |
| `tests/external-adapters.test.mjs` | 6815 | 175 | 自动化测试（node:test） |
| `tests/forensics.test.mjs` | 36002 | 835 | 自动化测试（node:test） |
| `tests/hardening.test.mjs` | 4197 | 83 | 自动化测试（node:test） |
| `tests/network.test.mjs` | 49402 | 1102 | 自动化测试（node:test） |
| `tests/runner-directory.test.mjs` | 8208 | 184 | 自动化测试（node:test） |
| `tests/runner-gates.test.mjs` | 8993 | 160 | 自动化测试（node:test） |
| `tests/sast.test.mjs` | 18872 | 416 | 自动化测试（node:test） |
| `tests/security-boundary.test.mjs` | 9395 | 182 | 自动化测试（node:test） |
| `tests/task-queue.test.mjs` | 4702 | 111 | 自动化测试（node:test） |
| `tests/tools-integration.test.mjs` | 9752 | 199 | 自动化测试（node:test） |
| `tests/tools-lossless.test.mjs` | 5747 | 131 | 自动化测试（node:test） |
| `tests/ui-api.test.mjs` | 13860 | 300 | 自动化测试（node:test） |
| `tests/web.test.mjs` | 17832 | 434 | 自动化测试（node:test） |
| `tests/workflow-dag.test.mjs` | 6076 | 128 | 自动化测试（node:test） |
| `tools.js` | 59545 | 1005 | preset 子插件：注册 8 个模型工具并桥接平台审批 |

## 说明

- 本清单覆盖交付源码、测试、文档与开发期 overlay；不含测试运行时产生的 `.armorbreak/` 数据。
- `dev/*.yml` 仅用于开发/验收期挂载测试，不随 bundle 安装生效。
- 未在此清单中的文件（如用户工作区里的 `.armorbreak/tasks/*`）是运行时产物，不是交付物。
