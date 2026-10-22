---
id: ABA-ISO-01
milestone: P0
priority: P0
owner: lead
status: TESTED
dependsOn: [ABU-001]
changedFiles:
  - lib/core/isolation.js
  - lib/core/runtime.js
  - tests/environment.test.mjs
testRefs:
  - environment.test.mjs
runEvidence:
  verify: "docker self-test PASS (network none, non-root, read-only)"
  diagnoseAfterRestart: "IsolationVerified / available=true"
acceptanceResult: PASS
rollbackPlan: "Revert four changed files; delete stateRoot/isolation-verified.json; L1 requires re-verification."
---

# ABA-ISO-01 IsolationVerified 持久化

## 真实缺陷

`armorbreak_environment verify docker` 成功后，状态只存在当前进程的 `Map`；下一次独立进程 `diagnose` 仍为 `DaemonReady`。这导致 L1 永远显示不可用，和验收截图一致。

## 修复

- 自检标记持久化到 `<stateRoot>/isolation-verified.json`，原子写入。
- 标记绑定 daemon `server` 版本；daemon 变化后自动回到 `DaemonReady`，不沿用旧自检。
- 运行时构造 `IsolationProviderManager({ stateRoot })`。
- 新增跨 manager/进程持久化与 server 变化失效测试。

## 证据

- `node --test tests/environment.test.mjs`：5/5 pass
- 真实 Docker 自检：PASS
- 跨进程 `diagnose`：`IsolationVerified` / `available=true`
- 仍然需要独立的 L1 平台审批；持久化自检不等于自动授权。
