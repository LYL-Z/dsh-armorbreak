# Workflow Engine v2 (design — not implemented in v1.0.4)

> 状态：**设计草案**。v1.0.4 仍是固定顺序工作流（9 个模板）；DAG、后台队列、重启恢复、步骤重试均未实现。

## 1. 目标

从“一次工具调用执行 7 个固定步骤”升级为可靠任务系统：显式依赖、后台执行、可暂停/恢复/取消、进程重启恢复、失败重试与幂等。

## 2. DAG 模型

```ts
interface StepDefinition {
  stepId: string;
  capabilityId: string;
  dependsOn: string[];
  timeoutMs: number;
  retryPolicy: { maxAttempts: number; backoffMs: number; retryOn: string[] };
  failurePolicy: "fail-fast" | "continue-independent" | "skip-dependent" | "retry-transient";
  riskLevel: "L0" | "L1" | "L2" | "L3";
  inputMapping?: Record<string, string>;
  outputMapping?: Record<string, string>;
}
```

- 规划期校验：能力存在、targetKind 兼容、依赖无环、风险上限可满足。
- 执行期：只有依赖全部成功（或策略允许）的步骤才可调度；`skip-dependent` 不执行下游但保留状态。

## 3. 异步任务

- `armorbreak_workflow action=start` 返回 taskId 并立即返回；后台执行器（Host 进程内受控队列）推进状态。
- `action=status` 返回当前步骤、进度、耗时、错误、证据/发现计数；`action=cancel` 发出 AbortSignal 并等待句柄终止；`action=retry` 重跑失败步骤（仅幂等）。
- UI/Agent 分别通过只读状态路由/工具轮询进度。

## 4. 取消与恢复

- 每个执行实例登记可终止句柄（子进程/容器/AbortController）；取消必须先终止后写终态。
- 取消后禁止写入新结果（当前 runner 已有部分检查，v2 再强化）。
- 启动时扫描未完成任务：`RUNNING` 但无租约/心跳 → `INTERRUPTED`，可恢复的进入 `RECOVERABLE`；不把重启前 RUNNING 当作仍在执行。
- 租约：`leaseId/owner/heartbeatAt`；只有幂等步骤允许自动重试。

## 5. 并发与资源预算

- 每能力配置并发上限（静态分析可并发；动态容器默认串行；证据写入按文件串行）。
- 资源预算按工具配置（内存/CPU/输出上限），由执行器统一扣减；超限拒绝而非静默降级。
- 性能目标必须由基准测试确定，不写死设备无关的 SLA。

## 6. 迁移

任务 JSON 增加 `schemaVersion`/`migrationVersion`；旧任务可读，首次写入前备份并迁移；失败回滚。
