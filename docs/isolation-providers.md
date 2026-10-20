# Isolation Providers (design + current state)

> 状态：v1.0.4 只实现了 Docker 提供者的检测/拒绝路径与 L1 参数硬化；**没有** Docker 成功执行验证，也未实现 Podman/WSL2/VM 提供者。

## 1. 当前状态（v1.0.4）

| 提供者 | 检测 | 执行 | 验证状态 |
|---|---|---|---|
| Docker | CLI + `docker info` 探活（HealthService） | `live.container_exec` 参数已硬化（digest pin、allowlist、非 root、无网络、只读根、tmpfs、资源限制、超时清理） | 本机 daemon 不可用 → 仅拒绝分支 + 参数单测；**成功路径未验证** |
| Podman | 未实现 | — | — |
| WSL2 | 未实现 | — | — |
| VM | 未实现 | — | — |

## 2. 状态模型（目标）

```text
Unavailable → Installed → DaemonReady → IsolationVerified
                                  ↘ Degraded / Error
```

- `IsolationVerified` 只能由一次无害自检（启动容器、确认网络不可达、只读、非 root、退出清理）成功后设置。
- “Docker CLI 存在” ≠ “隔离可用”；WSL2 可用 ≠ 未知样本可安全执行。
- 缺省维持 L1 不可用；绝不静默降级到宿主执行。

## 3. Provider 接口草案

```ts
interface IsolationProvider {
  id: "docker" | "podman" | "wsl2" | "vm";
  detect(): Promise<ProviderHealth>;        // installed/context/daemon/version
  verify(): Promise<IsolationVerification>; // harmless self-test
  run(plan: ExecutionPlan, signal: AbortSignal): Promise<ExecutionResult>;
  cancel(runId: string): Promise<void>;
  cleanup(): Promise<CleanupReport>;
}
```

## 4. 安全要求

- 镜像白名单 + digest 固定 + 禁止自动拉取；容器内非 root；seccomp/资源限制；只读根；样本只读挂载；临时目录独立挂载。
- 检查 Docker Context/远程 daemon，拒绝非本地/不可信上下文。
- 记录容器 id、退出码、终止原因、资源限制命中；取消/超时后检查残留并清理。
- 任何无法证明隔离的情况保持 L1 不可用。

## 5. 后续工作

1. 实现自检容器并接入 `armorbreak_environment action=verify`（新增工具，见任务书 §4.2）。
2. Windows 上评估 WSL2 隔离边界（默认不当作安全沙箱）。
3. Podman provider 与 CI 上有 daemon 的 job（明确标注依赖，不静默跳过）。
