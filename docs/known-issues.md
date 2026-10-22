# 已知问题与限制（v2.0.1 + Universal Core 分支）

> 历史 v1.2.0 记录保留在 git 历史与 `docs/acceptance-v1.2.0.md`；本文件描述当前分支。

## 已解决
1. TShark/Syft/JADX/Ghidra 适配器已实现并通过本机真实 Gate B。
2. L1 provider 门接入：Docker 自检+审批真实执行；Podman 状态机；WSL2 仅诊断。
3. L2 loopback 授权+审批真实探测 200。
4. 真实模型 GUI BinaryStaticAnalysis 全链路完成。
5. 环境视图/证据筛选/报告格式/工作区持久化经 CDP 验证。

## 残余限制
1. 本地授权记录可被本机写权限用户伪造；真正闸门是平台审批+路径限制+审计。
2. Podman 未真机验证；WSL2 不是安全沙箱。
3. 真实模型 E2E 已在重启后的 V2 Desktop 宿主完成：`armorbreak_health` + L0 `forensics.hash` 报告，见 `docs/v2/acceptance/desktop-e2e.json`。更广的 L1/L2 与 PDF 仍受限。
4. Ghidra/JADX 依赖 JDK/JRE；CI 不装重型工具，真实 Gate B 仅本地证据。
5. .NET/Go/Rust、APK v4、DEX 方法级引用、PCAP 分片重组、TLS 证书链未实现。
6. PDF 依赖 LibreOffice；英文报告未本地化；大文件仍有界读取。
7. Windows junction/reparse 语义未穷尽；敏感路径清单固定。
8. 工作台写操作仅 L0；L1/L2 浏览器无审批通道，fail-closed。
9. 队列进程内；重启依赖 task 状态/resume。
10. macOS/Linux 桌面未真机验证；Windows 卸载/重装未复测；Browser Control 扩展离线。
