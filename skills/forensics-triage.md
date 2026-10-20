# 数字取证初筛（ArmorBreak）

## 适用
可疑文件取证初筛、证据固定、时间线、IOC、规则匹配、可复现说明。

## 标准流程
1. `forensics.hash`：MD5/SHA-1/SHA-256/SHA-512 + 大小/类型；**先记哈希再分析**。
2. `forensics.filetype`：魔数与容器识别（PE/ELF/Office/PDF/压缩包/脚本）。
3. `forensics.metadata`：PE 时间戳/版本/资源、ELF build-id、图片/Office 元数据。
4. `forensics.timeline`：从结构里提取时间戳并按时间排序，标注时间来源与可信度。
5. `forensics.ioc`：IP/域名/URL/邮箱/哈希/注册表路径/文件路径，计数与去重。
6. `forensics.yara_lite`：内置启发式规则匹配，命中只能作为 hypothesis。
7. `armorbreak_evidence` 检查证据链与审计链；`armorbreak_report` 生成取证报告。

## 证据规范
- 每个证据记录包含：标题、类型、目标 SHA-256、摘录（脱敏）、来源能力、时间。
- 不修改原始文件；不把源文件复制进报告；只引用路径与哈希。
- 证据链校验失败必须在报告显著位置标出，不得当作已通过。
- 时间线冲突（例如 PE 编译时间晚于文件系统时间）要说明可能是伪造/时区/工具影响，标 hypothesis。

## 输出
- 证据清单（id、哈希、类型、来源）+ 时间线表 + IOC 表 + 待验证项。
