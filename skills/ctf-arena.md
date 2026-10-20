# CTF 与本地靶场分析（ArmorBreak）

## 适用
本地题目文件、编码/解码、文件格式恢复、古典密码原理、flag 提取、可复现解题记录。**仅限 CTF 题目与授权靶场；不得外推到真实第三方系统。**

## 标准流程
1. `armorbreak_analyze` capability=`ctf.classify`：识别文件类型/多层编码（base64/base32/hex/URL/ROT13/morse/gzip/zlib/zip/png/jpg/pdf/ELF/PE/PCAP）并给出递归解码链（有深度上限）。
2. capability=`ctf.hash_id`：按长度/字符集/前缀判断哈希类型，标不确定。
3. capability=`ctf.crypto_basics`：古典密码（Caesar/XOR/频率/IC）启发式分析，**输出为 hypothesis**。
4. capability=`ctf.flag_scan`：常见 flag 模式与高熵异常扫描。
5. 需要定向解码时再次调用 `ctf.classify` 并在 options 指定 transforms（base64→gzip→…），记录每一步结果。
6. `armorbreak_task` 记录关键步骤与结论；`armorbreak_report` 输出可复现的解题报告。

## 规则
- 解题过程必须可复现：命令、能力 id、参数、中间产物哈希。
- 区分「已解出（observed）」与「猜测（hypothesis）」，不确定的密码分析不得宣称唯一解。
- 不执行未知可执行文件；二进制题目用静态分析能力。
- 靶场授权不适用于公网目标；出现真实域名/IP 时停止主动操作。

## 输出
- 解码链表（步骤、变换、结果摘要、哈希）。
- flag（若找到）与定位；未找到时给出已排除的路径与下一步建议。
