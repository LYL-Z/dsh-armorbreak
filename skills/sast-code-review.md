# 源码与供应链安全审计（ArmorBreak）

## 适用
本地代码目录审计、危险调用与污点线索、硬编码密钥、依赖盘点/SBOM、CWE 映射、修复补丁与回归测试建议。**不自动应用补丁。**

## 标准流程
1. `armorbreak_workflow` `WebCodeSecurityReview`（目录目标）或逐项执行：
   - `sast.scan`：多语言 dangerous sink（eval/exec/system/命令执行/反序列化/SQL 拼接/XSS/路径穿越/弱加密）。
   - `sast.secrets`：云厂商 key、私钥、JWT、通用口令/令牌 + 熵检测；输出必须脱敏。
   - `sast.deps`：package.json / requirements.txt / go.mod / pom.xml 盘点（没有漏洞库时不给 CVE 结论）。
   - `sast.sbom`：CycloneDX JSON。
2. 对每条命中人工/模型复核：入口可控？参数可达？有校验？→ 决定 verification（observed/corroborated/hypothesis/unverified）。
3. `sast.patch_suggestion` 生成 unified diff 与回归测试建议（由人或后续任务应用）。

## 判定规则（降噪）
- 扫描告警 ≠ 漏洞：必须说明数据流（source → sink）或明确标注未验证。
- 测试代码、示例、注释中的 key 也照报，但 severity 可降级并注明。
- 依赖清单只做盘点与启发式（例如版本过旧、无 lockfile、typosquat 线索）；没有漏洞数据库时**禁止编造 CVE**。
- 不要读取 `.env` 真实值写进报告；证据摘录用 `[REDACTED]`。

## 输出
- 发现表：CWE、文件:行、代码片段（脱敏、≤5 行）、验证状态、修复建议。
- 覆盖说明：扫描了哪些语言/文件数/跳过的目录与原因。
