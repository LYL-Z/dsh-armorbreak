# Android APK 离线安全审计（ArmorBreak）

## 适用
APK 结构、Manifest、组件暴露、权限、签名、明文流量与配置风险；**仅离线分析文件，不连接设备、不插桩。**

## 标准流程
1. `armorbreak_analyze` capability=`android.apk_structure`：ZIP 条目、classes*.dex、resources.arsc、lib ABI、assets、META-INF。
2. capability=`android.manifest`：package/versionName/versionCode、minSdk/targetSdk、permissions、组件与 intent-filter、`android:exported`、`debuggable`、`allowBackup`、`usesCleartextTraffic`、networkSecurityConfig。
3. capability=`android.dex`：DEX 头、字符串与类描述概况（有界）。
4. capability=`android.signing`：v1 META-INF 证书、v2/v3 签名块、证书 SHA-256、debug 证书线索。
5. capability=`android.findings`：把上述事实汇总为分级发现。

## 判定规则（降噪）
- exported=true 的组件**本身不等于漏洞**；需要 intent-filter/权限保护缺失等组合条件。标 observed 的是「组件导出」事实，风险推断标 hypothesis。
- `dangerous` 权限需结合业务用途；不要按数量刷告警。
- Cleartext：targetSdk>=28 且未配置 networkSecurityConfig 才更值得关注。
- `debuggable=true` 出现在 release 包中 = high，需签名/渠道佐证。
- 签名证书过期、debug 证书、v1-only 均为风险线索，不等于被篡改。

## 输出
- 组件清单表（类型、名称、exported、permission、intent-filter 摘要）。
- 每条发现带 evidence id 与 Manifest 定位（组件名/属性）。
- 说明动态验证未执行的原因（无授权设备/隔离环境）。

## 外部工具（可选）
JADX（反编译）、apktool（资源）、adb/frida（仅授权隔离设备，且 L1/L2 门控）。缺失时不得声称已完成反编译。
