# 链接验证记录

- 日期：2026-10-23
- 基线：`8df5bf98b059139707cc048dcb97f8dea380873e`
- 方法：临时 Node 脚本解析 Markdown 相对链接，按源文件目录解析并检查文件存在；外部徽章使用 HTTP HEAD。

## 1. 本轮检查范围

- `README.md`
- `README.zh-CN.md`
- `docs/installation.md`
- `docs/usage.md`
- `docs/compatibility-matrix.md`
- `docs/v2/release/user-guide.md`

旧 README 归档 `docs/readme-archive-v2.2.md` 作为历史快照，不纳入本轮“新入口”链接检查；其内容来自原 README，外部链接可能随时间变化。

## 2. 结果

| 检查 | 数量 | 结果 |
|---|---:|---|
| 本地相对链接 | 72 | **0 broken** |
| 外部徽章链接 | 4 | **4/4 HTTP 200** |

外部链接：

- GitHub Actions CI badge
- version badge
- Node badge
- license badge

## 3. 复现命令

本地链接检查脚本为一次性 QA 工具，未提交到仓库：

```powershell
node D:\ArmorBreak-Docs\check-links.mjs `
  D:\ArmorBreak-Docs\armorbreak-docs `
  README.md README.zh-CN.md docs/installation.md docs/usage.md `
  docs/compatibility-matrix.md docs/v2/release/user-guide.md
```

外部徽章：

```powershell
node D:\ArmorBreak-Docs\check-external.mjs `
  D:\ArmorBreak-Docs\armorbreak-docs README.md README.zh-CN.md
```

## 4. 未覆盖

- 未逐条请求旧 README 归档中的全部外部链接；
- 未检查 GitHub 渲染后的锚点/图片排版；
- 未验证外部付费/登录服务（本项目零预算，不需要）。

## 5. 结论

新 README 与相关文档的本地文件引用全部可达；外部徽章可访问。PR 页面仍需人工确认 Mermaid 与 GitHub Markdown 渲染。
