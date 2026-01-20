# 可公开示例插件

本目录提供可公开分发的示例插件，用于演示 wb-packager 的插件系统能力。

## legal-notice-and-integrity.cjs

- 作用：当 Electron 产物的完整性校验失败（例如资源被替换/篡改）时，弹出法律告警并退出。
- 说明：该插件不伪造密钥、不做欺骗性“垃圾干扰”，仅注入一段告警文本，并保证被实际调用。

### 启用方式

1. 在打包器所在目录创建 `plugins/` 目录（或在 UI 中设置 `options.wb.pluginDir` 指向你的插件目录）。
2. 把 `legal-notice-and-integrity.cjs` 复制到该目录。
3. 在 UI 勾选“启用插件目录”（`options.wb.enablePluginDir = true`），然后重新导出。

### 配合完整性验签（推荐）

- 在 UI 启用 `options.wb.integrity.enabled` 与 `required`，并提供公钥/签名（可通过 `hooks.signIntegrityManifest` 或 `sign-integrity.js` 脚本接入）。
- 完整性校验失败时，将触发弹窗告警并退出。
