# 更新记录

## Unreleased

- Security: `wb.secureCsp` 现在启用基于 nonce 的 CSP（默认禁用），降低 XSS 注入面。
- Fix: Electron cleanHtmlTemplate 运行时兼容加密 v2 的 `enc.project.iv`，修复加密分片 (`wb-project.<n>.wb`) 无法加载导致的 `Missing project.json`。
- Fix: Electron `wb-read-file` 增加 `resources/app.asar` 搜索路径，避免资源被打进 asar 后读取失败。
- Logs: Electron 导出新增 `wb-packager.log`，并在 UI 展示“最近一次导出摘要/日志”（用于判断 icon/icns/desktop/扩展嵌入是否成功）。
- Plugins: 新增可公开示例插件 `plugins-available/legal-notice-and-integrity.cjs`，用于完整性校验失败时弹出法律告警并退出。
- Linux: 可选生成 `.desktop` 与 `install-desktop.sh`，并附带 hicolor 图标资源。
- macOS: 可选写入 `electron.icns`，并记录成功/失败原因到导出信息与日志。
