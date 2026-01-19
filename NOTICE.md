# NOTICE（WB Packager）

本仓库为 TurboWarp Packager 的下游修改版，用于在保留上游主要功能的基础上增加：

- 插件系统与部分“打包保护/加固”选项
- Windows Electron 导出的一些额外处理（例如图标注入）

## 上游与许可证

- 上游项目：TurboWarp Packager（https://packager.turbowarp.org/）
- 本仓库核心代码许可证：Mozilla Public License 2.0（见 [LICENSE](file:///g:/工程/javascript/desktop/wb-packager/LICENSE)）

MPL-2.0 是“文件级”许可证：当你分发本仓库的修改版时，你需要向接收者提供你修改过的 MPL 覆盖文件的源代码，同时可以把独立文件（例如闭源插件）作为“Larger Work”的一部分独立分发。

## 关于闭源插件（边界说明）

本仓库**不包含**任何闭源插件源码。闭源插件建议以独立文件/独立分发形态存在，并仅通过 packer 的 hook API 交互，避免把闭源代码拼接进 MPL 覆盖文件中。

说明：我们当前仅发布 packer 产物（Web/Standalone/Node module 等），不发布 Desktop 宿主与其源码；因此本仓库不包含任何 Desktop 相关实现或发行说明。

## 第三方依赖补充

本仓库引入/使用了一些第三方依赖，其许可证以各依赖仓库/包声明为准。新增依赖示例：

- `@shockpkg/resedit`：用于 Windows 可执行文件资源编辑（例如注入 exe 图标），许可证为 MIT（以其 npm/仓库声明为准）。

## 关于“XOR 资源封包”功能的声明

本仓库包含一个用于“降低非技术用户直接提取资源”的 XOR 封包功能（`options.wb.packResourcesXor`）。该功能属于混淆封装，不应被描述为加密或提供机密性/强防篡改能力。
