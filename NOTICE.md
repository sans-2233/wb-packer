# NOTICE（WB Packager）

本仓库为 TurboWarp Packager 的下游修改版，用于在保留上游主要功能的基础上增加：

- 插件系统与部分“打包保护/加固”选项
- Windows Electron 导出的一些额外处理（例如图标注入）

## 上游与许可证

- 上游项目：TurboWarp Packager（https://packager.turbowarp.org/）
- 本仓库核心代码许可证：Mozilla Public License 2.0（见 [LICENSE](wb-packager/LICENSE)）

MPL-2.0 是“文件级”许可证：当你分发本仓库的修改版时，你需要向接收者提供你修改过的 MPL 覆盖文件的源代码，同时可以把独立文件（例如闭源插件）作为“Larger Work”的一部分独立分发。

## 关于闭源插件（边界说明）

本仓库**不包含**任何闭源插件源码。闭源插件建议以独立文件/独立分发形态存在，并仅通过 packer 的 hook API 交互，避免把闭源代码拼接进 MPL 覆盖文件中。

示例：可以在其他闭源代码库中实现仅供发行版本使用的插件（例如通过 `beforePackage` 与 `transformCompiledProject` 等 Hook，对打包产生的 JS 文件进行自定义处理，包括但不限于压缩、重写、混淆等），这些插件作为 “Larger Work” 的一部分分发，但不改变本仓库中 MPL 覆盖文件的开源义务。

## 第三方依赖补充

本仓库引入/使用了一些第三方依赖，其许可证以各依赖仓库/包声明为准。新增依赖示例：

- `@shockpkg/resedit`：用于 Windows 可执行文件资源编辑（例如注入 exe 图标），许可证为 MIT（以其 npm/仓库声明为准）。
- `javascript-obfuscator`：用于对 JavaScript 代码进行混淆保护。项目主页：https://github.com/javascript-obfuscator/javascript-obfuscator

### javascript-obfuscator 许可证声明

本仓库使用的 `javascript-obfuscator` 依赖包内包含 `LICENSE.BSD`，其许可证文本如下（保留原文）：

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## 关于“XOR 资源封包”功能的声明

本仓库包含一个用于“降低非技术用户直接提取资源”的 XOR 封包功能（`options.wb.packResourcesXor`）。该功能属于混淆封装，不应被描述为加密或提供机密性/强防篡改能力。

## 关于“预编译脚本导出”功能的声明

本仓库包含一个实验性打包形态（`options.wb.compileProjectRuntimeJS`），用于在打包阶段预生成运行时脚本并输出独立的 `compiled-project.js` 与 `project-meta.json`（结构信息，不含 blocks）。闭源插件仍建议仅通过 Hook 对生成的 JS 文件做处理。

## 关于“代码签名”功能的声明

本仓库增加了一个“导出后签名”的可选步骤（仅对 Electron 目标生效）。由于代码签名依赖平台原生工具链：

- Windows：需要 `signtool.exe`（Windows SDK），且必须在 Windows 上执行签名
- macOS：需要 `codesign`（Xcode Command Line Tools），且必须在 macOS 上执行签名
- Linux：没有统一的 zip 代码签名；本仓库以生成 `SHA256SUMS` 与可选 `GPG` detached signature 的方式提供发布校验能力

浏览器环境不提供执行本机签名工具的能力；如需在 GUI 中触发签名，需要宿主环境（例如 Electron/Node）提供对应的调用桥接。

## 修改文件清单（便于 MPL-2.0 文件级合规）

当前工作区相对上游/基线的修改文件（可用 `git status` 获取）：

- README.md
- node-api-docs/README.md
- package.json
- package-lock.json
- src/p4/PackagerOptions.svelte
- src/p4/task.js
- src/packager/brand.js
- src/packager/large-assets.js
- src/packager/packager.js
- src/packager/packer-old.js
- src/packager/web/adapter.js
- webpack.config.js
- test/packager/precompiled-runtime.test.js
