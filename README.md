# WB Packager（基于 TurboWarp Packager）

上游项目：TurboWarp Packager（https://packager.turbowarp.org/）

Converts Scratch projects into HTML files, zip archives, or executable programs for Windows, macOS, and Linux.

## 本仓库的定位与边界

- 这是一个“修改版”仓库：在上游 packager 的基础上增加了插件系统与打包保护相关的选项整合
- 本仓库公开内容：packer/插件系统本体与可公开的示例插件（见 plugins-available）
- 本仓库不包含：任何闭源插件源码、任何构建产物（dist、打包目录等）
- 许可证：本仓库包含并遵循 MPL-2.0（见 [LICENSE](file:///g:/工程/javascript/desktop/wb-packager/LICENSE)），额外声明见 [NOTICE](file:///g:/工程/javascript/desktop/wb-packager/NOTICE)

## 插件系统（简述）

- 加载来源（Node 环境）：可从指定目录加载 `.js/.cjs` 插件文件
- 加载来源（Desktop 环境）：通过宿主提供的安全接口读取插件源码并执行（无 `require`）
- Hook：插件可实现 `hooks.beforePackage`、`hooks.transformProjectJson` 等来影响打包过程
- 安全提示：插件是可执行代码，请勿加载不可信来源的插件

## 修改文件列表（相对上游 TurboWarp Packager）

- src/packager/plugin-system.js
- src/packager/packager.js
- src/p4/PackagerOptions.svelte
- src/build/clean-dist.js
- plugins-available/obfuscate-extension-plugins.cjs

## Development

Install dependencies:

```
npm ci
```

Start in development mode:

```
npm start
```

Then visit http://localhost:8947. Manually refresh to see changes.

Packaged projects generated while in development mode should not be distributed. Instead, you should run a production build to significantly reduce file size of both the website and the packager.

```
npm run build-prod
```

Output will be located in the `dist` folder.

The general layout of `src` is:

 - packager: The code that downloads and packages projects.
 - p4: The Svelte website for the packager. "p4" is the name that the packager uses internally to refer to itself.
 - scaffolding: A minimal Scratch project player. Handles most of the boring details of running Scratch projects like handling mouse inputs.
 - common: Some files used by both scaffolding and the packager.
 - addons: Optional addons such as gamepad support or pointerlock.
 - locales: Translations. en.json contains the original English messages. The other languages are translated by volunteers and imported by an automated script. ([you can help](https://docs.turbowarp.org/translate))
 - build: Various build-time scripts such as webpack plugins and loaders.

## Tips for downstream variants

We strive to make the packager easy to modify and redistribute as a downstream variant, even for mods that aren't based on TurboWarp. Reading this section, at least the first half, should make it much easier to do so.

### Packages

If you want to change the scratch-vm/scratch-render/scratch-audio/scratch-storage/etc. used, this is simple:

 - `npm install` or `npm link` your package. The package name does not matter.
 - Update src/scaffolding/scratch-libraries.js to import the packages with the name you have. (some of our packages are prefixed with `@turbowarp/` while others are still just `scratch-vm` -- just make sure they match yours)

Then just rebuild. You can even install a vanilla scratch-vm and all core functionality will still work (but optional features such as interpolation, high quality pen, stage size, etc. may not work)

Note that npm is a very buggy piece of software and our dependency tree is very large. Occasionally you might get errors about missing dependencies, which should go away if you run `npm install`.

### Deployment

The packager is deployed as a simple static website. You can host it anywhere by just copying the `dist` folder after a build.

We use GitHub Actions and GitHub Pages to manage our deployment. If you want to do this too:

 - Create a new repository on GitHub and push your changes.
 - Go to your repository settings on GitHub and enable GitHub Pages with the source set to GitHub Actions.
 - Go to the "Actions" tab and enable GitHub Actions if it isn't already enabled.
 - Push commits to the "master" branch.
 - In a few minutes, your site will automatically be built and deployed to GitHub Pages.

### Branding

We ask that you at least take a moment to rename the website by editting `src/packager/brand.js` with your own app name, links, etc.

### Large files

Large files such as NW.js, Electron, and WKWebView executables are stored on an external server outside of this repository. While we aren't actively removing old files (the server still serves files unused since November 2020), we can't promise they will exist forever. The packager uses a secure checksum to validate these downloads. Forks are free to use our servers, but it's easy to setup your own if you'd prefer (it's just a static file server; see `src/packager/large-assets.js` for more information).

### Service worker

Set the environment variable `ENABLE_SERVICE_WORKER` to `1` to enable service worker for offline support (experimental, not 100% reliable). This is not recommended in development. Our GitHub Actions deploy script uses this by default.

## Standalone builds

The packager supports generating "standalone builds" that are single HTML files containing the entire packager. Large files such as Electron binaries will still be downloaded from a remote server as needed. You can download prebuilt standalone builds from [our GitHub releases](https://github.com/TurboWarp/packager/releases). These can be useful if our website is blocked or you don't have a reliable internet connection. Note that standalone builds do not contain an update checker, so do check on your own occasionally.

To make a production standalone build locally:

```
npm run build-standalone-prod
```

The build outputs to `dist/standalone.html`.

## Node.js module and API

See [node-api-docs/README.md](node-api-docs/README.md) for Node.js API documentation.

To build the Node.js module locally:

```
npm run build-node-prod
```

## License

<!-- Make sure to also update COPYRIGHT_NOTICE in src/packager/brand.js -->

Copyright (C) 2021-2024 Thomas Weber

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
