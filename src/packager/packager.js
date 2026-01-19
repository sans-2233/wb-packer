import {EventTarget, CustomEvent} from '../common/event-target';
import sha256 from './sha256';
import SHA256 from 'sha.js/sha256';
import JavaScriptObfuscator from 'javascript-obfuscator';
import escapeXML from '../common/escape-xml';
import largeAssets from './large-assets';
import request from '../common/request';
import pngToAppleICNS from './icns';
import {buildId, verifyBuildId} from './build-id';
import {encode} from './base85';
import {parsePlist, generatePlist} from './plist';
import {APP_NAME, WEBSITE, COPYRIGHT_NOTICE, ACCENT_COLOR} from './brand';
import {OutdatedPackagerError} from '../common/errors';
import {darken} from './colors';
import {Adapter} from './adapter';
import encodeBigString from './encode-big-string';
import {loadPluginsFromDir, loadPluginsFromDesktopPreload, runHookChain} from './plugin-system';
import {patchWindowsExecutableIcon} from './windows/patch-exe-icon';
import {pngToIco} from './windows/png-to-ico';

const PROGRESS_LOADED_SCRIPTS = 0.1;

// Used by environments that fetch the entire compressed project before calling loadProject()
const PROGRESS_FETCHED_COMPRESSED = 0.75;
const PROGRESS_EXTRACTED_COMPRESSED = 0.98;

// Used by environments that pass a project.json into loadProject() and fetch assets separately
const PROGRESS_FETCHED_PROJECT_JSON = 0.2;
const PROGRESS_FETCHED_ASSETS = 0.98;

const removeUnnecessaryEmptyLines = (string) => string.split('\n')
  .filter((line, index, array) => {
    if (index === 0 || index === array.length - 1) return true;
    if (line.trim().length === 0 && array[index - 1].trim().length === 0) return false;
    return true;
  })
  .join('\n');

export const getJSZip = async () => (await import(/* webpackChunkName: "jszip" */ '@turbowarp/jszip')).default;

const sha256HexOfString = (string) => {
  const hash = new SHA256();
  hash.update(String(string));
  return hash.digest('hex');
};

const sha256HexOfBytes = (bytes) => {
  const hash = new SHA256();
  hash.update(bytes);
  return hash.digest('hex');
};

const stableIntegrityManifestString = (manifest) => {
  const files = manifest && manifest.files && typeof manifest.files === 'object' ? manifest.files : {};
  const sortedFiles = {};
  for (const k of Object.keys(files).sort()) {
    sortedFiles[k] = files[k];
  }
  const normalized = {
    v: 1,
    kid: String(manifest && manifest.kid ? manifest.kid : ''),
    files: sortedFiles
  };
  return JSON.stringify(normalized);
};

const buildIntegrityManifestForPrefix = async (zip, resourcesPrefix, excludeRel) => {
  const files = {};
  const exclude = excludeRel && typeof excludeRel.has === 'function' ? excludeRel : null;
  for (const fullPath of Object.keys(zip.files || {})) {
    if (!fullPath.startsWith(resourcesPrefix)) continue;
    if (zip.files[fullPath] && zip.files[fullPath].dir) continue;
    const rel = fullPath.slice(resourcesPrefix.length);
    if (!rel || rel.endsWith('/')) continue;
    if (exclude && exclude.has(rel)) continue;
    const data = await zip.file(fullPath).async('uint8array');
    files[rel] = {
      sha256: sha256HexOfBytes(data),
      size: data.length
    };
  }
  return {v: 1, kid: '', files};
};

const stableObfuscatedName = (prefix, id) => `${prefix}${sha256HexOfString(id).substring(0, 10)}`;

const bytesToHex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

const randomOpcodeAlias = () => `op${bytesToHex(randomBytes(8))}`;

const obfuscateProjectOpcodes = (projectJSON) => {
  const used = new Set();
  const realOpcodes = new Set();
  if (!projectJSON || !Array.isArray(projectJSON.targets)) return null;
  for (const t of projectJSON.targets) {
    if (!t || !t.blocks || typeof t.blocks !== 'object') continue;
    for (const b of Object.values(t.blocks)) {
      if (!b || typeof b !== 'object') continue;
      const op = b.opcode;
      if (typeof op === 'string' && op) {
        realOpcodes.add(op);
        used.add(op);
      }
    }
  }

  const aliasesByReal = new Map();
  const map = {};
  for (const real of realOpcodes) {
    const aliasCount = 2 + (randomBytes(1)[0] % 3);
    const aliases = [];
    while (aliases.length < aliasCount) {
      const alias = randomOpcodeAlias();
      if (used.has(alias)) continue;
      used.add(alias);
      aliases.push(alias);
      map[alias] = real;
    }
    aliasesByReal.set(real, aliases);
  }

  for (const t of projectJSON.targets) {
    if (!t || !t.blocks || typeof t.blocks !== 'object') continue;
    for (const b of Object.values(t.blocks)) {
      if (!b || typeof b !== 'object') continue;
      const op = b.opcode;
      if (typeof op !== 'string' || !aliasesByReal.has(op)) continue;
      const aliases = aliasesByReal.get(op);
      b.opcode = aliases[randomBytes(1)[0] % aliases.length];
    }
  }

  projectJSON.wbOpcodeMap = {
    v: 1,
    map
  };
  return projectJSON.wbOpcodeMap;
};

const fileSeed = (name) => {
  let seed = 0;
  for (let i = 0; i < name.length; i++) {
    seed = (seed + name.charCodeAt(i)) & 0xff;
  }
  return seed;
};

const xorCrypt = (bytes, keyBytes, seed) => {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[i] ^ keyBytes[(i + seed) % keyBytes.length] ^ seed;
  }
  return out;
};

const normalizePackedResourceKey = (zipPath) => {
  if (zipPath === 'project.json' || zipPath.endsWith('/project.json')) return 'project.json';
  if (zipPath.startsWith('assets/')) return zipPath.slice('assets/'.length);
  const slash = zipPath.lastIndexOf('/');
  if (slash !== -1) return zipPath.slice(slash + 1);
  return zipPath;
};

const bytesToBase64 = (bytes) => {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
};

const randomBytes = (length) => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
};

const aesGcmEncrypt = async (plaintext, keyBytes, ivBytes) => {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    {name: 'AES-GCM'},
    false,
    ['encrypt']
  );
  return crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: ivBytes},
    key,
    plaintext
  );
};

const xorshift32 = (x) => {
  x ^= x << 13;
  x ^= x >>> 17;
  x ^= x << 5;
  return x >>> 0;
};

const shardSeed = (keyBytes, ivBytes, label) => {
  const hash = new SHA256();
  hash.update(keyBytes);
  hash.update(ivBytes);
  hash.update(String(label));
  const d = hash.digest();
  return (((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0);
};

const shuffledIndices = (count, seed) => {
  const indices = Array.from({length: count}, (_, i) => i);
  let s = seed >>> 0;
  for (let i = indices.length - 1; i > 0; i--) {
    s = xorshift32(s);
    const j = s % (i + 1);
    const tmp = indices[i];
    indices[i] = indices[j];
    indices[j] = tmp;
  }
  return indices;
};

const splitIntoShards = (bytes, count) => {
  const len = bytes.length;
  const base = Math.floor(len / count);
  const rem = len % count;
  const shards = [];
  let off = 0;
  for (let i = 0; i < count; i++) {
    const size = base + (i < rem ? 1 : 0);
    shards.push(bytes.subarray(off, off + size));
    off += size;
  }
  return shards;
};

const buildXorResourcePackMeta = (projectId, keyBytes, saltBytes, partCount = 8) => {
  const shards = splitIntoShards(keyBytes, partCount);
  const seed = shardSeed(keyBytes, saltBytes, `wb-res:${String(projectId || '')}`);
  const order = shuffledIndices(partCount, seed);
  const parts = Array(partCount);
  for (let i = 0; i < partCount; i++) {
    const physical = order[i];
    const obf = xorCrypt(shards[i], saltBytes, i & 0xff);
    parts[physical] = bytesToBase64(obf);
  }
  return {
    v: 1,
    salt: bytesToBase64(saltBytes),
    order,
    parts,
    map: {}
  };
};

const injectWbResMetaIntoHtml = (htmlBytes, meta, nonce) => {
  try {
    const text = new TextDecoder().decode(htmlBytes);
    if (text.includes('window.__WB_RSP__')) return htmlBytes;
    const nonceAttr = (typeof nonce === 'string' && nonce) ? ` nonce="${nonce}"` : '';
    const injected = text.replace('</body>', `<script${nonceAttr}>window.__WB_RSP__=${JSON.stringify(meta)};</script></body>`);
    if (injected === text) return htmlBytes;
    return new TextEncoder().encode(injected);
  } catch (e) {
    return htmlBytes;
  }
};

const splitString = (string, count) => {
  const len = string.length;
  const base = Math.floor(len / count);
  const rem = len % count;
  const parts = [];
  let off = 0;
  for (let i = 0; i < count; i++) {
    const size = base + (i < rem ? 1 : 0);
    parts.push(string.slice(off, off + size));
    off += size;
  }
  return parts;
};

const obfuscateProjectJSON = (projectJSON) => {
  const broadcastIdToName = new Map();
  const targets = Array.isArray(projectJSON.targets) ? projectJSON.targets : [];
  for (const target of targets) {
    if (!target || typeof target !== 'object') continue;
    const broadcasts = target.broadcasts;
    if (!broadcasts || typeof broadcasts !== 'object') continue;
    for (const [id, name] of Object.entries(broadcasts)) {
      if (!broadcastIdToName.has(id)) {
        broadcastIdToName.set(id, stableObfuscatedName('b_', name || id));
      }
    }
  }

  for (const target of targets) {
    if (!target || typeof target !== 'object') continue;
    const variableIdToName = new Map();
    const listIdToName = new Map();

    if (target.variables && typeof target.variables === 'object') {
      for (const [id, variable] of Object.entries(target.variables)) {
        if (!Array.isArray(variable) || variable.length < 1) continue;
        variableIdToName.set(id, stableObfuscatedName('v_', variable[0] || id));
        variable[0] = variableIdToName.get(id);
      }
    }
    if (target.lists && typeof target.lists === 'object') {
      for (const [id, list] of Object.entries(target.lists)) {
        if (!Array.isArray(list) || list.length < 1) continue;
        listIdToName.set(id, stableObfuscatedName('l_', list[0] || id));
        list[0] = listIdToName.get(id);
      }
    }
    if (target.broadcasts && typeof target.broadcasts === 'object') {
      for (const [id] of Object.entries(target.broadcasts)) {
        if (!broadcastIdToName.has(id)) continue;
        target.broadcasts[id] = broadcastIdToName.get(id);
      }
    }

    const blocks = target.blocks && typeof target.blocks === 'object' ? target.blocks : null;
    if (blocks) {
      for (const block of Object.values(blocks)) {
        if (!block || typeof block !== 'object') continue;
        const fields = block.fields && typeof block.fields === 'object' ? block.fields : null;
        if (!fields) continue;
        for (const [fieldName, fieldValue] of Object.entries(fields)) {
          if (!Array.isArray(fieldValue) || fieldValue.length < 2) continue;
          const id = fieldValue[1];
          if (fieldName === 'VARIABLE' && variableIdToName.has(id)) {
            fieldValue[0] = variableIdToName.get(id);
          } else if (fieldName === 'LIST' && listIdToName.has(id)) {
            fieldValue[0] = listIdToName.get(id);
          } else if (fieldName === 'BROADCAST_OPTION' && broadcastIdToName.has(id)) {
            fieldValue[0] = broadcastIdToName.get(id);
          }
        }
      }
    }
  }

  if (Array.isArray(projectJSON.monitors)) {
    for (const monitor of projectJSON.monitors) {
      if (!monitor || typeof monitor !== 'object') continue;
      const id = monitor.id;
      const params = monitor.params && typeof monitor.params === 'object' ? monitor.params : null;
      if (!id || !params) continue;
      const target = targets.find(t => t && (t.isStage ? true : (t.name === monitor.spriteName)));
      if (!target) continue;
      if (monitor.opcode === 'data_variable' && target.variables && target.variables[id]) {
        params.VARIABLE = target.variables[id][0];
      } else if (monitor.opcode === 'data_listcontents' && target.lists && target.lists[id]) {
        params.LIST = target.lists[id][0];
      }
    }
  }

  return projectJSON;
};

const setFileFast = (zip, path, data) => {
  zip.files[path] = data;
};

const SELF_LICENSE = {
  title: APP_NAME,
  homepage: WEBSITE,
  license: COPYRIGHT_NOTICE
};

const SCRATCH_LICENSE = {
  title: 'Scratch',
  homepage: 'https://scratch.mit.edu/',
  license: `Copyright (c) 2016, Massachusetts Institute of Technology
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`
};

const ELECTRON_LICENSE = {
  title: 'Electron',
  homepage: 'https://www.electronjs.org/',
  license: `Copyright (c) Electron contributors
Copyright (c) 2013-2020 GitHub Inc.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`
};

const COPYRIGHT_HEADER = `/*!
Parts of this script are from the ${APP_NAME} <${WEBSITE}>, licensed as follows:
${SELF_LICENSE.license}

Parts of this script are from Scratch <https://scratch.mit.edu/>, licensed as follows:
${SCRATCH_LICENSE.license}
*/\n`;

const generateChromiumLicenseHTML = (licenses) => {
  const style = `<style>body { font-family: sans-serif; }</style>`;
  const pretext = `<h2>The following entries were added by the ${APP_NAME}</h2>`;
  const convertedLicenses = licenses.map((({title, license, homepage}, index) => `
<div class="product">
<span class="title">${escapeXML(title)}</span>
<span class="homepage"><a href="${escapeXML(homepage)}">homepage</a></span>
<input type="checkbox" hidden id="p4-${index}">
<label class="show" for="p4-${index}" tabindex="0"></label>
<div class="licence">
<pre>${escapeXML(license)}</pre>
</div>
</div>
`));
  return `${style}${pretext}${convertedLicenses.join('\n')}`;
};

// Unique identifier for the app. If this changes, things like local cloud variables will be lost.
// This should be in reverse-DNS format.
// https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleidentifier
const CFBundleIdentifier = 'CFBundleIdentifier';
// Even if you fork the packager, you shouldn't change this string unless you want packaged macOS apps
// to lose all their data.
const bundleIdentifierPrefix = 'org.turbowarp.packager.userland.';

// CFBundleName is displayed in the menu bar.
// I'm not actually sure where CFBundleDisplayName is displayed.
// Documentation says that CFBundleName is only supposed to be 15 characters and that CFBundleDisplayName
// should be used for longer names, but in reality CFBundleName seems to not have a length limit.
// https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundlename
// https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundledisplayname
const CFBundleName = 'CFBundleName';
const CFBundleDisplayName = 'CFBundleDisplayName';

// The name of the executable in the .app/Contents/MacOS folder
// https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleexecutable
const CFBundleExecutable = 'CFBundleExecutable';

// macOS's "About" screen will display: "Version {CFBundleShortVersionString} ({CFBundleVersion})"
// Apple's own apps are inconsistent about what they display here. Some apps set both of these to the same thing
// so you see eg. "Version 15.0 (15.0)" while others set CFBundleShortVersionString to a semver-like and
// treat CFBundleVersion as a simple build number eg. "Version 1.4.0 (876)"
// Apple's documentation says both of these are supposed to be major.minor.patch, but in reality it doesn't
// even have to contain numbers and everything seems to work fine.
// https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleversion
// https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleshortversionstring
const CFBundleVersion = 'CFBundleVersion';
const CFBundleShortVersionString = 'CFBundleShortVersionString';

// Describes the category of the app
// https://developer.apple.com/documentation/bundleresources/information_property_list/lsapplicationcategorytype
const LSApplicationCategoryType = 'LSApplicationCategoryType';

const generateMacReadme = (options) => `Due to macOS restrictions, running this app requires a few manual steps.

To run the app on macOS 15 and later:
1) Double click on the app file (${options.app.packageName} in the same folder as this document), then press "Done" when the warning appears
2) Open macOS System Settings
3) Go to the "Privacy & Security" section
4) Scroll to the bottom
5) By "${options.app.packageName} was blocked to protect your Mac", press "Open Anyway"
6) In the prompt that appears, press "Open Anyway"

To run the app on macOS 14 and earlier:
1) Control+click on the app file (${options.app.packageName} in the same folder as this document) and select "Open".
2) If a warning appears, select "Open" if it's an option.
3) If a warning appears but "Open" isn't an option, press "Cancel" and repeat from step 1.
   The open button will appear the second time the warning appears.

After completing these steps, the app should run without any further warnings.

Feel free to drag the app into your Applications folder.
`;

/**
 * @param {string} packageName
 */
const validatePackageName = (packageName) => {
  // Characters considered unsafe filenames on Windows
  const BLOCKLIST = ['/', '\\', ':', '*', '?', '<', '>', '|'];
  if (BLOCKLIST.some((i) => packageName.includes(i))) {
    throw new Error(`Invalid package name: ${packageName}. It must not use the characters: ${BLOCKLIST.join(' ')}`)
  }
};

class Packager extends EventTarget {
  constructor () {
    super();
    this.project = null;
    this.options = Packager.DEFAULT_OPTIONS();
    this.aborted = false;
    this.used = false;
    this.plugins = [];
  }

  async loadPlugins () {
    const enable = !!(this.options && this.options.wb && this.options.wb.enablePluginDir);
    if (!enable) {
      this.plugins = [];
      return;
    }
    const inNode = (() => {
      try {
        return typeof process === 'object' && process && process.versions && !!process.versions.node;
      } catch (e) {
        return false;
      }
    })();
    if (inNode) {
      const dirName = (this.options && this.options.wb && this.options.wb.pluginDir) ? this.options.wb.pluginDir : 'plugins';
      let dirPath = dirName;
      try {
        if (typeof process === 'object' && process && typeof process.cwd === 'function') {
          let nodeRequire = null;
          try {
            nodeRequire = __non_webpack_require__;
          } catch (e) {}
          if (typeof nodeRequire === 'function') {
            const path = nodeRequire('path');
            dirPath = path.resolve(process.cwd(), dirName);
          }
        }
      } catch (e) {}
      this.plugins = await loadPluginsFromDir(dirPath);
      return;
    }
    this.plugins = await loadPluginsFromDesktopPreload();
  }

  async runPluginHook (hookName, value, extraContext) {
    if (!this.plugins || this.plugins.length === 0) return value;
    const context = Object.assign({
      target: this.options && this.options.target,
      options: this.options,
      libs: {
        JavaScriptObfuscator
      }
    }, extraContext || null);
    return runHookChain(this.plugins, hookName, value, context);
  }

  abort () {
    if (!this.aborted) {
      this.aborted = true;
      this.dispatchEvent(new Event('abort'));
    }
  }

  ensureNotAborted () {
    if (this.aborted) {
      throw new Error('Aborted');
    }
  }

  async fetchLargeAsset (name, type) {
    this.ensureNotAborted();
    const asset = largeAssets[name];
    if (!asset) {
      throw new Error(`Invalid asset: ${name}`);
    }
    if (typeof __ASSETS__ !== 'undefined' && __ASSETS__[asset.src]) {
      return __ASSETS__[asset.src];
    }
    const dispatchProgress = (progress) => this.dispatchEvent(new CustomEvent('large-asset-fetch', {
      detail: {
        asset: name,
        progress
      }
    }));
    dispatchProgress(0);
    let result;
    let cameFromCache = false;
    try {
      const cached = await Adapter.getCachedAsset(asset);
      if (cached) {
        result = cached;
        cameFromCache = true;
        dispatchProgress(0.5);
      }
    } catch (e) {
      console.warn(e);
    }
    if (!result) {
      let url = asset.src;
      if (asset.useBuildId) {
        url += `?${buildId}`;
      }
      result = await request({
        url,
        type,
        estimatedSize: asset.estimatedSize,
        progressCallback: (progress) => {
          dispatchProgress(progress);
        },
        abortTarget: this
      });
    }
    if (asset.useBuildId && !verifyBuildId(buildId, result)) {
      throw new OutdatedPackagerError('Build ID does not match.');
    }
    if (asset.sha256) {
      const hash = await sha256(result);
      if (hash !== asset.sha256) {
        throw new Error(`Hash mismatch for ${name}, found ${hash} but expected ${asset.sha256}`);
      }
    }
    if (!cameFromCache) {
      try {
        await Adapter.cacheAsset(asset, result);
      } catch (e) {
        console.warn(e);
      }
    }
    dispatchProgress(1);
    return result;
  }

  getAddonOptions () {
    return {
      ...this.options.chunks,
      specialCloudBehaviors: this.options.cloudVariables.specialCloudBehaviors,
      unsafeCloudBehaviors: this.options.cloudVariables.unsafeCloudBehaviors,
      pause: this.options.controls.pause.enabled
    };
  }

  async loadResources () {
    const texts = [COPYRIGHT_HEADER];
    if (this.project.analysis.usesMusic) {
      texts.push(await this.fetchLargeAsset('scaffolding', 'text'));
    } else {
      texts.push(await this.fetchLargeAsset('scaffolding-min', 'text'));
    }
    if (Object.values(this.getAddonOptions()).some((i) => i)) {
      texts.push(await this.fetchLargeAsset('addons', 'text'));
    }
    this.script = texts.join('\n').replace(/<\/script>/g,"</scri'+'pt>");
  }

  computeWindowSize () {
    let width = this.options.stageWidth;
    let height = this.options.stageHeight;
    if (
      this.options.controls.greenFlag.enabled ||
      this.options.controls.stopAll.enabled ||
      this.options.controls.pause.enabled
    ) {
      height += 48;
    }
    return {width, height};
  }

  getPlistPropertiesForPrimaryExecutable () {
    return {
      [CFBundleIdentifier]: `${bundleIdentifierPrefix}${this.options.app.packageName}`,

      // For simplicity, we'll set these to the same thing
      [CFBundleName]: this.options.app.windowTitle,
      [CFBundleDisplayName]: this.options.app.windowTitle,

      // We do rename the executable
      [CFBundleExecutable]: this.options.app.packageName,

      // For simplicity, we'll set these to the same thing
      [CFBundleVersion]: this.options.app.version,
      [CFBundleShortVersionString]: this.options.app.version,

      // Most items generated by the packager are games
      [LSApplicationCategoryType]: 'public.app-category.games'
    };
  }

  async updatePlist (zip, name, newProperties) {
    const contents = await zip.file(name).async('string');
    const plist = parsePlist(contents);
    Object.assign(plist, newProperties);
    zip.file(name, generatePlist(plist));
  }

  async addNwJS (projectZip) {
    const packageName = this.options.app.packageName;
    validatePackageName(packageName);

    const nwjsBuffer = await this.fetchLargeAsset(this.options.target, 'arraybuffer');
    const nwjsZip = await (await getJSZip()).loadAsync(nwjsBuffer);

    const isWindows = this.options.target.startsWith('nwjs-win');
    const isMac = this.options.target === 'nwjs-mac';
    const isLinux = this.options.target.startsWith('nwjs-linux');

    // NW.js Windows folder structure:
    // * (root)
    // +-- nwjs-v0.49.0-win-x64
    //   +-- nw.exe (executable)
    //   +-- credits.html
    //   +-- (project data)
    //   +-- ...

    // NW.js macOS folder structure:
    // * (root)
    // +-- nwjs-v0.49.0-osx-64
    //   +-- credits.html
    //   +-- nwjs.app
    //     +-- Contents
    //       +-- Resources
    //         +-- app.icns (icon)
    //         +-- app.nw
    //           +-- (project data)
    //       +-- MacOS
    //         +-- nwjs (executable)
    //       +-- ...

    // the first folder, something like "nwjs-v0.49.0-win-64"
    const nwjsPrefix = Object.keys(nwjsZip.files)[0].split('/')[0];

    const zip = new (await getJSZip());

    // Copy NW.js files to the right place
    for (const path of Object.keys(nwjsZip.files)) {
      const file = nwjsZip.files[path];

      let newPath = path.replace(nwjsPrefix, packageName);
      if (isWindows) {
        newPath = newPath.replace('nw.exe', `${packageName}.exe`);
      } else if (isMac) {
        newPath = newPath.replace('nwjs.app', `${packageName}.app`);
      } else if (isLinux) {
        newPath = newPath.replace(/nw$/, packageName);
      }

      setFileFast(zip, newPath, file);
    }

    const ICON_NAME = 'icon.png';
    const icon = await Adapter.getAppIcon(this.options.app.icon);
    const manifest = {
      name: packageName,
      main: 'main.js',
      version: this.options.app.version,
      window: {
        width: this.computeWindowSize().width,
        height: this.computeWindowSize().height,
        icon: ICON_NAME
      }
    };

    let dataPrefix;
    if (isWindows) {
      dataPrefix = `${packageName}/`;
    } else if (isMac) {
      zip.file(`${packageName}/How to run ${packageName}.txt`, generateMacReadme(this.options));

      const icnsData = await pngToAppleICNS(icon);
      zip.file(`${packageName}/${packageName}.app/Contents/Resources/app.icns`, icnsData);
      dataPrefix = `${packageName}/${packageName}.app/Contents/Resources/app.nw/`;
    } else if (isLinux) {
      const startScript = `#!/bin/bash
cd "$(dirname "$0")"
./${packageName}`;
      zip.file(`${packageName}/start.sh`, startScript, {
        unixPermissions: 0o100755
      });
      dataPrefix = `${packageName}/`;
    }

    // Copy project files and extra NW.js files to the right place
    for (const path of Object.keys(projectZip.files)) {
      setFileFast(zip, dataPrefix + path, projectZip.files[path]);
    }
    zip.file(dataPrefix + ICON_NAME, icon);
    zip.file(dataPrefix + 'package.json', JSON.stringify(manifest, null, 4));
    zip.file(dataPrefix + 'main.js', `
    const start = () => nw.Window.open('index.html', {
      position: 'center',
      new_instance: true
    });
    nw.App.on('open', start);
    start();`);

    const creditsHtmlPath = `${packageName}/credits.html`;
    const creditsHtml = await zip.file(creditsHtmlPath).async('string');
    zip.file(creditsHtmlPath, creditsHtml + generateChromiumLicenseHTML([
      SELF_LICENSE,
      SCRATCH_LICENSE
    ]));

    return zip;
  }

  async addElectron (projectZip) {
    const packageName = this.options.app.packageName;
    validatePackageName(packageName);

    const buffer = await this.fetchLargeAsset(this.options.target, 'arraybuffer');
    const electronZip = await (await getJSZip()).loadAsync(buffer);

    const isWindows = this.options.target.includes('win');
    const isMac = this.options.target.includes('mac');
    const isLinux = this.options.target.includes('linux');

    // See https://www.electronjs.org/docs/latest/tutorial/application-distribution#manual-distribution

    // Electron Windows/Linux folder structure:
    // * (root)
    // +-- electron.exe (executable)
    // +-- resources
    //    +-- default_app.asar (we will delete this)
    //    +-- app (we will create this)
    //      +-- index.html and the other project files (we will create this)
    // +-- LICENSES.chromium.html and everything else

    // Electron macOS folder structure:
    // * (root)
    // +-- Electron.app
    //    +-- Contents
    //      +-- Info.plist (we must update)
    //      +-- MacOS
    //        +-- Electron (executable)
    //      +-- Frameworks
    //        +-- Electron Helper.app
    //          +-- Contents
    //            +-- Info.plist (we must update)
    //        +-- Electron Helper (GPU).app
    //          +-- Contents
    //            +-- Info.plist (we must update)
    //        +-- Electron Helper (Renderer).app
    //          +-- Contents
    //            +-- Info.plist (we must update)
    //        +-- Electron Helper (Plugin).app
    //          +-- Contents
    //            +-- Info.plist (we must update)
    //        +-- and several other helpers which we won't touch
    //      +-- Resources
    //        +-- default_app.asar (we will delete this)
    //        +-- electron.icns (we will update this)
    //        +-- app (we will create this)
    //          +-- index.html and the other project files (we will create this)
    // +-- LICENSES.chromium.html and other license files

    const zip = new (await getJSZip());
    for (const path of Object.keys(electronZip.files)) {
      const file = electronZip.files[path];

      // On Windows and Linux, make an inner folder inside the zip. Zip extraction tools will sometimes make
      // a mess if you don't make an inner folder.
      // On macOS, the .app is already itself a folder already and macOS will always make a folder for the
      // extracted files if there's multiple files at the root.
      let newPath;
      if (isMac) {
        newPath = path;
      } else {
        newPath = `${packageName}/${path}`;
      }

      if (isWindows) {
        newPath = newPath.replace('electron.exe', `${packageName}.exe`);
      } else if (isMac) {
        newPath = newPath.replace('Electron.app', `${packageName}.app`);
        newPath = newPath.replace(/Electron$/, packageName);
      } else if (isLinux) {
        newPath = newPath.replace(/electron$/, packageName);
      }

      setFileFast(zip, newPath, file);
    }

    const rootPrefix = isMac ? '' : `${packageName}/`;

    const creditsHtml = await zip.file(`${rootPrefix}LICENSES.chromium.html`).async('string');
    zip.file(`${rootPrefix}licenses.html`, creditsHtml + generateChromiumLicenseHTML([
      SELF_LICENSE,
      SCRATCH_LICENSE,
      ELECTRON_LICENSE
    ]));

    zip.remove(`${rootPrefix}LICENSE.txt`);
    zip.remove(`${rootPrefix}LICENSES.chromium.html`);
    zip.remove(`${rootPrefix}LICENSE`);
    zip.remove(`${rootPrefix}version`);
    zip.remove(`${rootPrefix}resources/default_app.asar`);

    const contentsPrefix = isMac ? `${rootPrefix}${packageName}.app/Contents/` : rootPrefix;
    const resourcesPrefix = isMac ? `${contentsPrefix}Resources/app/` : `${contentsPrefix}resources/app/`;
    const electronMainName = 'electron-main.js';
    const electronPreloadName = 'electron-preload.js';
    const electronOverlayPreloadName = 'electron-overlay-preload.js';
    const iconName = 'icon.png';

    const icon = await Adapter.getAppIcon(this.options.app.icon);
    zip.file(`${resourcesPrefix}${iconName}`, icon);
    const packagerInfo = {
      buildId: buildId || null,
      target: this.options.target,
      packageName,
      version: this.options.app && this.options.app.version,
      logLines: [],
      wb: {
        protectElectron: !!(this.options.wb && this.options.wb.protectElectron),
        encryptProject: !!(this.options.wb && this.options.wb.encryptProject),
        encryptRuntime: !!(this.options.wb && this.options.wb.encryptRuntime),
        opcodeObfuscation: !!(this.options.wb && this.options.wb.opcodeObfuscation),
        shredWbResources: !!(this.options.wb && this.options.wb.shredWbResources),
        splitElectronEntry: !!(this.options.wb && this.options.wb.splitElectronEntry),
        secureCsp: !!(this.options.wb && this.options.wb.secureCsp),
        extensionLoadStrategy: (this.options.wb && this.options.wb.extensionLoadStrategy) || 'auto',
        debugLog: !!(this.options.wb && this.options.wb.debugLog),
        debugLogVerbose: !!(this.options.wb && this.options.wb.debugLogVerbose)
      },
      embeddedExtensions: {
        files: this._embeddedExtensionFiles ? Object.keys(this._embeddedExtensionFiles).length : 0
      },
      windows: {
        writeWindowsExeIcon: !!(this.options.app && this.options.app.writeWindowsExeIcon !== false),
        exportWindowsIco: !!(this.options.app && this.options.app.exportWindowsIco),
        exeIconPatched: null,
        exeIconError: null,
        exportedIco: null,
        exportedIcoError: null
      },
      macos: {
        writeMacElectronIcns: !!(this.options.app && this.options.app.writeMacElectronIcns !== false),
        icnsWritten: null,
        icnsError: null
      },
      linux: {
        exportDesktopFile: !!(this.options.app && this.options.app.exportLinuxDesktopFile),
        desktopWritten: null,
        desktopError: null
      }
    };
    const wbPackagerLog = (message, data) => {
      const m = String(message || '');
      const payload = (typeof data === 'undefined') ? '' : (() => {
        try { return JSON.stringify(data); } catch (e) { return String(data); }
      })();
      const line = payload ? `${m} ${payload}` : m;
      try { packagerInfo.logLines.push(line); } catch (e) {}
      try { console.log('[packager]', line); } catch (e) {}
    };
    wbPackagerLog('build', {buildId: packagerInfo.buildId, target: packagerInfo.target, packageName: packagerInfo.packageName, version: packagerInfo.version});
    wbPackagerLog('wb options', packagerInfo.wb);
    wbPackagerLog('embedded extensions', packagerInfo.embeddedExtensions);
    if (isWindows && this.options.app.exportWindowsIco) {
      try {
        const ico = await pngToIco(icon);
        zip.file(`${resourcesPrefix}icon.ico`, ico);
        packagerInfo.windows.exportedIco = true;
        wbPackagerLog('windows icon.ico exported');
      } catch (e) {
        console.warn(e);
        packagerInfo.windows.exportedIco = false;
        packagerInfo.windows.exportedIcoError = String(e && (e.stack || e));
        wbPackagerLog('windows icon.ico export failed', {error: packagerInfo.windows.exportedIcoError});
      }
    }
    if (isWindows && this.options.app.writeWindowsExeIcon !== false) {
      try {
        const exePath = `${rootPrefix}${packageName}.exe`;
        const exe = await zip.file(exePath).async('arraybuffer');
        const patchedExe = await patchWindowsExecutableIcon(exe, icon);
        zip.file(exePath, patchedExe);
        packagerInfo.windows.exeIconPatched = true;
        wbPackagerLog('windows exe icon patched', {exePath});
      } catch (e) {
        console.warn(e);
        packagerInfo.windows.exeIconPatched = false;
        packagerInfo.windows.exeIconError = String(e && (e.stack || e));
        wbPackagerLog('windows exe icon patch failed', {error: packagerInfo.windows.exeIconError});
      }
    }
    const writePackagerInfo = () => {
      try {
        zip.file(`${resourcesPrefix}wb-packager-info.json`, JSON.stringify(packagerInfo, null, 2));
        try {
          const text = packagerInfo.logLines.join('\n') + '\n';
          zip.file(`${resourcesPrefix}wb-packager.log`, text);
        } catch (e) {}
        try {
          this.dispatchEvent(new CustomEvent('wb-packager-info', {detail: packagerInfo}));
        } catch (e) {}
        wbPackagerLog('wb-packager-info.json written');
      } catch (e) {
        console.warn('[packager]', 'failed to write wb-packager-info.json');
      }
    };

    const manifest = {
      name: packageName,
      main: electronMainName,
      version: this.options.app.version
    };
    zip.file(`${resourcesPrefix}package.json`, JSON.stringify(manifest, null, 4));

    const wbProtectElectron = !!(this.options.wb && this.options.wb.protectElectron);
    const wbSplitElectronEntry = !!(this.options.wb && this.options.wb.splitElectronEntry);
    const wbDisableDevtools = wbProtectElectron || !(this.options.wb && this.options.wb.disableDevtools === false);
    const wbVerifyScriptHash = !(this.options.wb && this.options.wb.verifyScriptHash === false);
    const wbVerifyIndexHash = !(this.options.wb && this.options.wb.verifyIndexHash === false);
    const wbIntegrity = (this.options.wb && this.options.wb.integrity && typeof this.options.wb.integrity === 'object')
      ? this.options.wb.integrity
      : null;
    const wbIntegrityEnabled = !!(wbIntegrity && wbIntegrity.enabled);
    const wbIntegrityRequired = !!(wbIntegrity && wbIntegrity.required);
    const wbIntegrityManifestName = (wbIntegrity && typeof wbIntegrity.manifestName === 'string' && wbIntegrity.manifestName) ? wbIntegrity.manifestName : 'wb-integrity.json';
    const wbIntegritySignatureName = (wbIntegrity && typeof wbIntegrity.signatureName === 'string' && wbIntegrity.signatureName) ? wbIntegrity.signatureName : 'wb-integrity.sig';
    let wbIntegrityPublicKeys = (wbIntegrity && wbIntegrity.publicKeys && typeof wbIntegrity.publicKeys === 'object') ? wbIntegrity.publicKeys : {};
    let wbIntegrityKid = (wbIntegrity && typeof wbIntegrity.kid === 'string') ? wbIntegrity.kid : '';

    const indexHTML = projectZip.file('index.html') ? await projectZip.file('index.html').async('string') : '';
    const expectedIndexHash = wbVerifyIndexHash ? sha256HexOfString(indexHTML) : null;

    if (wbIntegrityEnabled) {
      try {
        const exclude = new Set([wbIntegrityManifestName, wbIntegritySignatureName]);
        const integrityManifest = await buildIntegrityManifestForPrefix(zip, resourcesPrefix, exclude);
        if (wbIntegrityKid) integrityManifest.kid = wbIntegrityKid;
        const integrityManifestText = stableIntegrityManifestString(integrityManifest);
        const signResult = await this.runPluginHook('signIntegrityManifest', {
          manifestText: integrityManifestText,
          manifest: integrityManifest,
          publicKeys: wbIntegrityPublicKeys
        }, {phase: 'signIntegrityManifest'});
        const resultObj = signResult && typeof signResult === 'object' ? signResult : null;
        if (resultObj) {
          if (typeof resultObj.kid === 'string' && resultObj.kid) {
            wbIntegrityKid = resultObj.kid;
            integrityManifest.kid = wbIntegrityKid;
          }
          if (resultObj.publicKeys && typeof resultObj.publicKeys === 'object') {
            wbIntegrityPublicKeys = resultObj.publicKeys;
          }
        }
        const finalManifestText = stableIntegrityManifestString(integrityManifest);
        zip.file(resourcesPrefix + wbIntegrityManifestName, finalManifestText);
        if (resultObj && resultObj.signature) {
          zip.file(resourcesPrefix + wbIntegritySignatureName, resultObj.signature);
        }
      } catch (e) {
        console.warn(e);
      }
    }

    let mainJS = `'use strict';
const {app, BrowserWindow, Menu, shell, screen, dialog, ipcMain} = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const isWindows = process.platform === 'win32';
const isMac = process.platform === 'darwin';
const isLinux = process.platform === 'linux';

const overlayWindows = new Map();

if (isMac) {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { role: 'appMenu' },
    { role: 'fileMenu' },
    { role: 'editMenu' },
    { role: 'windowMenu' },
    { role: 'help' }
  ]));
} else {
  Menu.setApplicationMenu(null);
}

const resourcesURL = Object.assign(new URL('file://'), {
  pathname: path.join(__dirname, '/')
}).href;
const defaultProjectURL = new URL('./index.html', resourcesURL).href;
${wbVerifyScriptHash ? `const expectedScriptHash = ${JSON.stringify(this.wbAppIntegrity ? this.wbAppIntegrity.sha256 : sha256HexOfString(this.script))};` : ''}
${wbVerifyIndexHash ? `const expectedIndexHash = ${JSON.stringify(expectedIndexHash)};` : ''}
const wbIntegrityFile = ${JSON.stringify(this.wbAppIntegrity ? this.wbAppIntegrity.file : 'script.js')};
const WB_INTEGRITY_REQUIRED = ${JSON.stringify(wbIntegrityRequired)};
const WB_INTEGRITY_MANIFEST = ${JSON.stringify(wbIntegrityManifestName)};
const WB_INTEGRITY_SIGNATURE = ${JSON.stringify(wbIntegritySignatureName)};
const WB_INTEGRITY_KEYS = ${JSON.stringify(wbIntegrityPublicKeys || {})};

const verifySignedIntegrityManifest = () => {
  try {
    const manifestPath = path.join(__dirname, WB_INTEGRITY_MANIFEST);
    const sigPath = path.join(__dirname, WB_INTEGRITY_SIGNATURE);
    if (!fs.existsSync(manifestPath) || !fs.existsSync(sigPath)) {
      return !WB_INTEGRITY_REQUIRED;
    }
    const manifestBytes = fs.readFileSync(manifestPath);
    const signature = fs.readFileSync(sigPath);
    const manifest = JSON.parse(manifestBytes.toString('utf8'));
    const kid = manifest && typeof manifest.kid === 'string' ? manifest.kid : '';
    const pub = WB_INTEGRITY_KEYS[kid];
    if (!pub) return false;
    const ok = crypto.verify('sha256', manifestBytes, pub, signature);
    if (!ok) return false;
    const files = manifest && manifest.files && typeof manifest.files === 'object' ? manifest.files : null;
    if (!files) return false;
    for (const rel of Object.keys(files)) {
      if (typeof rel !== 'string' || !rel) return false;
      const expected = files[rel] && typeof files[rel].sha256 === 'string' ? files[rel].sha256 : '';
      if (!expected) return false;
      const abs = path.join(__dirname, rel);
      const normalized = path.normalize(abs);
      if (!normalized.startsWith(path.normalize(__dirname + path.sep))) return false;
      const data = fs.readFileSync(abs);
      const actual = crypto.createHash('sha256').update(data).digest('hex');
      if (actual !== expected) return false;
    }
    return true;
  } catch (e) {
    return false;
  }
};

const verifyIntegrity = () => {
  if (!verifySignedIntegrityManifest()) {
    app.exit(2);
    return false;
  }
  if (!${JSON.stringify(wbVerifyScriptHash)} && !${JSON.stringify(wbVerifyIndexHash)}) return true;
  try {
    if (${JSON.stringify(wbVerifyScriptHash)}) {
      const data = fs.readFileSync(path.join(__dirname, wbIntegrityFile));
      const actual = crypto.createHash('sha256').update(data).digest('hex');
      if (actual !== expectedScriptHash) {
        app.exit(2);
        return false;
      }
    }
    if (${JSON.stringify(wbVerifyIndexHash)}) {
      const data = fs.readFileSync(path.join(__dirname, 'index.html'));
      const actual = crypto.createHash('sha256').update(data).digest('hex');
      if (actual !== expectedIndexHash) {
        app.exit(2);
        return false;
      }
    }
  } catch (e) {
    app.exit(2);
    return false;
  }
  return true;
};

const createWindow = (windowOptions) => {
  const options = {
    title: ${JSON.stringify(this.options.app.windowTitle)},
    icon: path.resolve(__dirname, ${JSON.stringify(iconName)}),
    useContentSize: true,
    webPreferences: {
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false,
      devTools: ${wbDisableDevtools ? 'false' : 'true'},
      preload: path.resolve(__dirname, ${JSON.stringify(electronPreloadName)}),
      backgroundThrottling: ${this.options.app.backgroundThrottling},
    },
    frame: ${this.options.app.windowControls !== 'frameless'},
    show: true,
    width: ${this.options.stageWidth},
    height: ${this.options.stageHeight},
    ...windowOptions,
  };

  const activeScreen = screen.getDisplayNearestPoint(screen.getCursorScreenPoint());
  const bounds = activeScreen.workArea;
  options.x = bounds.x + ((bounds.width - options.width) / 2);
  options.y = bounds.y + ((bounds.height - options.height) / 2);

  const window = new BrowserWindow(options);
  return window;
};

const createProjectWindow = (url) => {
  const windowMode = ${JSON.stringify(this.options.app.windowMode)};
  const options = {
    show: false,
    backgroundColor: ${JSON.stringify(this.options.appearance.background)},
    width: ${this.computeWindowSize().width},
    height: ${this.computeWindowSize().height},
    minWidth: 50,
    minHeight: 50,
  };
  // fullscreen === false disables fullscreen on macOS so only set this property when it's true
  if (windowMode === 'fullscreen') {
    options.fullscreen = true;
  }
  const window = createWindow(options);
  if (windowMode === 'maximize') {
    window.maximize();
  }
  window.loadURL(url);
  if (!${JSON.stringify(wbDisableDevtools)}) {
    try {
      window.webContents.openDevTools({mode: 'detach'});
    } catch (e) {
      // ignore
    }
  }
  window.show();
};

const getOverlayDataURL = () => {
  const html = \`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{margin:0;padding:0;width:100%;height:100%;background:transparent;overflow:hidden;}#img{position:absolute;left:0;top:0;pointer-events:none;user-select:none;will-change:transform,opacity,width,height;image-rendering:auto;}</style></head><body><img id="img"><script>const img=document.getElementById('img');let meta=null;let pendingState=null;let hasNew=false;const applyState=(state)=>{if(!meta||!state)return;const stageScale=Number(state.stageScale)||1;const scale=(Number(state.scale)||100)/100;const pxScale=stageScale*scale;const bw=Number(meta.baseWidth)||0;const bh=Number(meta.baseHeight)||0;const rcxBase=Number(meta.rotationCenterX)||0;const rcyBase=Number(meta.rotationCenterY)||0;const w=bw*pxScale;const h=bh*pxScale;const rcx=rcxBase*pxScale;const rcy=rcyBase*pxScale;img.style.width=w+'px';img.style.height=h+'px';img.style.transformOrigin=rcx+'px '+rcy+'px';const x=Number(state.x)||0;const y=Number(state.y)||0;const rot=Number(state.rotation)||0;img.style.transform='translate3d('+(x-rcx)+'px,'+(y-rcy)+'px,0) rotate('+rot+'deg)';img.style.opacity=state.visible?'1':'0';};const tick=()=>{if(hasNew){hasNew=false;applyState(pendingState);}requestAnimationFrame(tick);};requestAnimationFrame(tick);window.OverlayPreload.onState((payload)=>{if(!payload)return;if(payload.type==='init'){meta=payload.meta||null;if(meta&&meta.costumeDataURI){img.src=meta.costumeDataURI;}pendingState=payload.state||null;hasNew=true;}else if(payload.type==='state'){pendingState=payload.state||null;hasNew=true;}});</script></body></html>\`;
  return \`data:text/html;charset=utf-8,\${encodeURIComponent(html)}\`;
};

const createOverlayWindow = (parentWindow, display) => {
  const overlayWindow = new BrowserWindow({
    x: display.bounds.x,
    y: display.bounds.y,
    width: display.bounds.width,
    height: display.bounds.height,
    parent: parentWindow,
    frame: false,
    transparent: true,
    resizable: false,
    fullscreenable: false,
    minimizable: false,
    maximizable: false,
    closable: true,
    hasShadow: false,
    show: false,
    focusable: false,
    skipTaskbar: true,
    backgroundColor: '#00000000',
    webPreferences: {
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.resolve(__dirname, ${JSON.stringify(electronOverlayPreloadName)}),
      backgroundThrottling: false,
    }
  });
  overlayWindow.setIgnoreMouseEvents(true);
  overlayWindow.loadURL(getOverlayDataURL());
  return overlayWindow;
};

const createDataWindow = (dataURI) => {
  const window = createWindow({});
  window.loadURL(dataURI);
};

const isResourceURL = (url) => {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.protocol === 'file:' && parsedUrl.href.startsWith(resourcesURL);
  } catch (e) {
    // ignore
  }
  return false;
};

const SAFE_PROTOCOLS = [
  'https:',
  'http:',
  'mailto:',
];

const isSafeOpenExternal = (url) => {
  try {
    const parsedUrl = new URL(url);
    return SAFE_PROTOCOLS.includes(parsedUrl.protocol);
  } catch (e) {
    // ignore
  }
  return false;
};

const isDataURL = (url) => {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.protocol === 'data:';
  } catch (e) {
    // ignore
  }
  return false;
};

const openLink = (url) => {
  if (isDataURL(url)) {
    createDataWindow(url);
  } else if (isResourceURL(url)) {
    createProjectWindow(url);
  } else if (isSafeOpenExternal(url)) {
    shell.openExternal(url);
  }
};

const createProcessCrashMessage = (details) => {
  let message = details.type ? details.type + ' child process' : 'Renderer process';
  message += ' crashed: ' + details.reason + ' (' + details.exitCode + ')\\n\\n';
  if (process.arch === 'ia32') {
    message += 'Usually this means the project was too big for the 32-bit Electron environment or your computer is out of memory. Ask the creator to use the 64-bit environment instead.';
  } else {
    message += 'Usually this means your computer is out of memory.';
  }
  return message;
};

app.on('render-process-gone', (event, webContents, details) => {
  const window = BrowserWindow.fromWebContents(webContents);
  dialog.showMessageBoxSync(window, {
    type: 'error',
    title: 'Error',
    message: createProcessCrashMessage(details)
  });
});

app.on('child-process-gone', (event, details) => {
  dialog.showMessageBoxSync({
    type: 'error',
    title: 'Error',
    message: createProcessCrashMessage(details)
  });
});

app.on('web-contents-created', (event, contents) => {
  contents.setWindowOpenHandler((details) => {
    setImmediate(() => {
      openLink(details.url);
    });
    return {action: 'deny'};
  });
  contents.on('will-navigate', (e, url) => {
    if (!isResourceURL(url)) {
      e.preventDefault();
      openLink(url);
    }
  });
  contents.on('before-input-event', (e, input) => {
    const window = BrowserWindow.fromWebContents(contents);
    if (!window || input.type !== "keyDown") return;
    if (input.key === 'F11' || (input.key === 'Enter' && input.alt)) {
      window.setFullScreen(!window.isFullScreen());
    } else if (!${JSON.stringify(wbDisableDevtools)} && (input.key === 'F12' || (input.key && input.key.toLowerCase() === 'i' && input.control && input.shift))) {
      try {
        if (contents.isDevToolsOpened()) {
          contents.closeDevTools();
        } else {
          contents.openDevTools({mode: 'detach'});
        }
      } catch (e) {
        // ignore
      }
    } else if (input.key === 'Escape') {
      const behavior = ${JSON.stringify(this.options.app.escapeBehavior)};
      if (window.isFullScreen() && (behavior === 'unfullscreen-only' || behavior === 'unfullscreen-or-exit')) {
        window.setFullScreen(false);
      } else if (behavior === 'unfullscreen-or-exit' || behavior === 'exit-only') {
        window.close();
      }
    }
  });
});

app.on('session-created', (session) => {
  session.webRequest.onBeforeRequest({
    urls: ["file://*"]
  }, (details, callback) => {
    callback({
      cancel: !details.url.startsWith(resourcesURL)
    });
  });

  const referer = 'https://packager.turbowarp.org/referer.html#' + app.getName();
  session.webRequest.onBeforeSendHeaders((details, callback) => {
    callback({
      requestHeaders: {
        referer
      }
    });
  });
});

app.on('window-all-closed', () => {
  app.quit();
});

app.whenReady().then(() => {
  if (!verifyIntegrity()) return;
  createProjectWindow(defaultProjectURL);
});
`;

    let preloadJS = `'use strict';
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('EditorPreload', {
  overlayCreate: (id, meta) => ipcRenderer.invoke('overlay-create', {id, meta}),
  overlayUpdate: (id, state) => ipcRenderer.invoke('overlay-update', {id, state}),
  overlayDestroy: (id) => ipcRenderer.invoke('overlay-destroy', {id}),
  wbLog: (level, message, data) => {
    try {
      ipcRenderer.send('wb-log-event', {level, message, data});
    } catch (e) {
      // ignore
    }
    return Promise.resolve({ok: true});
  },
  wbGetOverlayLogPath: () => ipcRenderer.invoke('wb-overlay-log-path'),
  wbOpenOverlayLog: () => ipcRenderer.invoke('wb-open-overlay-log'),
  readFile: (path) => ipcRenderer.invoke('wb-read-file', {path}),
  getWindowBounds: () => ipcRenderer.invoke('wb-get-window-bounds'),
  openDevTools: () => ipcRenderer.invoke('wb-open-devtools')
});

try {
  ipcRenderer.send('wb-log-event', {level: 'info', message: 'editor preload loaded'});
} catch (e) {
  try { console.log('editor preload loaded'); } catch (e2) { }
}
`;

    let overlayPreloadJS = `'use strict';
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('OverlayPreload', {
  onState: (callback) => {
    ipcRenderer.on('overlay-state', (event, state) => callback(state));
  }
});

try {
  ipcRenderer.send('wb-log-event', {level: 'info', message: 'overlay preload loaded'});
} catch (e) {
  try { console.log('overlay preload loaded'); } catch (e2) { }
}
`;

    mainJS += `
let wbOverlayLogPath = path.join(os.tmpdir(), 'wb-overlay-' + process.pid + '.log');
const wbOverlayLogFallbackPath = path.join(__dirname, 'wb-overlay.log');
const wbEnsureLogFile = (p) => {
  try {
    fs.mkdirSync(path.dirname(p), {recursive: true});
    fs.appendFileSync(p, '');
    return true;
  } catch (e) {
    return false;
  }
};
if (!wbEnsureLogFile(wbOverlayLogPath)) {
  wbOverlayLogPath = wbOverlayLogFallbackPath;
  wbEnsureLogFile(wbOverlayLogPath);
}
const wbOverlayLogSafe = (value) => {
  try {
    if (typeof value === 'string') return value;
    return JSON.stringify(value);
  } catch (e) {
    try {
      return String(value);
    } catch (e2) {
      return '[unserializable]';
    }
  }
};
const wbOverlayLog = (...args) => {
  const line = new Date().toISOString() + ' ' + args.map(wbOverlayLogSafe).join(' ') + '\\n';
  try {
    fs.appendFileSync(wbOverlayLogPath, line);
  } catch (e) {
    try {
      wbOverlayLogPath = wbOverlayLogFallbackPath;
      wbEnsureLogFile(wbOverlayLogPath);
      fs.appendFileSync(wbOverlayLogPath, line);
    } catch (e2) {
    }
  }
  try { console.log(line.trim()); } catch (e) { }
};
wbOverlayLog('main started');
wbOverlayLog('overlay log path', wbOverlayLogPath);
process.on('uncaughtException', (e) => {
  wbOverlayLog('uncaughtException', e && (e.stack || e));
});
process.on('unhandledRejection', (e) => {
  wbOverlayLog('unhandledRejection', e && (e.stack || e));
});

ipcMain.handle('wb-log', async (event, {level, message, data}) => {
  wbOverlayLog('renderer', level || 'info', message || '', data);
  return {ok: true};
});
ipcMain.on('wb-log-event', (event, payload) => {
  try {
    const p = payload && typeof payload === 'object' ? payload : {};
    wbOverlayLog('renderer', p.level || 'info', p.message || '', p.data);
  } catch (e) {
    wbOverlayLog('renderer', 'error', 'wb-log-event error', e && (e.stack || e));
  }
});
ipcMain.handle('wb-overlay-log-path', async () => ({ok: true, path: wbOverlayLogPath}));
ipcMain.handle('wb-open-overlay-log', async () => {
  try {
    await shell.openPath(wbOverlayLogPath);
    return {ok: true};
  } catch (e) {
    return {ok: false, error: String(e && (e.stack || e))};
  }
});

ipcMain.handle('overlay-create', async (event, {id, meta}) => {
  try {
    const overlayId = typeof id === 'string' ? id.trim() : '';
    if (!overlayId) return {ok: false, error: 'Missing overlay id'};
    if (!meta || typeof meta !== 'object') return {ok: false, error: 'Missing meta'};
    const parentWindow = BrowserWindow.fromWebContents(event.sender);
    if (!parentWindow) return {ok: false, error: 'Missing parent window'};
    wbOverlayLog('overlay-create', overlayId, 'from', parentWindow.id);
    const existing = overlayWindows.get(overlayId);
    if (existing && existing.window && !existing.window.isDestroyed()) {
      existing.window.destroy();
    }
    overlayWindows.delete(overlayId);
    const s = meta && meta.state && typeof meta.state === 'object' ? meta.state : null;
    const sx = s ? Number(s.screenX) : NaN;
    const sy = s ? Number(s.screenY) : NaN;
    const parentBounds = parentWindow.getBounds();
    const point = (Number.isFinite(sx) && Number.isFinite(sy)) ? {x: sx, y: sy} : {
      x: parentBounds.x + (parentBounds.width / 2),
      y: parentBounds.y + (parentBounds.height / 2)
    };
    const display = screen.getDisplayNearestPoint({x: point.x, y: point.y});
    const overlayWindow = createOverlayWindow(parentWindow, display);
    overlayWindow.webContents.on('did-fail-load', (e, errorCode, errorDescription) => {
      wbOverlayLog('overlay did-fail-load', overlayId, errorCode, errorDescription);
    });
    overlayWindow.on('closed', () => {
      wbOverlayLog('overlay closed', overlayId);
    });
    overlayWindows.set(overlayId, {window: overlayWindow, displayId: display.id});
    overlayWindow.webContents.once('did-finish-load', () => {
      try {
        if (overlayWindow.isDestroyed()) return;
        const bounds = overlayWindow.getBounds();
        const payloadState = {
          x: Number.isFinite(sx) ? (sx - bounds.x) : 0,
          y: Number.isFinite(sy) ? (sy - bounds.y) : 0,
          stageScale: s && Number.isFinite(Number(s.stageScale)) ? Number(s.stageScale) : 1,
          scale: s && Number.isFinite(Number(s.scale)) ? Number(s.scale) : 100,
          rotation: s && Number.isFinite(Number(s.rotation)) ? Number(s.rotation) : 0,
          visible: s ? !!s.visible : true
        };
        wbOverlayLog('overlay init', overlayId, 'bounds', bounds, 'state', payloadState);
        overlayWindow.webContents.send('overlay-state', {type: 'init', meta, state: payloadState});
        overlayWindow.showInactive();
        overlayWindow.moveTop();
        try { overlayWindow.setAlwaysOnTop(true, 'screen-saver'); } catch (e) { /* ignore */ }
        try { overlayWindow.setVisibleOnAllWorkspaces(true, {visibleOnFullScreen: true}); } catch (e) { /* ignore */ }
      } catch (e) {
        wbOverlayLog('overlay init error', overlayId, e && (e.stack || e));
      }
    });
    parentWindow.once('closed', () => {
      const entry = overlayWindows.get(overlayId);
      if (entry && entry.window && !entry.window.isDestroyed()) {
        entry.window.destroy();
      }
      overlayWindows.delete(overlayId);
    });
    return {ok: true};
  } catch (e) {
    wbOverlayLog('overlay-create error', e && (e.stack || e));
    return {ok: false, error: String(e && (e.stack || e))};
  }
});
ipcMain.handle('overlay-update', async (event, {id, state}) => {
  try {
    const overlayId = typeof id === 'string' ? id.trim() : '';
    if (!overlayId) return {ok: false, error: 'Missing overlay id'};
    const entry = overlayWindows.get(overlayId);
    if (!entry || !entry.window || entry.window.isDestroyed()) return {ok: false, error: 'Overlay not found'};
    if (!state || typeof state !== 'object') return {ok: false, error: 'Missing state'};
    const screenX = Number(state.screenX);
    const screenY = Number(state.screenY);
    if (!Number.isFinite(screenX) || !Number.isFinite(screenY)) return {ok: false, error: 'Missing screenX/screenY'};
    const display = screen.getDisplayNearestPoint({x: screenX, y: screenY});
    if (display && display.id !== entry.displayId) {
      entry.displayId = display.id;
      entry.window.setBounds(display.bounds, false);
    }
    const bounds = entry.window.getBounds();
    const payloadState = {
      x: screenX - bounds.x,
      y: screenY - bounds.y,
      stageScale: Number(state.stageScale) || 1,
      scale: Number(state.scale) || 100,
      rotation: Number(state.rotation) || 0,
      visible: !!state.visible
    };
    entry.window.webContents.send('overlay-state', {type: 'state', state: payloadState});
    return {ok: true};
  } catch (e) {
    wbOverlayLog('overlay-update error', e && (e.stack || e));
    return {ok: false, error: String(e && (e.stack || e))};
  }
});
ipcMain.handle('overlay-destroy', async (event, {id}) => {
  try {
    const overlayId = typeof id === 'string' ? id.trim() : '';
    if (!overlayId) return {ok: false, error: 'Missing overlay id'};
    wbOverlayLog('overlay-destroy', overlayId);
    const entry = overlayWindows.get(overlayId);
    if (entry && entry.window && !entry.window.isDestroyed()) {
      entry.window.destroy();
    }
    overlayWindows.delete(overlayId);
    return {ok: true};
  } catch (e) {
    wbOverlayLog('overlay-destroy error', e && (e.stack || e));
    return {ok: false, error: String(e && (e.stack || e))};
  }
});
ipcMain.handle('wb-read-file', async (event, {path: relativePath}) => {
  const rel = typeof relativePath === 'string' ? relativePath : '';
  const safe = rel.replace(/^\.?[\\/]+/, '');
  const candidates = [];
  try {
    if (typeof process === 'object' && process) {
      if (typeof process.resourcesPath === 'string' && process.resourcesPath) {
        candidates.push(path.join(process.resourcesPath, 'app'));
        candidates.push(path.join(process.resourcesPath, 'app.asar'));
        candidates.push(path.join(process.resourcesPath, 'app.asar.unpacked'));
      }
      if (typeof process.execPath === 'string' && process.execPath) {
        candidates.push(path.dirname(process.execPath));
      }
      if (typeof process.cwd === 'function') {
        candidates.push(process.cwd());
      }
    }
  } catch (e) {}
  candidates.push(__dirname);
  let resolved = null;
  for (const base of candidates) {
    try {
      if (!base) continue;
      const attempt = path.join(base, safe);
      if (fs.existsSync(attempt)) {
        resolved = attempt;
        break;
      }
    } catch (e) {}
  }
  if (!resolved) {
    resolved = path.join(__dirname, safe);
  }
  const data = fs.readFileSync(resolved);
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
});
ipcMain.handle('wb-get-window-bounds', async (event) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  if (!window) return null;
  return window.getBounds();
});
ipcMain.handle('wb-open-devtools', async (event) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  if (!window) return {ok: false};
  try {
    if (!window.webContents.isDevToolsOpened()) {
      window.webContents.openDevTools({mode: 'detach'});
    }
    return {ok: true};
  } catch (e) {
    return {ok: false};
  }
});
`;

    if (
      this.project.analysis.usesSteamworks &&
      ['electron-win64', 'electron-linux64', 'electron-mac'].includes(this.options.target)
    ) {
      mainJS += `
      const enableSteamworks = () => {
        const APP_ID = +${JSON.stringify(this.options.steamworks.appId)};
        const steamworks = require('./steamworks.js/');

        const client = steamworks.init(APP_ID);

        const async = (event, callback) => ipcMain.handle(event, (e, ...args) => {
          return callback(...args);
        });
        const sync = (event, callback) => ipcMain.on(event, (e, ...args) => {
          e.returnValue = callback(...args);
        });

        async('Steamworks.achievement.activate', (achievement) => client.achievement.activate(achievement));
        async('Steamworks.achievement.clear', (achievement) => client.achievement.clear(achievement));
        sync('Steamworks.achievement.isActivated', (achievement) => client.achievement.isActivated(achievement));
        sync('Steamworks.apps.isDlcInstalled', (dlc) => client.apps.isDlcInstalled(dlc));
        sync('Steamworks.localplayer.getName', () => client.localplayer.getName());
        sync('Steamworks.localplayer.getLevel', () => client.localplayer.getLevel());
        sync('Steamworks.localplayer.getIpCountry', () => client.localplayer.getIpCountry());
        sync('Steamworks.localplayer.getSteamId', () => client.localplayer.getSteamId());
        async('Steamworks.overlay.activateToWebPage', (url) => client.overlay.activateToWebPage(url));

        steamworks.electronEnableSteamOverlay();
        sync('Steamworks.ok', () => true);
      };

      try {
        enableSteamworks();
      } catch (e) {
        console.error(e);
        ipcMain.on('Steamworks.ok', (e) => {
          e.returnValue = false;
        });
        app.whenReady().then(() => {
          const ON_ERROR = ${JSON.stringify(this.options.steamworks.onError)};
          const window = BrowserWindow.getAllWindows()[0];
          if (ON_ERROR === 'warning') {
            dialog.showMessageBox(window, {
              type: 'error',
              message: 'Error initializing Steamworks: ' + e,
            });
          } else if (ON_ERROR === 'error') {
            dialog.showMessageBoxSync(window, {
              type: 'error',
              message: 'Error initializing Steamworks: ' + e,
            });
            app.quit();
          }
        });
      }`;

      preloadJS += `
      const enableSteamworks = () => {
        const sync = (event) => (...args) => ipcRenderer.sendSync(event, ...args);
        const async = (event) => (...args) => ipcRenderer.invoke(event, ...args);

        contextBridge.exposeInMainWorld('Steamworks', {
          ok: sync('Steamworks.ok'),
          achievement: {
            activate: async('Steamworks.achievement.activate'),
            clear: async('Steamworks.achievement.clear'),
            isActivated: sync('Steamworks.achievement.isActivated'),
          },
          apps: {
            isDlcInstalled: sync('Steamworks.apps.isDlcInstalled'),
          },
          leaderboard: {
            uploadScore: async('Steamworks.leaderboard.uploadScore'),
          },
          localplayer: {
            getName: sync('Steamworks.localplayer.getName'),
            getLevel: sync('Steamworks.localplayer.getLevel'),
            getIpCountry: sync('Steamworks.localplayer.getIpCountry'),
            getSteamId: sync('Steamworks.localplayer.getSteamId'),
          },
          overlay: {
            activateToWebPage: async('Steamworks.overlay.activateToWebPage'),
          },
        });
      };
      enableSteamworks();`;

      const steamworksBuffer = await this.fetchLargeAsset('steamworks.js', 'arraybuffer');
      const steamworksZip = await (await getJSZip()).loadAsync(steamworksBuffer);
      for (const [path, file] of Object.entries(steamworksZip.files)) {
        const newPath = path.replace(/^package\//, 'steamworks.js/');
        setFileFast(zip, `${resourcesPrefix}${newPath}`, file);
      }
    }

    if (wbProtectElectron) {
      const obf = (code) => JavaScriptObfuscator.obfuscate(code, {
        compact: true,
        controlFlowFlattening: true,
        controlFlowFlatteningThreshold: 0.75,
        deadCodeInjection: true,
        deadCodeInjectionThreshold: 0.2,
        stringArray: true,
        stringArrayEncoding: ['base64'],
        stringArrayThreshold: 0.75,
        renameGlobals: false
      }).getObfuscatedCode();
      mainJS = obf(mainJS);
      preloadJS = obf(preloadJS);
      overlayPreloadJS = obf(overlayPreloadJS);
    }

    const writeSplitEntry = (entryName, baseName, code) => {
      const partCount = 8;
      const parts = splitString(code, partCount);
      const partFiles = [];
      for (let i = 0; i < partCount; i++) {
        const partFile = `${baseName}.${i}.wb`;
        partFiles.push(partFile);
        zip.file(`${resourcesPrefix}${partFile}`, parts[i]);
      }
      const stub = `'use strict';const fs=require('fs');const path=require('path');let code='';for(const p of ${JSON.stringify(partFiles)}){code+=fs.readFileSync(path.join(__dirname,p),'utf8');}eval(code);`;
      zip.file(`${resourcesPrefix}${entryName}`, stub);
    };

    if (wbSplitElectronEntry && wbProtectElectron) {
      writeSplitEntry(electronMainName, 'electron-main', mainJS);
      writeSplitEntry(electronPreloadName, 'electron-preload', preloadJS);
      writeSplitEntry(electronOverlayPreloadName, 'electron-overlay-preload', overlayPreloadJS);
    } else {
      zip.file(`${resourcesPrefix}${electronMainName}`, mainJS);
      zip.file(`${resourcesPrefix}${electronPreloadName}`, preloadJS);
      zip.file(`${resourcesPrefix}${electronOverlayPreloadName}`, overlayPreloadJS);
    }

    for (const [path, data] of Object.entries(projectZip.files)) {
      setFileFast(zip, `${resourcesPrefix}${path}`, data);
    }

    if (isWindows) {
      const readme = [
        '1) Extract the whole zip',
        `2) Open "${packageName}.exe" to start the app.`,
        'Open "licenses.html" for information regarding open source software used by the app.',
      ].join('\n\n');
      zip.file(`${rootPrefix}README.txt`, readme);
    } else if (isMac) {
      zip.file(`How to run ${this.options.app.packageName}.txt`, generateMacReadme(this.options));

      const plist = this.getPlistPropertiesForPrimaryExecutable();
      await this.updatePlist(zip, `${contentsPrefix}Info.plist`, plist);

      // macOS Electron apps also contain several helper apps that we should update.
      const HELPERS = [
        'Electron Helper',
        'Electron Helper (GPU)',
        'Electron Helper (Renderer)',
        'Electron Helper (Plugin)',
      ];
      for (const name of HELPERS) {
        await this.updatePlist(zip, `${contentsPrefix}Frameworks/${name}.app/Contents/Info.plist`, {
          // In the prebuilt Electron binaries on GitHub, the original app has a CFBundleIdentifier of
          // com.github.Electron and all the helpers have com.github.Electron.helper
          [CFBundleIdentifier]: `${plist[CFBundleIdentifier]}.helper`,

          // We shouldn't change the actual name of the helpers because we don't actually rename their .app
          // We also don't rename the executable
          [CFBundleDisplayName]: name.replace('Electron', this.options.app.packageName),

          // electron-builder always updates the helpers to use the same version as the app itself
          [CFBundleVersion]: this.options.app.version,
          [CFBundleShortVersionString]: this.options.app.version,
        });
      }

      if (this.options.app.writeMacElectronIcns !== false) {
        try {
          const icns = await pngToAppleICNS(icon);
          zip.file(`${contentsPrefix}Resources/electron.icns`, icns);
          packagerInfo.macos.icnsWritten = true;
          wbPackagerLog('macos electron.icns written');
        } catch (e) {
          packagerInfo.macos.icnsWritten = false;
          packagerInfo.macos.icnsError = String(e && (e.stack || e));
          wbPackagerLog('macos electron.icns write failed', {error: packagerInfo.macos.icnsError});
        }
      } else {
        packagerInfo.macos.icnsWritten = null;
        wbPackagerLog('macos electron.icns skipped');
      }
    } else if (isLinux) {
      // Some Linux distributions can't easily open the executable file from the GUI, so we'll add a simple wrapper that people can use instead.
      const startScript = `#!/bin/bash
cd "$(dirname "$0")"
./${packageName}`;
      zip.file(`${rootPrefix}start.sh`, startScript, {
        unixPermissions: 0o100755
      });
      if (this.options.app.exportLinuxDesktopFile) {
        try {
          const desktopName = `${packageName}.desktop`;
          const iconInstallPath = `${packageName}/icons/hicolor/512x512/apps/${packageName}.png`;
          zip.file(iconInstallPath, icon);
          const desktop = [
            '[Desktop Entry]',
            'Type=Application',
            `Name=${this.options.app.windowTitle || packageName}`,
            `Exec=sh -c 'cd \"$(dirname \"%k\")\"; ./start.sh'`,
            `Icon=${packageName}`,
            'Terminal=false',
            'Categories=Game;'
          ].join('\n') + '\n';
          zip.file(`${packageName}/${desktopName}`, desktop);
          const installScript = `#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="${packageName}"
mkdir -p "$HOME/.local/share/applications"
mkdir -p "$HOME/.local/share/icons/hicolor/512x512/apps"
cp "$DIR/${desktopName}" "$HOME/.local/share/applications/${packageName}.desktop"
cp "$DIR/icons/hicolor/512x512/apps/${packageName}.png" "$HOME/.local/share/icons/hicolor/512x512/apps/${packageName}.png"
update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
gtk-update-icon-cache -q "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
echo "Installed desktop entry: $HOME/.local/share/applications/${packageName}.desktop"
`;
          zip.file(`${packageName}/install-desktop.sh`, installScript, {unixPermissions: 0o100755});
          packagerInfo.linux.desktopWritten = true;
          wbPackagerLog('linux desktop entry written', {desktop: `${packageName}/${desktopName}`, icon: iconInstallPath});
        } catch (e) {
          packagerInfo.linux.desktopWritten = false;
          packagerInfo.linux.desktopError = String(e && (e.stack || e));
          wbPackagerLog('linux desktop entry write failed', {error: packagerInfo.linux.desktopError});
        }
      } else {
        packagerInfo.linux.desktopWritten = null;
        wbPackagerLog('linux desktop entry skipped');
      }
    }

    writePackagerInfo();
    return zip;
  }

  async addWebViewMac (projectZip) {
    validatePackageName(this.options.app.packageName);

    const buffer = await this.fetchLargeAsset(this.options.target, 'arraybuffer');
    const appZip = await (await getJSZip()).loadAsync(buffer);

    // +-- WebView.app
    //   +-- Contents
    //     +-- Info.plist
    //     +-- MacOS
    //       +-- WebView (executable)
    //     +-- Resources
    //       +-- index.html
    //       +-- application_config.json
    //       +-- AppIcon.icns

    const newAppName = `${this.options.app.packageName}.app`;
    const contentsPrefix = `${newAppName}/Contents/`;
    const resourcesPrefix = `${newAppName}/Contents/Resources/`;

    const zip = new (await getJSZip());
    for (const [path, data] of Object.entries(appZip.files)) {
      const newPath = path
        // Rename the .app itself
        .replace('WebView.app', newAppName)
        // Rename the executable
        .replace(/WebView$/, this.options.app.packageName);
      setFileFast(zip, newPath, data);
    }
    for (const [path, data] of Object.entries(projectZip.files)) {
      setFileFast(zip, `${resourcesPrefix}${path}`, data);
    }

    const icon = await Adapter.getAppIcon(this.options.app.icon);
    const icns = await pngToAppleICNS(icon);
    zip.file(`${resourcesPrefix}AppIcon.icns`, icns);
    zip.remove(`${resourcesPrefix}Assets.car`);

    const parsedBackgroundColor = parseInt(this.options.appearance.background.substr(1), 16);
    const applicationConfig = {
      title: this.options.app.windowTitle,
      background: [
        // R, G, B [0-255]
        parsedBackgroundColor >> 16 & 0xff,
        parsedBackgroundColor >> 8 & 0xff,
        parsedBackgroundColor & 0xff,
        // A [0-1]
        1
      ],
      width: this.computeWindowSize().width,
      height: this.computeWindowSize().height
    };
    zip.file(`${resourcesPrefix}application_config.json`, JSON.stringify(applicationConfig));

    await this.updatePlist(zip, `${contentsPrefix}Info.plist`, this.getPlistPropertiesForPrimaryExecutable());

    zip.file(`How to run ${this.options.app.packageName}.txt`, generateMacReadme(this.options));

    return zip;
  }

  makeWebSocketProvider () {
    // If using the default turbowarp.org server, we'll add a fallback for the turbowarp.xyz alias.
    // This helps work around web filters as turbowarp.org can be blocked for games and turbowarp.xyz uses
    // a problematic TLD. These are the same server and same variables, just different domain.
    const cloudHost = this.options.cloudVariables.cloudHost === 'wss://clouddata.turbowarp.org' ? [
      'wss://clouddata.turbowarp.org',
      'wss://clouddata.turbowarp.xyz'
    ] : this.options.cloudVariables.cloudHost;
    return `new Scaffolding.Cloud.WebSocketProvider(${JSON.stringify(cloudHost)}, ${JSON.stringify(this.options.projectId)})`;
  }

  makeLocalStorageProvider () {
    return `new Scaffolding.Cloud.LocalStorageProvider(${JSON.stringify(`cloudvariables:${this.options.projectId}`)})`;
  }

  makeCustomProvider () {
    const variables = this.options.cloudVariables.custom;
    let result = '{const providers = {};\n';
    for (const provider of new Set(Object.values(variables))) {
      if (provider === 'ws') {
        result += `providers.ws = ${this.makeWebSocketProvider()};\n`;
      } else if (provider === 'local') {
        result += `providers.local = ${this.makeLocalStorageProvider()};\n`;
      }
    }
    result += 'for (const provider of Object.values(providers)) scaffolding.addCloudProvider(provider);\n';
    for (const variableName of Object.keys(variables)) {
      const providerToUse = variables[variableName];
      result += `scaffolding.addCloudProviderOverride(${JSON.stringify(variableName)}, providers[${JSON.stringify(providerToUse)}] || null);\n`;
    }
    result += '}';
    return result;
  }

  generateFilename (extension) {
    return `${this.options.app.windowTitle}.${extension}`;
  }

  async generateGetProjectData () {
    const result = [];
    let getProjectDataFunction = '';
    let isZip = false;
    let storageProgressStart;
    let storageProgressEnd;

    const encryptProject = !!(this.options.wb && this.options.wb.encryptProject && this.options.target !== 'html');
    const packResourcesXor = !!(this.options.wb && this.options.wb.packResourcesXor);
    const shredWbResources = !!(encryptProject && this.options.wb && this.options.wb.shredWbResources);
    const obfuscateUnpack = !!(this.options.wb && this.options.wb.obfuscateUnpack);
    const nonceAttr = (this.options.wb && this.options.wb.secureCsp && this._wbCspNonce) ? ` nonce="${this._wbCspNonce}"` : '';
    let wbUnpackHelpers = '';
    if (encryptProject) {
      const enc = this.wbEncryption;
      if (!enc || !enc.k || (!enc.iv && !(enc.v === 2 && enc.project && enc.project.iv))) {
        throw new Error('Missing encryption metadata');
      }
      result.push(`
      <script${nonceAttr}>
        window.__WB_ENC__ = ${JSON.stringify(Object.assign({}, enc, shredWbResources ? {shred: {parts: 32}} : null))};
      </script>`);

      wbUnpackHelpers = `(function () {
  const b64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const seedFromName = (name) => {
    let seed = 0;
    for (let i = 0; i < name.length; i++) seed = (seed + name.charCodeAt(i)) & 0xff;
    return seed;
  };
  const xorDecrypt = (bytes, keyBytes, seed) => {
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      out[i] = bytes[i] ^ keyBytes[(i + seed) % keyBytes.length] ^ seed;
    }
    return out;
  };
  const state = {
    ready: false,
    hasManifest: false,
    manifest: null,
    outerKey: null,
    projectKeyBytes: null,
    projectIvBase: null,
    assetXorKey: null,
    ensureInit: async (zip) => {
      if (state.ready) return;
      const mf = zip.file('wb/manifest.json');
      if (!mf) {
        state.ready = true;
        state.hasManifest = false;
        return;
      }
      state.manifest = JSON.parse(await mf.async('string'));
      state.hasManifest = true;

      const enc = window.__WB_ENC__;
      if (!enc || !enc.k) throw new Error('Missing encryption metadata');
      const outerKeyBytes = b64ToBytes(enc.k);
      state.outerKey = await crypto.subtle.importKey('raw', outerKeyBytes, {name: 'AES-GCM'}, false, ['decrypt']);

      const unwrapKey = async (encObj) => {
        const iv = b64ToBytes(encObj.iv);
        const ct = b64ToBytes(encObj.data);
        const raw = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, state.outerKey, ct);
        return new Uint8Array(raw);
      };

      state.projectIvBase = b64ToBytes(state.manifest.pj.ivBase);
      state.projectKeyBytes = await unwrapKey(state.manifest.pj.keyEnc);
      state.assetXorKey = await unwrapKey(state.manifest.assets.keyEnc);

      state.ready = true;
    },
    decryptProjectJSON: async (zip) => {
      if (!state.hasManifest) return null;
      const key = await crypto.subtle.importKey('raw', state.projectKeyBytes, {name: 'AES-GCM'}, false, ['decrypt']);
      const out = new Uint8Array(state.manifest.pj.total);
      let offset = 0;
      for (let i = 0; i < state.manifest.pj.chunkCount; i++) {
        const chunkFile = zip.file('wb/pj/' + i + '.bin');
        if (!chunkFile) throw new Error('Missing project chunk: ' + i);
        const chunkEncrypted = await chunkFile.async('arraybuffer');
        const iv = new Uint8Array(12);
        iv.set(state.projectIvBase, 0);
        new DataView(iv.buffer).setUint32(8, i, true);
        const chunkPlain = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, chunkEncrypted);
        const chunkBytes = new Uint8Array(chunkPlain);
        out.set(chunkBytes, offset);
        offset += chunkBytes.length;
      }
      return out.buffer;
    },
    decryptAsset: async (path, data) => {
      if (!state.hasManifest) return data;
      return xorDecrypt(data, state.assetXorKey, seedFromName(path));
    }
  };
  window.__WB_UNPACK__ = state;
})();`;
      if (obfuscateUnpack) {
        wbUnpackHelpers = JavaScriptObfuscator.obfuscate(wbUnpackHelpers, {
          compact: true,
          controlFlowFlattening: true,
          controlFlowFlatteningThreshold: 0.75,
          deadCodeInjection: true,
          deadCodeInjectionThreshold: 0.2,
          stringArray: true,
          stringArrayEncoding: ['base64'],
          stringArrayThreshold: 0.75,
          renameGlobals: false
        }).getObfuscatedCode();
      }
    }

    if (this.options.target === 'html') {
      isZip = this.project.type !== 'blob';
      storageProgressStart = PROGRESS_FETCHED_COMPRESSED;
      storageProgressEnd = PROGRESS_EXTRACTED_COMPRESSED;

      const originalProjectData = new Uint8Array(this.project.arrayBuffer);
      let projectData = originalProjectData;
      if (packResourcesXor && isZip) {
        const keyBytes = randomBytes(32);
        const saltBytes = randomBytes(16);
        const meta = buildXorResourcePackMeta(this.options.projectId, keyBytes, saltBytes, 8);
        const seed = (fileSeed('project') ^ saltBytes[0]) & 0xff;
        meta.seed = seed;
        projectData = xorCrypt(originalProjectData, keyBytes, seed);
        result.push(`<script${nonceAttr}>window.__WB_PX__=${JSON.stringify(meta)};</script>`);
      }

      // keep this up-to-date with base85.js
      result.push(`
      <script${nonceAttr}>
      const getBase85DecodeValue = (code) => {
        if (code === 0x28) code = 0x3c;
        if (code === 0x29) code = 0x3e;
        return code - 0x2a;
      };
      const base85decode = (str, outBuffer, outOffset) => {
        const view = new DataView(outBuffer, outOffset, Math.floor(str.length / 5 * 4));
        for (let i = 0, j = 0; i < str.length; i += 5, j += 4) {
          view.setUint32(j, (
            getBase85DecodeValue(str.charCodeAt(i + 4)) * 85 * 85 * 85 * 85 +
            getBase85DecodeValue(str.charCodeAt(i + 3)) * 85 * 85 * 85 +
            getBase85DecodeValue(str.charCodeAt(i + 2)) * 85 * 85 +
            getBase85DecodeValue(str.charCodeAt(i + 1)) * 85 +
            getBase85DecodeValue(str.charCodeAt(i))
          ), true);
        }
      };
      let projectDecodeBuffer = new ArrayBuffer(${Math.ceil(projectData.length / 4) * 4});
      let projectDecodeIndex = 0;
      const decodeChunk = (size) => {
        try {
          if (document.currentScript.tagName.toUpperCase() !== 'SCRIPT') throw new Error('document.currentScript is not a script');
          base85decode(document.currentScript.getAttribute("data"), projectDecodeBuffer, projectDecodeIndex);
          document.currentScript.remove();
          projectDecodeIndex += size;
          setProgress(interpolate(${PROGRESS_LOADED_SCRIPTS}, ${PROGRESS_FETCHED_COMPRESSED}, projectDecodeIndex / ${projectData.length}));
        } catch (e) {
          handleError(e);
        }
      };
      </script>`);

      // To avoid unnecessary padding, this should be a multiple of 4.
      const CHUNK_SIZE = 1024 * 64;

      for (let i = 0; i < projectData.length; i += CHUNK_SIZE) {
        const projectChunk = projectData.subarray(i, i + CHUNK_SIZE);
        const base85 = encode(projectChunk);
        result.push(`<script data="${base85}">decodeChunk(${projectChunk.length})</script>\n`);
      }

      getProjectDataFunction = `() => {
        const buffer = projectDecodeBuffer;
        projectDecodeBuffer = null; // Allow GC
        let out = new Uint8Array(buffer, 0, ${projectData.length});
        try {
          const px = window.__WB_PX__;
          if (px && px.parts && px.order && px.salt && Number.isFinite(px.seed)) {
            const b64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            const saltBytes = b64ToBytes(px.salt);
            const xor = (bytes, keyBytes, seed) => {
              const o = new Uint8Array(bytes.length);
              for (let i = 0; i < bytes.length; i++) {
                o[i] = bytes[i] ^ keyBytes[(i + seed) % keyBytes.length] ^ seed;
              }
              return o;
            };
            const partCount = px.parts.length;
            const shards = [];
            for (let i = 0; i < partCount; i++) {
              const physical = px.order[i];
              const obf = b64ToBytes(px.parts[physical]);
              shards.push(xor(obf, saltBytes, i & 0xff));
            }
            const total = shards.reduce((a, b) => a + b.length, 0);
            const keyBytes = new Uint8Array(total);
            let off = 0;
            for (const s of shards) {
              keyBytes.set(s, off);
              off += s.length;
            }
            out = xor(out, keyBytes, px.seed & 0xff);
          }
        } catch (e) {}
        return Promise.resolve(out);
      }`;
    } else {
      let src;
      if (encryptProject) {
        isZip = true;
        src = shredWbResources ? './wb-project.0.wb' : './wb-project.bin';
        storageProgressStart = PROGRESS_FETCHED_COMPRESSED;
        storageProgressEnd = PROGRESS_EXTRACTED_COMPRESSED;
      } else if (this.project.type === 'blob' || this.options.target === 'zip-one-asset') {
        isZip = this.project.type !== 'blob';
        src = './project.zip';
        storageProgressStart = PROGRESS_FETCHED_COMPRESSED;
        storageProgressEnd = PROGRESS_EXTRACTED_COMPRESSED;
      } else {
        src = './assets/project.json';
        storageProgressStart = PROGRESS_FETCHED_PROJECT_JSON;
        storageProgressEnd = PROGRESS_FETCHED_ASSETS;
      }

      getProjectDataFunction = `() => new Promise((resolve, reject) => {
        const readAll = async (readFile) => {
          ${encryptProject ? `
          const enc = window.__WB_ENC__;
          const parts = enc && enc.shred && Number(enc.shred.parts);
          if (parts && parts > 1) {
            const base64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            const keyBytes = base64ToBytes(enc.k);
            const ivB64 = (enc && enc.v === 2 && enc.project && enc.project.iv) ? enc.project.iv : enc.iv;
            const ivBytes = base64ToBytes(ivB64);
            const labelBytes = new TextEncoder().encode('wb-project');
            const combined = new Uint8Array(keyBytes.length + ivBytes.length + labelBytes.length);
            combined.set(keyBytes, 0);
            combined.set(ivBytes, keyBytes.length);
            combined.set(labelBytes, keyBytes.length + ivBytes.length);
            let seed = 0;
            if (crypto && crypto.subtle && crypto.subtle.digest) {
              const digest = await crypto.subtle.digest('SHA-256', combined);
              seed = new DataView(digest).getUint32(0, false) >>> 0;
            }
            const xorshift32 = (x) => {
              x ^= x << 13;
              x ^= x >>> 17;
              x ^= x << 5;
              return x >>> 0;
            };
            const order = Array.from({length: parts}, (_, i) => i);
            let s = seed >>> 0;
            for (let i = order.length - 1; i > 0; i--) {
              s = xorshift32(s);
              const j = s % (i + 1);
              const tmp = order[i];
              order[i] = order[j];
              order[j] = tmp;
            }
            const buffers = [];
            let total = 0;
            for (let i = 0; i < parts; i++) {
              const physical = order[i];
              const data = await readFile('./wb-project.' + physical + '.wb');
              const u8 = data instanceof Uint8Array ? data : new Uint8Array(data);
              buffers.push(u8);
              total += u8.length;
            }
            const out = new Uint8Array(total);
            let offset = 0;
            for (const b of buffers) {
              out.set(b, offset);
              offset += b.length;
            }
            return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
          }` : ''}
          return readFile(${JSON.stringify(src)});
        };
        if (window.EditorPreload && typeof window.EditorPreload.readFile === 'function') {
          Promise.resolve(readAll(window.EditorPreload.readFile)).then(async (data) => {
            try {
              ${encryptProject ? `
              const enc = window.__WB_ENC__;
              if (!enc || !enc.k || (!enc.iv && !(enc.v === 2 && enc.project && enc.project.iv))) throw new Error('Missing encryption metadata');
              if (!(crypto && crypto.subtle && crypto.subtle.importKey && crypto.subtle.decrypt)) {
                throw new Error('WebCrypto is not available');
              }
              const base64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
              const keyBytes = base64ToBytes(enc.k);
              const ivB64 = (enc && enc.v === 2 && enc.project && enc.project.iv) ? enc.project.iv : enc.iv;
              const ivBytes = base64ToBytes(ivB64);
              const key = await crypto.subtle.importKey('raw', keyBytes, {name: 'AES-GCM'}, false, ['decrypt']);
              const plaintext = await crypto.subtle.decrypt({name: 'AES-GCM', iv: ivBytes}, key, data);
              resolve(plaintext);` : `
              resolve(data);`}
            } catch (e) {
              reject(e);
            }
          }).catch(reject);
          return;
        }
        const xhr = new XMLHttpRequest();
        xhr.onload = async () => {
          try {
            ${encryptProject ? `
            const enc = window.__WB_ENC__;
            if (!enc || !enc.k || (!enc.iv && !(enc.v === 2 && enc.project && enc.project.iv))) throw new Error('Missing encryption metadata');
            if (!(crypto && crypto.subtle && crypto.subtle.importKey && crypto.subtle.decrypt)) {
              throw new Error('WebCrypto is not available');
            }
            const base64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            const keyBytes = base64ToBytes(enc.k);
            const ivB64 = (enc && enc.v === 2 && enc.project && enc.project.iv) ? enc.project.iv : enc.iv;
            const ivBytes = base64ToBytes(ivB64);
            const key = await crypto.subtle.importKey('raw', keyBytes, {name: 'AES-GCM'}, false, ['decrypt']);
            let ciphertext = xhr.response;
            const parts = enc && enc.shred && Number(enc.shred.parts);
            if (parts && parts > 1) {
              const labelBytes = new TextEncoder().encode('wb-project');
              const combined = new Uint8Array(keyBytes.length + ivBytes.length + labelBytes.length);
              combined.set(keyBytes, 0);
              combined.set(ivBytes, keyBytes.length);
              combined.set(labelBytes, keyBytes.length + ivBytes.length);
              let seed = 0;
              if (crypto && crypto.subtle && crypto.subtle.digest) {
                const digest = await crypto.subtle.digest('SHA-256', combined);
                seed = new DataView(digest).getUint32(0, false) >>> 0;
              }
              const xorshift32 = (x) => {
                x ^= x << 13;
                x ^= x >>> 17;
                x ^= x << 5;
                return x >>> 0;
              };
              const order = Array.from({length: parts}, (_, i) => i);
              let s = seed >>> 0;
              for (let i = order.length - 1; i > 0; i--) {
                s = xorshift32(s);
                const j = s % (i + 1);
                const tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
              }
              const buffers = [];
              let total = 0;
              for (let i = 0; i < parts; i++) {
                const physical = order[i];
                const xhr2 = new XMLHttpRequest();
                const p = new Promise((resolve2, reject2) => {
                  xhr2.onload = () => resolve2(xhr2.response);
                  xhr2.onerror = () => reject2(new Error('Failed to load project shard'));
                });
                xhr2.responseType = 'arraybuffer';
                xhr2.open('GET', './wb-project.' + physical + '.wb');
                xhr2.send();
                const data = await p;
                const u8 = new Uint8Array(data);
                buffers.push(u8);
                total += u8.length;
              }
              const out = new Uint8Array(total);
              let offset = 0;
              for (const b of buffers) {
                out.set(b, offset);
                offset += b.length;
              }
              ciphertext = out.buffer;
            }
            const plaintext = await crypto.subtle.decrypt({name: 'AES-GCM', iv: ivBytes}, key, ciphertext);
            resolve(plaintext);` : `
            resolve(xhr.response);`}
          } catch (e) {
            reject(e);
          }
        };
        xhr.onerror = () => {
          if (location.protocol === 'file:') {
            reject(new Error('Zip environment must be used on a website, not on a local file. To fix this error, use the "Plain HTML" environment instead.'));
          } else {
            reject(new Error('Request to load project data failed.'));
          }
        };
        xhr.onprogress = (e) => {
          if (e.lengthComputable) {
            setProgress(interpolate(${PROGRESS_LOADED_SCRIPTS}, ${storageProgressStart}, e.loaded / e.total));
          }
        };
        xhr.responseType = 'arraybuffer';
        xhr.open('GET', ${JSON.stringify(src)});
        xhr.send();
      })`;
    }

    result.push(`
    <script${nonceAttr}>
      const getProjectData = (function() {
        const storage = scaffolding.storage;
        storage.onprogress = (total, loaded) => {
          setProgress(interpolate(${storageProgressStart}, ${storageProgressEnd}, loaded / total));
        };
        ${encryptProject ? `
        ${wbUnpackHelpers}
        ` : ''}
        ${isZip ? `
        let zip;
        // Allow zip to be GC'd after project loads
        vm.runtime.on('PROJECT_LOADED', () => (zip = null));
        const findFileInZip = (path) => zip.file(path) || zip.file(new RegExp("^([^/]*/)?" + path + "$"))[0];
        const initWbRes = (() => {
          let ready = false;
          let meta = null;
          let keyBytes = null;
          let saltBytes = null;
          const b64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
          const seedFromName = (name) => {
            let seed = 0;
            for (let i = 0; i < name.length; i++) seed = (seed + name.charCodeAt(i)) & 0xff;
            return seed;
          };
          const xor = (bytes, key, seed) => {
            const out = new Uint8Array(bytes.length);
            for (let i = 0; i < bytes.length; i++) {
              out[i] = bytes[i] ^ key[(i + seed) % key.length] ^ seed;
            }
            return out;
          };
          const ensure = () => {
            if (ready) return;
            ready = true;
            meta = (typeof window === 'object' && window) ? window.__WB_RSP__ : null;
            if (!meta || !meta.parts || !meta.order || !meta.salt) {
              meta = null;
              return;
            }
            saltBytes = b64ToBytes(meta.salt);
            const partCount = meta.parts.length;
            const parts = meta.parts;
            const order = meta.order;
            const shards = [];
            for (let i = 0; i < partCount; i++) {
              const physical = order[i];
              const shardObf = b64ToBytes(parts[physical]);
              shards.push(xor(shardObf, saltBytes, i & 0xff));
            }
            const total = shards.reduce((a, b) => a + b.length, 0);
            const out = new Uint8Array(total);
            let off = 0;
            for (const s of shards) {
              out.set(s, off);
              off += s.length;
            }
            keyBytes = out;
          };
          const tryLoad = async (requestedPath) => {
            ensure();
            if (!meta || !meta.map || !keyBytes || !saltBytes) return null;
            const packedPath = meta.map[requestedPath];
            if (!packedPath) return null;
            const file = zip.file(packedPath) || zip.file(new RegExp("^([^/]*/)?" + packedPath + "$"))[0];
            if (!file) return null;
            const data = await file.async('uint8array');
            const seed = (seedFromName(requestedPath) ^ saltBytes[0]) & 0xff;
            return xor(data, keyBytes, seed);
          };
          return {tryLoad};
        })();
        storage.addHelper({
          load: async (assetType, assetId, dataFormat) => {
            if (!zip) {
              throw new Error('Zip is not loaded or has been closed');
            }
            const path = assetId + '.' + dataFormat;
            const file = findFileInZip(path);
            let data;
            if (file) {
              data = await file.async('uint8array');
            } else {
              data = await initWbRes.tryLoad(path);
              if (!data) {
                console.error('Asset is not in zip: ' + path);
                return Promise.resolve(null);
              }
            }
            if (window.__WB_UNPACK__) await window.__WB_UNPACK__.ensureInit(zip);
            const decrypted = window.__WB_UNPACK__ ? await window.__WB_UNPACK__.decryptAsset(path, data) : data;
            return storage.createAsset(assetType, dataFormat, decrypted, assetId);
          }
        });
        return () => (${getProjectDataFunction})().then(async (data) => {
          zip = await Scaffolding.JSZip.loadAsync(data);
          if (window.__WB_UNPACK__) await window.__WB_UNPACK__.ensureInit(zip);
          if (window.__WB_UNPACK__) {
            const decrypted = await window.__WB_UNPACK__.decryptProjectJSON(zip);
            if (decrypted) return decrypted;
          }

          const file = findFileInZip('project.json');
          if (!file) {
            const packed = await initWbRes.tryLoad('project.json');
            if (packed) return packed.buffer.slice(packed.byteOffset, packed.byteOffset + packed.byteLength);
            throw new Error('project.json is not in zip');
          }
          return file.async('arraybuffer');
        });` : (packResourcesXor && !encryptProject && this.project && this.project.type === 'sb3' && this.options.target !== 'zip-one-asset' ? `
        const wbResState = {
          ready: false,
          initPromise: null,
          helperInstalled: false,
          meta: null,
          keyBytes: null,
          saltBytes: null
        };
        const readFileOrFetch = async (path) => {
          if (window.EditorPreload && typeof window.EditorPreload.readFile === 'function') {
            const data = await window.EditorPreload.readFile(path);
            if (data instanceof Uint8Array) return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
            if (data instanceof ArrayBuffer) return data;
            return new Uint8Array(data).buffer;
          }
          return await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.onload = () => resolve(xhr.response);
            xhr.onerror = () => reject(new Error('Request failed: ' + path));
            xhr.responseType = 'arraybuffer';
            xhr.open('GET', path);
            xhr.send();
          });
        };
        const b64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        const xor = (bytes, keyBytes, seed) => {
          const out = new Uint8Array(bytes.length);
          for (let i = 0; i < bytes.length; i++) {
            out[i] = bytes[i] ^ keyBytes[(i + seed) % keyBytes.length] ^ seed;
          }
          return out;
        };
        const seedFromName = (name) => {
          let seed = 0;
          for (let i = 0; i < name.length; i++) seed = (seed + name.charCodeAt(i)) & 0xff;
          return seed;
        };
        const initWbRes = async () => {
          if (wbResState.ready) return;
          if (wbResState.initPromise) return wbResState.initPromise;
          wbResState.initPromise = (async () => {
            const metaText = new TextDecoder().decode(new Uint8Array(await readFileOrFetch('./wb-res/meta.json')));
            const meta = JSON.parse(metaText);
            if (!meta || !meta.parts || !meta.order || !meta.salt || !meta.map) {
              wbResState.ready = true;
              return;
            }
            wbResState.meta = meta;
            wbResState.saltBytes = b64ToBytes(meta.salt);
            const shards = [];
            for (let i = 0; i < meta.parts.length; i++) {
              const physical = meta.order[i];
              const shardObf = b64ToBytes(meta.parts[physical]);
              shards.push(xor(shardObf, wbResState.saltBytes, i & 0xff));
            }
            const total = shards.reduce((a, b) => a + b.length, 0);
            const keyBytes = new Uint8Array(total);
            let off = 0;
            for (const s of shards) {
              keyBytes.set(s, off);
              off += s.length;
            }
            wbResState.keyBytes = keyBytes;
            wbResState.ready = true;
          })();
          return wbResState.initPromise;
        };
        const loadPacked = async (logicalPath) => {
          await initWbRes();
          if (!wbResState.meta || !wbResState.keyBytes || !wbResState.saltBytes) return null;
          const packedPath = wbResState.meta.map[logicalPath];
          if (!packedPath) return null;
          const ab = await readFileOrFetch('./' + packedPath);
          const data = new Uint8Array(ab);
          const seed = (seedFromName(logicalPath) ^ wbResState.saltBytes[0]) & 0xff;
          return xor(data, wbResState.keyBytes, seed);
        };
        const ensureHelper = async () => {
          if (wbResState.helperInstalled) return;
          await initWbRes();
          if (!wbResState.meta) return;
          wbResState.helperInstalled = true;
          storage.addHelper({
            load: async (assetType, assetId, dataFormat) => {
              const key = assetId + '.' + dataFormat;
              const plain = await loadPacked(key);
              if (!plain) return null;
              return storage.createAsset(assetType, dataFormat, plain, assetId);
            }
          });
        };
        return async () => {
          await ensureHelper();
          const plain = await loadPacked('project.json');
          if (!plain) throw new Error('Missing packed project.json');
          return plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength);
        };` : `
        storage.addWebStore(
          [
            storage.AssetType.ImageVector,
            storage.AssetType.ImageBitmap,
            storage.AssetType.Sound,
            storage.AssetType.Font
          ].filter(i => i),
          (asset) => new URL('./assets/' + asset.assetId + '.' + asset.dataFormat, location).href
        );
        return ${getProjectDataFunction};`)}
      })();
    </script>`);

    return result;
  }

  async generateFavicon () {
    if (this.options.app.icon === null) {
      return '';
    }
    const data = await Adapter.readAsURL(this.options.app.icon, 'app icon');
    return `<link rel="icon" href="${data}">`;
  }

  async generateCursor () {
    if (this.options.cursor.type !== 'custom') {
      return this.options.cursor.type;
    }
    if (!this.options.cursor.custom) {
      // Configured to use a custom cursor but no image was selected
      return 'auto';
    }
    const data = await Adapter.readAsURL(this.options.cursor.custom, 'custom cursor');
    return `url(${data}) ${this.options.cursor.center.x} ${this.options.cursor.center.y}, auto`;
  }

  async generateExtensionURLs () {
    const dispatchProgress = (progress) => this.dispatchEvent(new CustomEvent('fetch-extensions', {
      detail: {
        progress
      }
    }));

    const isSecureCsp = (() => {
      const wb = this.options && this.options.wb;
      return !!(wb && wb.secureCsp);
    })();
    const extensionLoadStrategy = (() => {
      const wb = this.options && this.options.wb;
      const configured = wb && typeof wb.extensionLoadStrategy === 'string' ? wb.extensionLoadStrategy : 'auto';
      if (configured === 'file' || configured === 'data') return configured;
      if (this.options && this.options.target === 'html') return 'data';
      return isSecureCsp ? 'file' : 'data';
    })();
    if (extensionLoadStrategy === 'file') {
      if (!this._embeddedExtensionFiles || typeof this._embeddedExtensionFiles !== 'object') {
        this._embeddedExtensionFiles = {};
      }
    }

    const shouldTryToFetch = (url) => {
      if (!this.options.bakeExtensions) {
        return false;
      }
      try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
      } catch (e) {
        return false;
      }
    };

    /** @type {string[]} */
    const allURLs = this.options.extensions;
    const unfetchableURLs = allURLs.filter((url) => !shouldTryToFetch(url));
    const urlsToFetch = allURLs.filter((url) => shouldTryToFetch(url));
    const finalURLs = [...unfetchableURLs];

    const extractDataUriCode = (dataUri) => {
      const s = String(dataUri || '');
      const comma = s.indexOf(',');
      if (comma === -1) return '';
      const encoded = s.slice(comma + 1);
      try {
        return decodeURIComponent(encoded);
      } catch (e) {
        return encoded;
      }
    };
    const storeExtensionAsFile = (code) => {
      const js = String(code || '');
      const hash = sha256HexOfString(js);
      const filePath = `extensions/${hash}.js`;
      this._embeddedExtensionFiles[filePath] = js;
      return `./${filePath}`;
    };
    const maybeConvertDataUri = (url) => {
      if (extensionLoadStrategy !== 'file') return url;
      const s = String(url || '');
      if (!s.startsWith('data:text/javascript')) return url;
      const js = extractDataUriCode(s);
      if (!js) return url;
      return storeExtensionAsFile(js);
    };

    for (let i = 0; i < finalURLs.length; i++) {
      finalURLs[i] = maybeConvertDataUri(finalURLs[i]);
    }

    if (urlsToFetch.length !== 0) {
      for (let i = 0; i < urlsToFetch.length; i++) {
        dispatchProgress(i / urlsToFetch.length);
        const url = urlsToFetch[i];
        try {
          const source = await Adapter.fetchExtensionScript(url);
          // Wrap the extension in an IIFE so that extensions written for the sandbox are less
          // likely to cause issues in an unsandboxed environment due to global pollution or
          // overriding Scratch.*
          const wrappedSource = `(function(Scratch) { ${source} })(Scratch);`
          if (extensionLoadStrategy === 'file') {
            finalURLs.push(storeExtensionAsFile(wrappedSource));
          } else {
            const dataURI = `data:text/javascript;,${encodeURIComponent(wrappedSource)}`;
            finalURLs.push(dataURI);
          }
        } catch (e) {
          console.warn('Could not bake extension', url, e);
          finalURLs.push(url);
        }
      }
      dispatchProgress(1);
    }

    return finalURLs;
  }

  async package () {
    if (!Adapter) {
      throw new Error('Missing adapter');
    }
    if (this.used) {
      throw new Error('Packager was already used');
    }
    this.used = true;
    this.ensureNotAborted();
    await this.loadResources();
    this.ensureNotAborted();
    await this.loadPlugins();
    await this.runPluginHook('beforePackage', null, {phase: 'beforePackage'});
    this._embeddedExtensionFiles = null;
    const packResourcesXor = !!(this.options.wb && this.options.wb.packResourcesXor);
    const encryptProject = !!(this.options.wb && this.options.wb.encryptProject && this.options.target !== 'html');
    if (encryptProject) {
      if (!(crypto && crypto.subtle && crypto.subtle.importKey && crypto.subtle.encrypt)) {
        throw new Error('WebCrypto is not available');
      }
      const keyBytes = randomBytes(32);
      const projectIvBytes = randomBytes(12);
      this.wbEncryption = {
        v: 2,
        alg: 'A256GCM',
        k: bytesToBase64(keyBytes),
        project: {
          iv: bytesToBase64(projectIvBytes)
        }
      };

      if (this.project && this.project.type === 'sb3') {
        const originalZip = await (await getJSZip()).loadAsync(this.project.arrayBuffer);
        const projectFile = originalZip.file('project.json');
        if (projectFile) {
          const innerZip = new (await getJSZip())();

          const innerProjectKey = randomBytes(32);
          const innerProjectIvBase = randomBytes(8);
          const innerAssetXorKey = randomBytes(32);

          const wrapKey = async (bytes) => {
            const wrapIv = randomBytes(12);
            const wrapped = await aesGcmEncrypt(bytes, keyBytes, wrapIv);
            return {
              iv: bytesToBase64(wrapIv),
              data: bytesToBase64(new Uint8Array(wrapped))
            };
          };

          let projectBytes;
          const needsProjectJSON = (this.options.wb && this.options.wb.opcodeObfuscation) || (this.plugins && this.plugins.length > 0);
          if (needsProjectJSON) {
            const jsonText = await projectFile.async('string');
            let projectJSON = JSON.parse(jsonText);
            if (this.options.wb && this.options.wb.opcodeObfuscation) {
              obfuscateProjectOpcodes(projectJSON);
            }
            projectJSON = await this.runPluginHook('transformProjectJson', projectJSON, {phase: 'encryptProject'});
            projectBytes = new TextEncoder().encode(JSON.stringify(projectJSON));
          } else {
            projectBytes = await projectFile.async('uint8array');
          }
          const chunkSize = 64 * 1024;
          const chunkCount = Math.ceil(projectBytes.length / chunkSize);
          for (let i = 0; i < chunkCount; i++) {
            const chunk = projectBytes.subarray(i * chunkSize, Math.min(projectBytes.length, (i + 1) * chunkSize));
            const iv = new Uint8Array(12);
            iv.set(innerProjectIvBase, 0);
            new DataView(iv.buffer).setUint32(8, i, true);
            const encrypted = await aesGcmEncrypt(chunk, innerProjectKey, iv);
            innerZip.file(`wb/pj/${i}.bin`, new Uint8Array(encrypted));
          }

          for (const name of Object.keys(originalZip.files)) {
            const file = originalZip.files[name];
            if (!file || file.dir) continue;
            if (name === 'project.json') continue;
            const data = await file.async('uint8array');
            innerZip.file(name, xorCrypt(data, innerAssetXorKey, fileSeed(name)));
          }

          const manifest = {
            v: 1,
            pj: {
              chunkSize,
              chunkCount,
              total: projectBytes.length,
              ivBase: bytesToBase64(innerProjectIvBase),
              keyEnc: await wrapKey(innerProjectKey)
            },
            assets: {
              algo: 'xor1',
              keyEnc: await wrapKey(innerAssetXorKey)
            }
          };
          innerZip.file('wb/manifest.json', JSON.stringify(manifest));

          this.project.arrayBuffer = await innerZip.generateAsync({
            type: 'uint8array',
            compression: 'DEFLATE',
            platform: 'UNIX'
          });
        }
      }
    } else {
      this.wbEncryption = null;
    }
    if (!encryptProject && this.project && this.project.type === 'sb3' && this.options.wb && this.options.wb.opcodeObfuscation) {
      const zip = await (await getJSZip()).loadAsync(this.project.arrayBuffer);
      const projectFile = zip.file('project.json');
      if (projectFile) {
        const jsonText = await projectFile.async('string');
        let projectJSON = JSON.parse(jsonText);
        obfuscateProjectOpcodes(projectJSON);
        projectJSON = await this.runPluginHook('transformProjectJson', projectJSON, {phase: 'postOpcodeObfuscation'});
        zip.file('project.json', JSON.stringify(projectJSON));
        this.project.arrayBuffer = await zip.generateAsync({
          type: 'uint8array',
          compression: 'DEFLATE',
          platform: 'UNIX'
        });
      }
    }
    if (this.project && this.project.type === 'sb3' && this.options.wb && this.options.wb.obfuscateNames) {
      const zip = await (await getJSZip()).loadAsync(this.project.arrayBuffer);
      const projectFile = zip.file('project.json');
      if (projectFile) {
        const jsonText = await projectFile.async('string');
        let projectJSON = JSON.parse(jsonText);
        obfuscateProjectJSON(projectJSON);
        projectJSON = await this.runPluginHook('transformProjectJson', projectJSON, {phase: 'postNameObfuscation'});
        zip.file('project.json', JSON.stringify(projectJSON));
        this.project.arrayBuffer = await zip.generateAsync({
          type: 'uint8array',
          compression: 'DEFLATE',
          platform: 'UNIX'
        });
      }
    }
    if (this.project && this.project.type === 'sb3' && this.plugins && this.plugins.length > 0 && !(this.options.wb && (this.options.wb.opcodeObfuscation || this.options.wb.obfuscateNames))) {
      const zip = await (await getJSZip()).loadAsync(this.project.arrayBuffer);
      const projectFile = zip.file('project.json');
      if (projectFile) {
        const jsonText = await projectFile.async('string');
        let projectJSON = JSON.parse(jsonText);
        projectJSON = await this.runPluginHook('transformProjectJson', projectJSON, {phase: 'projectJsonOnly'});
        zip.file('project.json', JSON.stringify(projectJSON));
        this.project.arrayBuffer = await zip.generateAsync({
          type: 'uint8array',
          compression: 'DEFLATE',
          platform: 'UNIX'
        });
      }
    }
    const useCleanTemplate = !!(this.options.wb && this.options.wb.cleanHtmlTemplate);
    const useSecureCsp = !!(this.options.wb && this.options.wb.secureCsp);
    const isLocalTarget = String(this.options.target || '').startsWith('electron-') || String(this.options.target || '').startsWith('nwjs-') || String(this.options.target || '') === 'webview-mac';
    const cspNonce = useSecureCsp ? bytesToBase64(randomBytes(16)).replace(/=+$/g, '') : '';
    this._wbCspNonce = cspNonce;
    const scriptNonceAttr = useSecureCsp ? ` nonce="${cspNonce}"` : '';
    const csp = useSecureCsp
      ? `default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data: blob:; media-src 'self' data: blob:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-${cspNonce}'; script-src-attr 'none'; connect-src 'self' https: http: ws: wss:${isLocalTarget ? " file:" : ""}; worker-src 'self' blob:;`
      : "default-src * 'self' 'unsafe-inline' 'unsafe-eval' data: blob:";
    let html = useCleanTemplate ? encodeBigString`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>${escapeXML(this.options.app.windowTitle)}</title>
  <style>
    :root { background: ${this.options.appearance.background}; color: ${this.options.appearance.foreground}; }
    html, body { width: 100%; height: 100%; margin: 0; padding: 0; overflow: hidden; background: ${this.options.appearance.background}; color: ${this.options.appearance.foreground}; font-family: sans-serif; }
    #app { position: fixed; inset: 0; }
    #overlay-ui { position: fixed; inset: 0; pointer-events: none; }
    .screen { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; background: ${this.options.appearance.background}; }
    #launch { background: rgba(0,0,0,0.55); cursor: pointer; pointer-events: auto; }
    #error { pointer-events: auto; padding: 24px; box-sizing: border-box; }
    #error h1 { margin: 0 0 12px; font-weight: 600; }
    #error-message, #error-stack { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; white-space: pre-wrap; max-width: 900px; }
    #error-stack { max-height: 40vh; overflow: auto; opacity: 0.9; }
    #loading-inner { width: 280px; height: 10px; border: 1px solid currentColor; box-sizing: border-box; }
    #loading-bar { height: 100%; width: 0%; background: currentColor; }
    [hidden] { display: none !important; }
    ${this.options.custom.css}
  </style>
  ${await this.generateFavicon()}
</head>
<body>
  <div id="app"></div>
  <div id="overlay-ui">
    <div id="launch" class="screen" hidden>
      <div>Click to start</div>
    </div>
    <div id="loading" class="screen">
      <noscript>Enable JavaScript</noscript>
      ${this.options.loadingScreen.text ? `<div style="font-size:32px;margin:0 0 16px;">${escapeXML(this.options.loadingScreen.text)}</div>` : ''}
      <div id="loading-inner"><div id="loading-bar"></div></div>
    </div>
    <div id="error" class="screen" hidden>
      <h1>Runtime error</h1>
      <div id="error-message"></div>
      <div id="error-stack"></div>
    </div>
  </div>

  ${this.options.target === 'html' ? `<script${scriptNonceAttr}>${this.script}</script>` : `<script src="script.js"${scriptNonceAttr}></script>`}
  <script${scriptNonceAttr}>${removeUnnecessaryEmptyLines(`
    const appElement = document.getElementById('app');
    const launchScreen = document.getElementById('launch');
    const loadingScreen = document.getElementById('loading');
    const loadingBar = document.getElementById('loading-bar');
    const errorScreen = document.getElementById('error');
    const errorMessage = document.getElementById('error-message');
    const errorStack = document.getElementById('error-stack');

    const handleError = (err) => {
      try { console.error(err); } catch (e) { }
      try { wbLog && wbLog('error', 'runtime error', String(err && (err.stack || err))); } catch (e) { }
      if (!errorScreen.hidden) return;
      errorScreen.hidden = false;
      if (loadingScreen) loadingScreen.hidden = true;
      if (launchScreen) launchScreen.hidden = true;
      const msg = '' + (err && (err.message || err) || 'Unknown error');
      errorMessage.textContent = msg;
      const stack = (err && err.stack) ? err.stack : 'no stack';
      errorStack.textContent = stack + '\\nUser agent: ' + navigator.userAgent;
    };
    const setProgress = (p) => {
      if (!loadingBar) return;
      const clamped = Math.max(0, Math.min(1, Number(p) || 0));
      loadingBar.style.width = (clamped * 100) + '%';
    };
    const interpolate = (a, b, t) => a + t * (b - a);
    const WB_DEBUG = ${JSON.stringify(!!(this.options.wb && this.options.wb.debugLog))};
    const WB_VERBOSE = ${JSON.stringify(!!(this.options.wb && this.options.wb.debugLogVerbose))};
    const WB_SECURE_CSP = ${JSON.stringify(useSecureCsp)};
    const wbLog = (level, message, data) => {
      if (!WB_DEBUG) return;
      const m = String(message || '');
      try {
        const fn = (level === 'error' && console.error) ? console.error : console.log;
        fn.call(console, '[wb]', m, data || '');
      } catch (e) {}
      try {
        if (window.EditorPreload && typeof window.EditorPreload.wbLog === 'function') {
          window.EditorPreload.wbLog(level || 'info', m, data);
        }
      } catch (e) {}
    };

    try {
      setProgress(${PROGRESS_LOADED_SCRIPTS});

      const scaffolding = new Scaffolding.Scaffolding();
      scaffolding.width = ${this.options.stageWidth};
      scaffolding.height = ${this.options.stageHeight};
      scaffolding.resizeMode = ${JSON.stringify(this.options.resizeMode)};
      scaffolding.usePackagedRuntime = ${this.options.packagedRuntime};
      scaffolding.editableLists = ${this.options.monitors.editableLists};
      scaffolding.setup();
      scaffolding.appendTo(appElement);

      const vm = scaffolding.vm;
      window.scaffolding = scaffolding;
      window.vm = vm;

      vm.setTurboMode(${this.options.turbo});
      if (vm.setInterpolation) vm.setInterpolation(${this.options.interpolation});
      if (vm.setFramerate) vm.setFramerate(${this.options.framerate});
      if (vm.renderer && vm.renderer.setUseHighQualityRender) vm.renderer.setUseHighQualityRender(${this.options.highQualityPen});
      if (vm.setRuntimeOptions) vm.setRuntimeOptions({fencing: ${this.options.fencing}, miscLimits: ${this.options.miscLimits}, maxClones: ${this.options.maxClones}});
      if (vm.setCompilerOptions) vm.setCompilerOptions({enabled: ${this.options.compiler.enabled}, warpTimer: ${this.options.compiler.warpTimer}});
      if (vm.renderer && vm.renderer.setMaxTextureDimension) vm.renderer.setMaxTextureDimension(${this.options.maxTextureDimension});
      if (vm.runtime && vm.runtime.setEnforcePrivacy) vm.runtime.setEnforcePrivacy(false);

      scaffolding.setExtensionSecurityManager({getSandboxMode: () => 'unsandboxed', canLoadExtensionFromProject: () => true});
      for (const extensionURL of ${JSON.stringify(await this.generateExtensionURLs())}) {
        if (WB_VERBOSE) wbLog('info', 'loadExtensionURL', extensionURL);
        vm.extensionManager.loadExtensionURL(extensionURL);
      }

      const wbReadFailures = [];
      const readFileOrFetch = async (path) => {
        if (window.EditorPreload && typeof window.EditorPreload.readFile === 'function') {
          try {
            const data = await window.EditorPreload.readFile(path);
            if (data instanceof Uint8Array) return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
            if (data instanceof ArrayBuffer) return data;
            return new Uint8Array(data).buffer;
          } catch (e) {
            const err = String(e && (e.stack || e));
            wbReadFailures.push({path, via: 'preload', error: err});
            if (WB_VERBOSE) wbLog('info', 'EditorPreload.readFile failed, falling back to fetch', {path, error: err});
          }
        }
        try {
          const res = await fetch(path, {cache: 'no-store'});
          if (!res.ok) throw new Error('Failed to load: ' + path + ' (' + res.status + ')');
          return await res.arrayBuffer();
        } catch (e) {
          const err = String(e && (e.stack || e));
          wbReadFailures.push({path, via: 'fetch', error: err});
          throw e;
        }
      };

      const tryRead = async (path) => {
        try {
          const ab = await readFileOrFetch(path);
          if (WB_VERBOSE) wbLog('info', 'read ok', {path, bytes: ab ? ab.byteLength : 0});
          return ab;
        } catch (e) {
          if (WB_VERBOSE) wbLog('info', 'read failed', {path, error: String(e && (e.stack || e))});
          return null;
        }
      };

      const wbResPack = (() => {
        let ready = false;
        let initPromise = null;
        let meta = null;
        let keyBytes = null;
        let saltBytes = null;

        const b64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        const seedFromName = (name) => {
          let seed = 0;
          for (let i = 0; i < name.length; i++) seed = (seed + name.charCodeAt(i)) & 0xff;
          return seed;
        };
        const xor = (bytes, key, seed) => {
          const out = new Uint8Array(bytes.length);
          for (let i = 0; i < bytes.length; i++) {
            out[i] = bytes[i] ^ key[(i + seed) % key.length] ^ seed;
          }
          return out;
        };
        const ensure = async () => {
          if (ready) return;
          if (initPromise) return initPromise;
          initPromise = (async () => {
            meta = window.__WB_RSP__ || null;
            if (!meta) {
              const ab = await tryRead('./wb-res/meta.json');
              if (ab) {
                try {
                  const text = new TextDecoder().decode(new Uint8Array(ab));
                  meta = JSON.parse(text);
                } catch (e) {
                  meta = null;
                }
              }
              if (!meta) {
                const ab2 = await tryRead('./assets/wb-res/meta.json');
                if (ab2) {
                  try {
                    const text2 = new TextDecoder().decode(new Uint8Array(ab2));
                    meta = JSON.parse(text2);
                  } catch (e) {
                    meta = null;
                  }
                }
              }
            }
            if (!meta || !meta.parts || !meta.order || !meta.salt || !meta.map) {
              meta = null;
              ready = true;
              return;
            }
            saltBytes = b64ToBytes(meta.salt);
            const partCount = meta.parts.length;
            const shards = [];
            for (let i = 0; i < partCount; i++) {
              const physical = meta.order[i];
              const shardObf = b64ToBytes(meta.parts[physical]);
              shards.push(xor(shardObf, saltBytes, i & 0xff));
            }
            const total = shards.reduce((a, b) => a + b.length, 0);
            const out = new Uint8Array(total);
            let off = 0;
            for (const s of shards) {
              out.set(s, off);
              off += s.length;
            }
            keyBytes = out;
            ready = true;
          })();
          return initPromise;
        };
        const getKeyCandidates = (p) => {
          let s = String(p || '');
          s = s.replace(/^[.][\\/]/, '');
          s = s.replace(/^[/\\\\]+/, '');
          const keys = [];
          keys.push(s);
          if (s === 'assets/project.json') keys.push('project.json');
          if (s === 'project.json') keys.push('assets/project.json');
          if (s.startsWith('assets/')) keys.push(s.slice('assets/'.length));
          const slash = s.lastIndexOf('/');
          if (slash !== -1) keys.push(s.slice(slash + 1));
          const seen = new Set();
          const out = [];
          for (const k of keys) {
            if (!k || seen.has(k)) continue;
            seen.add(k);
            out.push(k);
          }
          return out;
        };
        const loadPacked = async (path) => {
          await ensure();
          if (!meta || !keyBytes || !saltBytes) return null;
          const keys = getKeyCandidates(path);
          let packedPath = null;
          let key = null;
          for (const k of keys) {
            const p = meta.map[k];
            if (p) {
              packedPath = p;
              key = k;
              break;
            }
          }
          if (!packedPath || !key) return null;
          const ab = await tryRead('./' + packedPath);
          if (!ab) return null;
          const data = new Uint8Array(ab);
          const seed = (seedFromName(key) ^ saltBytes[0]) & 0xff;
          const plain = xor(data, keyBytes, seed);
          return plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength);
        };
        return {
          loadProject: () => loadPacked('./assets/project.json'),
          loadAsset: (assetId, dataFormat) => loadPacked('./assets/' + assetId + '.' + dataFormat)
        };
      })();

      const concatBuffers = (buffers) => {
        let total = 0;
        for (const b of buffers) total += b.byteLength;
        const out = new Uint8Array(total);
        let offset = 0;
        for (const b of buffers) {
          out.set(new Uint8Array(b), offset);
          offset += b.byteLength;
        }
        return out.buffer;
      };

      const aesGcmDecrypt = async (ciphertext, keyBytes, ivBytes) => {
        if (!(crypto && crypto.subtle && crypto.subtle.importKey && crypto.subtle.decrypt)) {
          throw new Error('WebCrypto is not available');
        }
        const key = await crypto.subtle.importKey('raw', keyBytes, {name: 'AES-GCM'}, false, ['decrypt']);
        return await crypto.subtle.decrypt({name: 'AES-GCM', iv: ivBytes}, key, ciphertext);
      };

      const computeShardOrder = async (keyBytes, ivBytes, label, parts) => {
        const labelBytes = new TextEncoder().encode(label);
        const combined = new Uint8Array(keyBytes.length + ivBytes.length + labelBytes.length);
        combined.set(keyBytes, 0);
        combined.set(ivBytes, keyBytes.length);
        combined.set(labelBytes, keyBytes.length + ivBytes.length);
        let seed = 0;
        if (crypto && crypto.subtle && crypto.subtle.digest) {
          const digest = await crypto.subtle.digest('SHA-256', combined);
          seed = new DataView(digest).getUint32(0, false) >>> 0;
        }
        const xorshift32 = (x) => {
          x ^= x << 13;
          x ^= x >>> 17;
          x ^= x << 5;
          return x >>> 0;
        };
        const order = Array.from({length: parts}, (_, i) => i);
        let s = seed >>> 0;
        for (let i = order.length - 1; i > 0; i--) {
          s = xorshift32(s);
          const j = s % (i + 1);
          const tmp = order[i];
          order[i] = order[j];
          order[j] = tmp;
        }
        return order;
      };

      const loadProjectZip = async (zipBuffer) => {
        const storage = scaffolding.storage;
        let zip = await Scaffolding.JSZip.loadAsync(zipBuffer);
        vm.runtime.on('PROJECT_LOADED', () => (zip = null));
        const findFileWithPath = (p) => {
          const direct = zip.file(p);
          if (direct) return {file: direct, path: p};
          const assetsDirect = zip.file('assets/' + p);
          if (assetsDirect) return {file: assetsDirect, path: 'assets/' + p};
          const escapeRegExp = (s) => String(s).replace(/[.*+?^{}$()|[\]\\]/g, '\\$&');
          const ep = escapeRegExp(p);
          const re1 = new RegExp('^([^/]*/)?' + ep + '$');
          const re2 = new RegExp('^([^/]*/)?assets/' + ep + '$');
          const m1 = zip.file(re1)[0] || null;
          if (m1) return {file: m1, path: m1.name};
          const m2 = zip.file(re2)[0] || null;
          if (m2) return {file: m2, path: m2.name};
          return null;
        };
        const xorDecrypt = (bytes, keyBytes, seed) => {
          const out = new Uint8Array(bytes.length);
          for (let i = 0; i < bytes.length; i++) {
            out[i] = bytes[i] ^ keyBytes[(i + seed) % keyBytes.length] ^ seed;
          }
          return out;
        };
        const seedFromName = (name) => {
          let seed = 0;
          for (let i = 0; i < name.length; i++) seed = (seed + name.charCodeAt(i)) & 0xff;
          return seed;
        };

        const manifestFile = zip.file('wb/manifest.json');
        let wbState = null;
        if (manifestFile) {
          const enc = window.__WB_ENC__;
          if (!enc || !enc.k) throw new Error('Missing encryption metadata');
          const base64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
          const outerKeyBytes = base64ToBytes(enc.k);
          const outerKey = await crypto.subtle.importKey('raw', outerKeyBytes, {name: 'AES-GCM'}, false, ['decrypt']);
          const unwrapKey = async (encObj) => {
            const iv = base64ToBytes(encObj.iv);
            const ct = base64ToBytes(encObj.data);
            const raw = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, outerKey, ct);
            return new Uint8Array(raw);
          };
          const manifest = JSON.parse(await manifestFile.async('string'));
          wbState = {
            hasManifest: true,
            manifest,
            projectIvBase: base64ToBytes(manifest.pj.ivBase),
            projectKeyBytes: await unwrapKey(manifest.pj.keyEnc),
            assetXorKey: await unwrapKey(manifest.assets.keyEnc)
          };
        }
        storage.addHelper({
          load: async (assetType, assetId, dataFormat) => {
            if (!zip) throw new Error('Zip is not loaded or has been closed');
            const p = assetId + '.' + dataFormat;
            const found = findFileWithPath(p);
            if (!found) return null;
            const data = await found.file.async('uint8array');
            const decrypted = wbState ? xorDecrypt(data, wbState.assetXorKey, seedFromName(found.path)) : data;
            return storage.createAsset(assetType, dataFormat, decrypted, assetId);
          }
        });
        if (wbState && wbState.hasManifest) {
          const manifest = wbState.manifest;
          const key = await crypto.subtle.importKey('raw', wbState.projectKeyBytes, {name: 'AES-GCM'}, false, ['decrypt']);
          const out = new Uint8Array(manifest.pj.total);
          let offset = 0;
          for (let i = 0; i < manifest.pj.chunkCount; i++) {
            const chunkFile = zip.file('wb/pj/' + i + '.bin');
            if (!chunkFile) throw new Error('Missing project chunk: ' + i);
            const chunkEncrypted = await chunkFile.async('arraybuffer');
            const iv = new Uint8Array(12);
            iv.set(wbState.projectIvBase, 0);
            new DataView(iv.buffer).setUint32(8, i, true);
            const chunkPlain = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, chunkEncrypted);
            const chunkBytes = new Uint8Array(chunkPlain);
            out.set(chunkBytes, offset);
            offset += chunkBytes.length;
          }
          return out.buffer;
        }
        const pjFound = findFileWithPath('project.json');
        if (!pjFound) throw new Error('project.json is not in zip');
        return await pjFound.file.async('arraybuffer');
      };

      const loadProjectData = async () => {
        const storage = scaffolding.storage;
        storage.onprogress = (total, loaded) => {
          setProgress(interpolate(${PROGRESS_LOADED_SCRIPTS}, 0.98, loaded / total));
        };

        const enc = window.__WB_ENC__;
        const ivB64 = (enc && enc.v === 2 && enc.project && enc.project.iv) ? enc.project.iv : (enc && enc.iv);
        const hasEnc = !!(enc && enc.k && ivB64);
        const base64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        if (WB_DEBUG) wbLog('info', 'loadProjectData start', {hasEnc});

        const tryLoadEncrypted = async () => {
          if (!hasEnc) return null;
          const parts = enc && enc.shred && Number(enc.shred.parts);
          const keyBytes = base64ToBytes(enc.k);
          const ivBytes = base64ToBytes(ivB64);
          if (WB_DEBUG) wbLog('info', 'tryLoadEncrypted', {parts: parts || 0});
          if (parts && parts > 1) {
            const order = await computeShardOrder(keyBytes, ivBytes, 'wb-project', parts);
            const buffers = [];
            for (let i = 0; i < parts; i++) {
              const physical = order[i];
              const b = await tryRead('./wb-project.' + physical + '.wb') || await tryRead('./assets/wb-project.' + physical + '.wb');
              if (!b) return null;
              buffers.push(b);
            }
            const ciphertext = concatBuffers(buffers);
            const plain = await aesGcmDecrypt(ciphertext, keyBytes, ivBytes);
            if (WB_DEBUG) wbLog('info', 'encrypted project decrypted', {bytes: plain ? plain.byteLength : 0});
            return await loadProjectZip(plain);
          }
          const b = await tryRead('./wb-project.bin') || await tryRead('./assets/wb-project.bin');
          if (!b) return null;
          const plain = await aesGcmDecrypt(b, keyBytes, ivBytes);
          if (WB_DEBUG) wbLog('info', 'encrypted project decrypted', {bytes: plain ? plain.byteLength : 0});
          return await loadProjectZip(plain);
        };

        const encrypted = await tryLoadEncrypted();
        if (encrypted) {
          if (WB_DEBUG) wbLog('info', 'project source', 'encrypted');
          return encrypted;
        }

        const zipBuffer = await tryRead('./project.zip') || await tryRead('./assets/project.zip');
        if (zipBuffer) {
          if (WB_DEBUG) wbLog('info', 'project source', 'project.zip');
          return await loadProjectZip(zipBuffer);
        }

        const packedProject = await wbResPack.loadProject();
        if (packedProject) {
          if (WB_DEBUG) wbLog('info', 'project source', 'wb-res');
          storage.addHelper({
            load: async (assetType, assetId, dataFormat) => {
              const ab = await wbResPack.loadAsset(assetId, dataFormat);
              if (!ab) return null;
              return storage.createAsset(assetType, dataFormat, new Uint8Array(ab), assetId);
            }
          });
          return packedProject;
        }

        storage.addWebStore(
          [
            storage.AssetType.ImageVector,
            storage.AssetType.ImageBitmap,
            storage.AssetType.Sound,
            storage.AssetType.Font
          ].filter(i => i),
          (asset) => new URL('./assets/' + asset.assetId + '.' + asset.dataFormat, location).href
        );
        const pj1 = await tryRead('./assets/project.json');
        if (pj1) return pj1;
        const pj2 = await tryRead('./project.json');
        if (pj2) return pj2;
        const debugChecks = {
          'wb-res/meta.json': !!(await tryRead('./wb-res/meta.json')),
          'assets/wb-res/meta.json': !!(await tryRead('./assets/wb-res/meta.json')),
          'project.zip': !!(await tryRead('./project.zip')),
          'assets/project.zip': !!(await tryRead('./assets/project.zip')),
          'wb-project.bin': !!(await tryRead('./wb-project.bin')),
          'assets/wb-project.bin': !!(await tryRead('./assets/wb-project.bin')),
          'assets/project.json': !!(await tryRead('./assets/project.json')),
          'project.json': !!(await tryRead('./project.json')),
        };
        const env = {
          href: location && location.href,
          protocol: location && location.protocol,
          origin: location && location.origin,
          secureCsp: WB_SECURE_CSP,
          hasEditorPreload: !!(window.EditorPreload && typeof window.EditorPreload.readFile === 'function')
        };
        const recentFailures = wbReadFailures.slice(-12);
        if (WB_DEBUG) wbLog('error', 'missing project.json', {env, debugChecks, recentFailures});
        throw new Error('Missing project.json; checked: ' + JSON.stringify(debugChecks) + '\\nEnv: ' + JSON.stringify(env) + '\\nRead failures: ' + JSON.stringify(recentFailures));
      };

      window.__wbStart = async () => {
        const projectData = await loadProjectData();
        await scaffolding.loadProject(projectData);
        setProgress(1);
        loadingScreen.hidden = true;
        scaffolding.start();
      };

      const start = async () => {
        if (${this.options.autoplay}) {
          await window.__wbStart();
          return;
        }
        loadingScreen.hidden = true;
        launchScreen.hidden = false;
        launchScreen.addEventListener('click', async () => {
          launchScreen.hidden = true;
          try { await window.__wbStart(); } catch (e) { handleError(e); }
        }, {once: true});
        launchScreen.focus();
      };

      setTimeout(() => start().catch(handleError), 0);
    } catch (e) {
      handleError(e);
    }
  `)}</script>

  ${this.options.custom.js ? `<script${scriptNonceAttr}>
    try { ${this.options.custom.js} } catch (e) { handleError(e); }
  </script>` : ''}
  ${this.options.wb && this.options.wb.encryptProject ? `<script${scriptNonceAttr}>window.__WB_ENC__ = ${JSON.stringify(this.wbEncryption ? Object.assign({}, this.wbEncryption, (this.options.wb && this.options.wb.shredWbResources) ? {shred: {parts: 32}} : null) : null)};</script>` : ''}
</body>
</html>
` : encodeBigString`<!DOCTYPE html>
<!-- Created with ${WEBSITE} -->
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <!-- We only include this to explicitly loosen the CSP of various packager environments. It does not provide any security. -->
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>${escapeXML(this.options.app.windowTitle)}</title>
  <style>
    body {
      color: ${this.options.appearance.foreground};
      font-family: sans-serif;
      overflow: hidden;
      margin: 0;
      padding: 0;
    }
    :root, body.is-fullscreen {
      background-color: ${this.options.appearance.background};
    }
    [hidden] {
      display: none !important;
    }
    h1 {
      font-weight: normal;
    }
    a {
      color: inherit;
      text-decoration: underline;
      cursor: pointer;
    }

    #app, #loading, #error, #launch {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
    }
    .screen {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      cursor: default;
      user-select: none;
      -webkit-user-select: none;
      background-color: ${this.options.appearance.background};
    }
    #launch {
      background-color: rgba(0, 0, 0, 0.7);
      cursor: pointer;
    }
    .green-flag {
      width: 80px;
      height: 80px;
      padding: 16px;
      border-radius: 100%;
      background: rgba(255, 255, 255, 0.75);
      border: 3px solid hsla(0, 100%, 100%, 1);
      display: flex;
      justify-content: center;
      align-items: center;
      box-sizing: border-box;
    }
    #loading {
      ${this.options.loadingScreen.image && this.options.loadingScreen.imageMode === 'stretch'
        ? `background-image: url(${await Adapter.readAsURL(this.options.loadingScreen.image, 'stretched loading screen')});
      background-repeat: no-repeat;
      background-size: contain;
      background-position: center;`
        : ''}
    }
    .progress-bar-outer {
      border: 1px solid currentColor;
      height: 10px;
      width: 200px;
      max-width: 200px;
    }
    .progress-bar-inner {
      height: 100%;
      width: 0;
      background-color: currentColor;
    }
    .loading-text, noscript {
      font-weight: normal;
      font-size: 36px;
      margin: 0 0 16px;
    }
    .loading-image {
      margin: 0 0 16px;
    }
    #error-message, #error-stack {
      font-family: monospace;
      max-width: 600px;
      white-space: pre-wrap;
      user-select: text;
      -webkit-user-select: text;
    }
    #error-stack {
      text-align: left;
      max-height: 200px;
      overflow: auto;
    }
    .control-button {
      width: 2rem;
      height: 2rem;
      padding: 0.375rem;
      margin-top: 0.5rem;
      margin-bottom: 0.5rem;
      user-select: none;
      -webkit-user-select: none;
      cursor: pointer;
      border: 0;
      border-radius: 4px;
    }
    .control-button-highlight:hover {
      background: ${this.options.appearance.accent}26;
    }
    .control-button-highlight.active {
      background: ${this.options.appearance.accent}59;
    }
    .fullscreen-button {
      background: white;
    }
    .standalone-fullscreen-button {
      position: absolute;
      top: 0;
      right: 0;
      background-color: rgba(0, 0, 0, 0.5);
      border-radius: 0 0 0 4px;
      padding: 4px;
      cursor: pointer;
    }
    .sc-canvas {
      cursor: ${await this.generateCursor()};
    }
    .sc-monitor-root[data-opcode^="data_"] .sc-monitor-value-color {
      background-color: ${this.options.monitors.variableColor};
    }
    .sc-monitor-row-value-outer {
      background-color: ${this.options.monitors.listColor};
    }
    .sc-monitor-row-value-editing .sc-monitor-row-value-outer {
      background-color: ${darken(this.options.monitors.listColor)};
    }
    ${this.options.custom.css}
  </style>
  <meta name="theme-color" content="${this.options.appearance.background}">
  ${await this.generateFavicon()}
</head>
<body>
  <div id="app"></div>

  <div id="launch" class="screen" hidden title="Click to start">
    <div class="green-flag">
      <svg viewBox="0 0 16.63 17.5" width="42" height="44">
        <defs><style>.cls-1,.cls-2{fill:#4cbf56;stroke:#45993d;stroke-linecap:round;stroke-linejoin:round;}.cls-2{stroke-width:1.5px;}</style></defs>
        <path class="cls-1" d="M.75,2A6.44,6.44,0,0,1,8.44,2h0a6.44,6.44,0,0,0,7.69,0V12.4a6.44,6.44,0,0,1-7.69,0h0a6.44,6.44,0,0,0-7.69,0"/>
        <line class="cls-2" x1="0.75" y1="16.75" x2="0.75" y2="0.75"/>
      </svg>
    </div>
  </div>

  <div id="loading" class="screen">
    <noscript>Enable JavaScript</noscript>
    ${this.options.loadingScreen.text ? `<h1 class="loading-text">${escapeXML(this.options.loadingScreen.text)}</h1>` : ''}
    ${this.options.loadingScreen.image && this.options.loadingScreen.imageMode === 'normal' ? `<div class="loading-image"><img src="${await Adapter.readAsURL(this.options.loadingScreen.image, 'loading-screen')}"></div>` : ''}
    ${this.options.loadingScreen.progressBar ? '<div class="progress-bar-outer"><div class="progress-bar-inner" id="loading-inner"></div></div>' : ''}
  </div>

  <div id="error" class="screen" hidden>
    <h1>Error</h1>
    <details>
      <summary id="error-message"></summary>
      <p id="error-stack"></p>
    </details>
  </div>

  ${this.options.target === 'html' ? `<script${scriptNonceAttr}>${this.script}</script>` : `<script src="script.js"${scriptNonceAttr}></script>`}
  <script${scriptNonceAttr}>${removeUnnecessaryEmptyLines(`
    const appElement = document.getElementById('app');
    const launchScreen = document.getElementById('launch');
    const loadingScreen = document.getElementById('loading');
    const loadingInner = document.getElementById('loading-inner');
    const errorScreen = document.getElementById('error');
    const errorScreenMessage = document.getElementById('error-message');
    const errorScreenStack = document.getElementById('error-stack');

    const handleError = (error) => {
      console.error(error);
      if (!errorScreen.hidden) return;
      errorScreen.hidden = false;
      errorScreenMessage.textContent = '' + error;
      let debug = error && error.stack || 'no stack';
      debug += '\\nUser agent: ' + navigator.userAgent;
      errorScreenStack.textContent = debug;
    };
    const setProgress = (progress) => {
      if (loadingInner) loadingInner.style.width = progress * 100 + '%';
    };
    const interpolate = (a, b, t) => a + t * (b - a);

    try {
      setProgress(${PROGRESS_LOADED_SCRIPTS});

      const scaffolding = new Scaffolding.Scaffolding();
      scaffolding.width = ${this.options.stageWidth};
      scaffolding.height = ${this.options.stageHeight};
      scaffolding.resizeMode = ${JSON.stringify(this.options.resizeMode)};
      scaffolding.editableLists = ${this.options.monitors.editableLists};
      scaffolding.usePackagedRuntime = ${this.options.packagedRuntime};
      scaffolding.setup();
      scaffolding.appendTo(appElement);

      const vm = scaffolding.vm;
      window.scaffolding = scaffolding;
      window.vm = scaffolding.vm;
      window.Scratch = {
        vm,
        renderer: vm.renderer,
        audioEngine: vm.runtime.audioEngine,
        bitmapAdapter: vm.runtime.v2BitmapAdapter,
        videoProvider: vm.runtime.ioDevices.video.provider
      };

      scaffolding.setUsername(${JSON.stringify(this.options.username)}.replace(/#/g, () => Math.floor(Math.random() * 10)));
      scaffolding.setAccentColor(${JSON.stringify(this.options.appearance.accent)});

      try {
        ${this.options.cloudVariables.mode === 'ws' ?
          `scaffolding.addCloudProvider(${this.makeWebSocketProvider()})` :
          this.options.cloudVariables.mode === 'local' ?
          `scaffolding.addCloudProvider(${this.makeLocalStorageProvider()})` :
          this.options.cloudVariables.mode === 'custom' ?
          this.makeCustomProvider() :
          ''
        };
      } catch (error) {
        console.error(error);
      }

      ${this.options.controls.greenFlag.enabled ? `
      const greenFlagButton = document.createElement('img');
      greenFlagButton.src = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16.63 17.5"><path d="M.75 2a6.44 6.44 0 017.69 0h0a6.44 6.44 0 007.69 0v10.4a6.44 6.44 0 01-7.69 0h0a6.44 6.44 0 00-7.69 0" fill="#4cbf56" stroke="#45993d" stroke-linecap="round" stroke-linejoin="round"/><path stroke-width="1.5" fill="#4cbf56" stroke="#45993d" stroke-linecap="round" stroke-linejoin="round" d="M.75 16.75v-16"/></svg>');
      greenFlagButton.className = 'control-button control-button-highlight green-flag-button';
      greenFlagButton.draggable = false;
      greenFlagButton.addEventListener('click', () => {
        scaffolding.greenFlag();
      });
      scaffolding.addEventListener('PROJECT_RUN_START', () => {
        greenFlagButton.classList.add('active');
      });
      scaffolding.addEventListener('PROJECT_RUN_STOP', () => {
        greenFlagButton.classList.remove('active');
      });
      scaffolding.addControlButton({
        element: greenFlagButton,
        where: 'top-left'
      });` : ''}

      ${this.options.controls.pause.enabled ? `
      const pauseButton = document.createElement('img');
      pauseButton.className = 'control-button control-button-highlight pause-button';
      pauseButton.draggable = false;
      let isPaused = false;
      pauseButton.addEventListener('click', () => {
        vm.setPaused(!isPaused);
      });
      const updatePause = () => {
        if (isPaused) {
          pauseButton.src = 'data:image/svg+xml,' + encodeURIComponent('<svg width="16" height="16" viewBox="0 0 4.2333332 4.2333335" xmlns="http://www.w3.org/2000/svg"><path d="m3.95163484 2.02835365-1.66643921.9621191-1.66643913.96211911V.10411543l1.66643922.9621191z" fill="#ffae00"/></svg>');
        } else {
          pauseButton.src = 'data:image/svg+xml,' + encodeURIComponent('<svg width="16" height="16" viewBox="0 0 4.2333332 4.2333335" xmlns="http://www.w3.org/2000/svg"><g fill="#ffae00"><path d="M.389.19239126h1.2631972v3.8485508H.389zM2.5810001.19239126h1.2631972v3.8485508H2.5810001z"/></g></svg>');
        }
      };
      vm.runtime.on('RUNTIME_PAUSED', () => {
        isPaused = true;
        updatePause();
      });
      vm.runtime.on('RUNTIME_UNPAUSED', () => {
        isPaused = false;
        updatePause();
      });
      updatePause();
      scaffolding.addControlButton({
        element: pauseButton,
        where: 'top-left'
      });` : ''}

      ${this.options.controls.stopAll.enabled ? `
      const stopAllButton = document.createElement('img');
      stopAllButton.src = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14"><path fill="#ec5959" stroke="#b84848" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" d="M4.3.5h5.4l3.8 3.8v5.4l-3.8 3.8H4.3L.5 9.7V4.3z"/></svg>');
      stopAllButton.className = 'control-button control-button-highlight stop-all-button';
      stopAllButton.draggable = false;
      stopAllButton.addEventListener('click', () => {
        scaffolding.stopAll();
      });
      scaffolding.addControlButton({
        element: stopAllButton,
        where: 'top-left'
      });` : ''}

      ${this.options.controls.fullscreen.enabled ? `
      if (document.fullscreenEnabled || document.webkitFullscreenEnabled) {
        let isFullScreen = !!(document.fullscreenElement || document.webkitFullscreenElement);
        const fullscreenButton = document.createElement('img');
        fullscreenButton.draggable = false;
        fullscreenButton.className = 'control-button fullscreen-button';
        fullscreenButton.addEventListener('click', () => {
          if (isFullScreen) {
            if (document.exitFullscreen) {
              document.exitFullscreen();
            } else if (document.webkitExitFullscreen) {
              document.webkitExitFullscreen();
            }
          } else {
            if (document.body.requestFullscreen) {
              document.body.requestFullscreen();
            } else if (document.body.webkitRequestFullscreen) {
              document.body.webkitRequestFullscreen();
            }
          }
        });
        const otherControlsExist = ${this.options.controls.greenFlag.enabled || this.options.controls.stopAll.enabled};
        const fillColor = otherControlsExist ? '#575E75' : '${this.options.appearance.foreground}';
        const updateFullScreen = () => {
          isFullScreen = !!(document.fullscreenElement || document.webkitFullscreenElement);
          document.body.classList.toggle('is-fullscreen', isFullScreen);
          if (isFullScreen) {
            fullscreenButton.src = 'data:image/svg+xml,' + encodeURIComponent('<svg width="20" height="20" xmlns="http://www.w3.org/2000/svg"><g fill="' + fillColor + '" fill-rule="evenodd"><path d="M12.662 3.65l.89.891 3.133-2.374a.815.815 0 011.15.165.819.819 0 010 .986L15.467 6.46l.867.871c.25.25.072.664-.269.664L12.388 8A.397.397 0 0112 7.611V3.92c0-.341.418-.514.662-.27M7.338 16.35l-.89-.89-3.133 2.374a.817.817 0 01-1.15-.166.819.819 0 010-.985l2.37-3.143-.87-.871a.387.387 0 01.27-.664L7.612 12a.397.397 0 01.388.389v3.692a.387.387 0 01-.662.27M7.338 3.65l-.89.891-3.133-2.374a.815.815 0 00-1.15.165.819.819 0 000 .986l2.37 3.142-.87.871a.387.387 0 00.27.664L7.612 8A.397.397 0 008 7.611V3.92a.387.387 0 00-.662-.27M12.662 16.35l.89-.89 3.133 2.374a.817.817 0 001.15-.166.819.819 0 000-.985l-2.368-3.143.867-.871a.387.387 0 00-.269-.664L12.388 12a.397.397 0 00-.388.389v3.692c0 .342.418.514.662.27"/></g></svg>');
          } else {
            fullscreenButton.src = 'data:image/svg+xml,' + encodeURIComponent('<svg width="20" height="20" xmlns="http://www.w3.org/2000/svg"><g fill="' + fillColor + '" fill-rule="evenodd"><path d="M16.338 7.35l-.89-.891-3.133 2.374a.815.815 0 01-1.15-.165.819.819 0 010-.986l2.368-3.142-.867-.871a.387.387 0 01.269-.664L16.612 3a.397.397 0 01.388.389V7.08a.387.387 0 01-.662.27M3.662 12.65l.89.89 3.133-2.374a.817.817 0 011.15.166.819.819 0 010 .985l-2.37 3.143.87.871c.248.25.071.664-.27.664L3.388 17A.397.397 0 013 16.611V12.92c0-.342.418-.514.662-.27M3.662 7.35l.89-.891 3.133 2.374a.815.815 0 001.15-.165.819.819 0 000-.986L6.465 4.54l.87-.871a.387.387 0 00-.27-.664L3.388 3A.397.397 0 003 3.389V7.08c0 .341.418.514.662.27M16.338 12.65l-.89.89-3.133-2.374a.817.817 0 00-1.15.166.819.819 0 000 .985l2.368 3.143-.867.871a.387.387 0 00.269.664l3.677.005a.397.397 0 00.388-.389V12.92a.387.387 0 00-.662-.27"/></g></svg>');
          }
        };
        updateFullScreen();
        document.addEventListener('fullscreenchange', updateFullScreen);
        document.addEventListener('webkitfullscreenchange', updateFullScreen);
        if (otherControlsExist) {
          fullscreenButton.className = 'control-button fullscreen-button';
          scaffolding.addControlButton({
            element: fullscreenButton,
            where: 'top-right'
          });
        } else {
          fullscreenButton.className = 'standalone-fullscreen-button';
          document.body.appendChild(fullscreenButton);
        }
      }` : ''}

      vm.setTurboMode(${this.options.turbo});
      if (vm.setInterpolation) vm.setInterpolation(${this.options.interpolation});
      if (vm.setFramerate) vm.setFramerate(${this.options.framerate});
      if (vm.renderer.setUseHighQualityRender) vm.renderer.setUseHighQualityRender(${this.options.highQualityPen});
      if (vm.setRuntimeOptions) vm.setRuntimeOptions({
        fencing: ${this.options.fencing},
        miscLimits: ${this.options.miscLimits},
        maxClones: ${this.options.maxClones},
      });
      if (vm.setCompilerOptions) vm.setCompilerOptions({
        enabled: ${this.options.compiler.enabled},
        warpTimer: ${this.options.compiler.warpTimer}
      });
      if (vm.renderer.setMaxTextureDimension) vm.renderer.setMaxTextureDimension(${this.options.maxTextureDimension});

      // enforcePrivacy threat model only makes sense in the editor
      if (vm.runtime.setEnforcePrivacy) vm.runtime.setEnforcePrivacy(false);

      if (typeof ScaffoldingAddons !== 'undefined') {
        ScaffoldingAddons.run(scaffolding, ${JSON.stringify(this.getAddonOptions())});
      }

      scaffolding.setExtensionSecurityManager({
        getSandboxMode: () => 'unsandboxed',
        canLoadExtensionFromProject: () => true
      });
      for (const extension of ${JSON.stringify(await this.generateExtensionURLs())}) {
        vm.extensionManager.loadExtensionURL(extension);
      }

      ${this.options.closeWhenStopped ? `
      vm.runtime.on('PROJECT_RUN_STOP', () => {
        if (!vm.isPaused || !vm.isPaused()) {
          window.close();
        }
      });` : ''}

      ${this.options.target.startsWith('nwjs-') ? `
      if (typeof nw !== 'undefined') {
        const win = nw.Window.get();
        win.on('new-win-policy', (frame, url, policy) => {
          policy.ignore();
          nw.Shell.openExternal(url);
        });
        win.on('navigation', (frame, url, policy) => {
          policy.ignore();
          nw.Shell.openExternal(url);
        });
        document.addEventListener('keydown', (e) => {
          if (e.key === 'Escape' && document.fullscreenElement) {
            document.exitFullscreen();
          }
        });
      }` : ''}
    } catch (e) {
      handleError(e);
    }
  `)}</script>
  ${this.options.custom.js ? `<script${scriptNonceAttr}>
    try {
      ${this.options.custom.js}
    } catch (e) {
      handleError(e);
    }
  </script>` : ''}
  ${await this.generateGetProjectData()}
  <script${scriptNonceAttr}>
    const run = async () => {
      const projectData = await getProjectData();
      await scaffolding.loadProject(projectData);
      setProgress(1);
      loadingScreen.hidden = true;
      if (${this.options.autoplay}) {
        scaffolding.start();
      } else {
        launchScreen.hidden = false;
        launchScreen.addEventListener('click', () => {
          launchScreen.hidden = true;
          scaffolding.start();
        });
        launchScreen.focus();
      }
    };
    run().catch(handleError);
  </script>
</body>
</html>
`;
    this.wbAppIntegrity = null;
    let outputHTML = html;
    let wbAppBin = null;
    let wbAppShards = null;
    const encryptRuntime = !!(encryptProject && this.options.target.startsWith('electron-') && this.options.wb && this.options.wb.encryptRuntime);
    const shredWbResources = !!(encryptProject && this.options.wb && this.options.wb.shredWbResources);
    if (encryptRuntime) {
      const htmlText = new TextDecoder().decode(html);
      const inlineScripts = [];
      const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/g;
      let m;
      while ((m = scriptRegex.exec(htmlText)) !== null) {
        inlineScripts.push(m[1] || '');
      }

      const payloadJS = [this.script, ...inlineScripts].join('\n;\n');
      const keyBytes = Uint8Array.from(atob(this.wbEncryption.k), c => c.charCodeAt(0));
      const ivBytes = randomBytes(12);
      const payloadBytes = new TextEncoder().encode(payloadJS);
      const ciphertext = await aesGcmEncrypt(payloadBytes, keyBytes, ivBytes);
      wbAppBin = new Uint8Array(ciphertext);
      wbAppShards = (encryptRuntime && shredWbResources) ? (() => {
        const seed = shardSeed(keyBytes, ivBytes, 'wb-app');
        const order = shuffledIndices(32, seed);
        const logical = splitIntoShards(wbAppBin, 32);
        const out = [];
        for (let i = 0; i < 32; i++) {
          const physical = order[i];
          out.push({physical, data: logical[i]});
        }
        return out;
      })() : null;
      this.wbAppIntegrity = {
        file: (encryptRuntime && shredWbResources) ? `wb-app.${wbAppShards[0].physical}.wb` : 'wb-app.bin',
        sha256: (encryptRuntime && shredWbResources) ? sha256HexOfBytes(wbAppShards[0].data) : sha256HexOfBytes(wbAppBin)
      };

      let shell = htmlText
        .replace(/<script[^>]*src="script\.js"[^>]*><\/script>/g, '')
        .replace(/<script[^>]*>[\s\S]*?<\/script>/g, '');

      const bootstrapMeta = `window.__WB_APP__ = ${JSON.stringify({k: this.wbEncryption.k, iv: bytesToBase64(ivBytes), shred: (encryptRuntime && shredWbResources) ? {parts: 32} : null, n: (useSecureCsp && cspNonce) ? cspNonce : null})};`;
      let bootstrap = `(async()=>{try{const app=document.getElementById('app');const loading=document.getElementById('loading');const errorScreen=document.getElementById('error');const errorMessage=document.getElementById('error-message');const errorStack=document.getElementById('error-stack');const handle=(e)=>{try{console.error(e);}catch(_){ }if(errorScreen){errorScreen.hidden=false;if(errorMessage)errorMessage.textContent=''+e;if(errorStack)errorStack.textContent=(e&&e.stack?e.stack:'no stack')+'\\nUser agent: '+navigator.userAgent;}else{alert(''+e);}};const meta=window.__WB_APP__;if(!meta||!meta.k||!meta.iv)throw new Error('Missing app metadata');const b64ToBytes=(b64)=>Uint8Array.from(atob(b64),c=>c.charCodeAt(0));const keyBytes=b64ToBytes(meta.k);const ivBytes=b64ToBytes(meta.iv);const key=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']);const load=(p)=>{if(window.EditorPreload&&typeof window.EditorPreload.readFile==='function'){return Promise.resolve(window.EditorPreload.readFile(p)).then(x=>x instanceof Uint8Array?x:new Uint8Array(x));}return new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();xhr.onload=()=>resolve(new Uint8Array(xhr.response));xhr.onerror=()=>reject(new Error('Failed to load app payload'));xhr.responseType='arraybuffer';xhr.open('GET',p);xhr.send();});};let data=null;const parts=meta&&meta.shred&&Number(meta.shred.parts);if(parts&&parts>1){const labelBytes=new TextEncoder().encode('wb-app');const combined=new Uint8Array(keyBytes.length+ivBytes.length+labelBytes.length);combined.set(keyBytes,0);combined.set(ivBytes,keyBytes.length);combined.set(labelBytes,keyBytes.length+ivBytes.length);let seed=0;if(crypto&&crypto.subtle&&crypto.subtle.digest){const digest=await crypto.subtle.digest('SHA-256',combined);seed=new DataView(digest).getUint32(0,false)>>>0;}const xorshift32=(x)=>{x^=x<<13;x^=x>>>17;x^=x<<5;return x>>>0;};const order=Array.from({length:parts},(_,i)=>i);let s=seed>>>0;for(let i=order.length-1;i>0;i--){s=xorshift32(s);const j=s%(i+1);const t=order[i];order[i]=order[j];order[j]=t;}const bufs=[];let total=0;for(let i=0;i<parts;i++){const physical=order[i];const b=await load('./wb-app.'+physical+'.wb');bufs.push(b);total+=b.length;}const out=new Uint8Array(total);let o=0;for(const b of bufs){out.set(b,o);o+=b.length;}data=out.buffer;}else{const b=await load('./wb-app.bin');data=b.buffer;}const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:ivBytes},key,data);const code=new TextDecoder('utf-8').decode(new Uint8Array(plain));const s=document.createElement('script');try{if(meta&&meta.n)s.setAttribute('nonce',meta.n);}catch(_){ }s.textContent=code;(document.head||document.documentElement).appendChild(s);}catch(e){handle(e);}})();`;
      if (this.options.wb && this.options.wb.obfuscateUnpack) {
        bootstrap = JavaScriptObfuscator.obfuscate(bootstrap, {
          compact: true,
          controlFlowFlattening: true,
          controlFlowFlatteningThreshold: 0.75,
          deadCodeInjection: true,
          deadCodeInjectionThreshold: 0.2,
          stringArray: true,
          stringArrayEncoding: ['base64'],
          stringArrayThreshold: 0.75,
          renameGlobals: false
        }).getObfuscatedCode();
      }

      const injected = `<script${scriptNonceAttr}>${bootstrapMeta}\n${bootstrap}</script>`;
      outputHTML = new TextEncoder().encode(shell.replace('</body>', `${injected}\n</body>`));
    }
    this.ensureNotAborted();

    if (this.options.target !== 'html') {
      let zip;
      if (!encryptProject && this.project.type === 'sb3' && this.options.target !== 'zip-one-asset') {
        zip = await (await getJSZip()).loadAsync(this.project.arrayBuffer);
        for (const file of Object.keys(zip.files)) {
          zip.files[`assets/${file}`] = zip.files[file];
          delete zip.files[file];
        }
      } else {
        zip = new (await getJSZip());
        if (encryptProject) {
          const keyBytes = Uint8Array.from(atob(this.wbEncryption.k), c => c.charCodeAt(0));
          const ivB64 = (this.wbEncryption && this.wbEncryption.v === 2 && this.wbEncryption.project && this.wbEncryption.project.iv) ? this.wbEncryption.project.iv : this.wbEncryption.iv;
          const ivBytes = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
          const ciphertext = await aesGcmEncrypt(this.project.arrayBuffer, keyBytes, ivBytes);
          const projectBin = new Uint8Array(ciphertext);
          if (shredWbResources) {
            const seed = shardSeed(keyBytes, ivBytes, 'wb-project');
            const order = shuffledIndices(32, seed);
            const logical = splitIntoShards(projectBin, 32);
            for (let i = 0; i < 32; i++) {
              const physical = order[i];
              zip.file(`wb-project.${physical}.wb`, logical[i]);
            }
          } else {
            zip.file('wb-project.bin', projectBin);
          }
        } else {
          zip.file('project.zip', this.project.arrayBuffer);
        }
      }
      try {
        const extFiles = this._embeddedExtensionFiles && typeof this._embeddedExtensionFiles === 'object' ? this._embeddedExtensionFiles : null;
        if (extFiles) {
          for (const [p, code] of Object.entries(extFiles)) {
            if (typeof p === 'string' && p && typeof code === 'string') {
              zip.file(p, code);
            }
          }
        }
      } catch (e) {}
      zip.file('index.html', outputHTML);
      if (encryptRuntime) {
        if (shredWbResources) {
          for (const shard of wbAppShards) {
            zip.file(`wb-app.${shard.physical}.wb`, shard.data);
          }
        } else {
          zip.file('wb-app.bin', wbAppBin);
        }
      } else {
        zip.file('script.js', this.script);
      }

      if (packResourcesXor && !encryptProject) {
        try {
          const keyBytes = randomBytes(32);
          const saltBytes = randomBytes(16);
          const meta = buildXorResourcePackMeta(this.options.projectId, keyBytes, saltBytes);
          const paths = Object.keys(zip.files || {}).filter((p) => {
            const f = zip.files[p];
            if (!f || f.dir) return false;
            if (p === 'index.html') return false;
            if (p.startsWith('wb-res/')) return false;
            if (p.startsWith('assets/')) return true;
            if (p === 'project.json' || p.endsWith('/project.json')) return true;
            return false;
          });
          for (const originalPath of paths) {
            const f = zip.file(originalPath);
            if (!f) continue;
            const key = normalizePackedResourceKey(originalPath);
            const packedPath = `wb-res/${bytesToHex(randomBytes(8))}.wb`;
            const plain = await f.async('uint8array');
            const seed = (fileSeed(key) ^ saltBytes[0]) & 0xff;
            const enc = xorCrypt(plain, keyBytes, seed);
            meta.map[key] = packedPath;
            zip.file(packedPath, enc);
            zip.remove(originalPath);
          }
          zip.file('wb-res/meta.json', JSON.stringify(meta));
          const indexFile = zip.file('index.html');
          if (indexFile) {
            const htmlBytes = await indexFile.async('uint8array');
            zip.file('index.html', injectWbResMetaIntoHtml(htmlBytes, meta, this._wbCspNonce));
          }
        } catch (e) {
          console.warn(e);
        }
      }

      if (this.options.target.startsWith('nwjs-')) {
        zip = await this.addNwJS(zip);
      } else if (this.options.target.startsWith('electron-')) {
        zip = await this.addElectron(zip);
      } else if (this.options.target === 'webview-mac') {
        zip = await this.addWebViewMac(zip);
      }

      this.ensureNotAborted();
      return {
        data: await zip.generateAsync({
          type: 'uint8array',
          compression: 'DEFLATE',
          // Use UNIX permissions so that executable bits are properly set for macOS and Linux
          platform: 'UNIX'
        }, (meta) => {
          this.dispatchEvent(new CustomEvent('zip-progress', {
            detail: {
              progress: meta.percent / 100
            }
          }));
        }),
        type: 'application/zip',
        filename: this.generateFilename('zip')
      };
    }
    return {
      data: html,
      type: 'text/html',
      filename: this.generateFilename('html')
    };
  }
}

Packager.getDefaultPackageNameFromFileName = (title) => {
  // Note: Changing this logic is very dangerous because changing the defaults will cause already packaged projects
  // to loose any data when they are updated.
  title = title.split('.')[0];
  title = title.replace(/[^\-a-z ]/gi, '');
  title = title.trim();
  title = title.replace(/ /g, '-');
  return title.toLowerCase() || 'packaged-project';
};

Packager.getWindowTitleFromFileName = (title) => {
  const split = title.split('.');
  if (split.length > 1) {
    split.pop();
  }
  title = split.join('.').trim();
  return title || 'Packaged Project';
};

Packager.usesUnsafeOptions = (options) => {
  const defaultOptions = Packager.DEFAULT_OPTIONS();
  const getUnsafeOptions = (options) => [
    options.custom,
    options.extensions,
    options.cloudVariables.unsafeCloudBehaviors
  ];
  return JSON.stringify(getUnsafeOptions(defaultOptions)) !== JSON.stringify(getUnsafeOptions(options));
};

Packager.DEFAULT_OPTIONS = () => ({
  turbo: false,
  interpolation: false,
  framerate: 30,
  highQualityPen: false,
  maxClones: 300,
  fencing: true,
  miscLimits: true,
  stageWidth: 480,
  stageHeight: 360,
  resizeMode: 'preserve-ratio',
  autoplay: false,
  username: 'player####',
  closeWhenStopped: false,
  projectId: '',
  custom: {
    css: '',
    js: ''
  },
  appearance: {
    background: '#000000',
    foreground: '#ffffff',
    accent: ACCENT_COLOR
  },
  loadingScreen: {
    progressBar: true,
    text: '',
    imageMode: 'normal',
    image: null
  },
  controls: {
    greenFlag: {
      enabled: false,
    },
    stopAll: {
      enabled: false,
    },
    fullscreen: {
      enabled: false
    },
    pause: {
      enabled: false
    }
  },
  monitors: {
    editableLists: false,
    variableColor: '#ff8c1a',
    listColor: '#fc662c'
  },
  compiler: {
    enabled: true,
    warpTimer: false
  },
  packagedRuntime: true,
  target: 'html',
  app: {
    icon: null,
    writeWindowsExeIcon: true,
    exportWindowsIco: false,
    writeMacElectronIcns: true,
    exportLinuxDesktopFile: false,
    packageName: Packager.getDefaultPackageNameFromFileName(''),
    windowTitle: Packager.getWindowTitleFromFileName(''),
    windowMode: 'window',
    version: '1.0.0',
    escapeBehavior: 'unfullscreen-only',
    windowControls: 'default',
    backgroundThrottling: false
  },
  chunks: {
    gamepad: false,
    pointerlock: false,
  },
  cloudVariables: {
    mode: 'ws',
    cloudHost: 'wss://clouddata.turbowarp.org',
    custom: {},
    specialCloudBehaviors: false,
    unsafeCloudBehaviors: false,
  },
  cursor: {
    type: 'auto',
    custom: null,
    center: {
      x: 0,
      y: 0
    }
  },
  steamworks: {
    // 480 is Spacewar, the Steamworks demo game
    appId: '480',
    // 'ignore' (no alert), 'warning' (alert and continue), or 'error' (alert and exit)
    onError: 'warning'
  },
  extensions: [],
  bakeExtensions: true,
  maxTextureDimension: 2048,
  wb: {
    obfuscateNames: false,
    encryptProject: false,
    encryptRuntime: false,
    opcodeObfuscation: false,
    protectElectron: false,
    splitElectronEntry: false,
    shredWbResources: false,
    cleanHtmlTemplate: false,
    extensionLoadStrategy: 'auto',
    debugLog: false,
    debugLogVerbose: false,
    enablePluginDir: false,
    pluginDir: 'plugins',
    obfuscateUnpack: true,
    disableDevtools: true,
    verifyScriptHash: true,
    verifyIndexHash: true,
    secureCsp: false,
    packResourcesXor: false,
    integrity: {
      enabled: false,
      required: false,
      kid: '',
      publicKeys: {},
      manifestName: 'wb-integrity.json',
      signatureName: 'wb-integrity.sig'
    }
  }
});

Packager._test = {
  buildXorResourcePackMeta,
  normalizePackedResourceKey,
  injectWbResMetaIntoHtml,
  xorCrypt,
  fileSeed
};

export default Packager;
