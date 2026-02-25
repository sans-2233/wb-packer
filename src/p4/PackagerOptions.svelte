<script>
  import {onDestroy, onMount} from 'svelte';
  import {_} from '../locales/';
  import {slide, fade} from 'svelte/transition';
  import Section from './Section.svelte';
  import Button from '../p4/Button.svelte';
  import ImageInput from './ImageInput.svelte';
  import CustomExtensions from '../p4/CustomExtensions.svelte';
  import LearnMore from './LearnMore.svelte';
  import ColorPicker from './ColorPicker.svelte';
  import Downloads from './Downloads.svelte';
  import writablePersistentStore from './persistent-store';
  import fileStore from './file-store';
  import {progress, currentTask, error} from './stores';
  import Preview from './preview';
  import deepClone from './deep-clone';
  import Packager from '../packager/web/export';
  import Task from './task';
  import downloadURL from './download-url';
  import {recursivelySerializeBlobs, recursivelyDeserializeBlobs} from './blob-serializer';
  import {readAsText} from '../common/readers';
  import merge from './merge';
  import DropArea from './DropArea.svelte';
  import {APP_NAME} from '../packager/brand';

  export let projectData;
  export let title;

  // JSON can't easily parse Infinity, so we'll just store large numbers instead
  const ALMOST_INFINITY = 9999999999;

  const cloudVariables = projectData.project.analysis.stageVariables
    .filter(i => i.isCloud)
    .map(i => i.name);

  const defaultOptions = Packager.DEFAULT_OPTIONS();
  defaultOptions.projectId = projectData.projectId || `p4-${projectData.uniqueId}`;
  for (const variable of cloudVariables) {
    defaultOptions.cloudVariables.custom[variable] = 'ws';
  }
  defaultOptions.app.packageName = Packager.getDefaultPackageNameFromFileName(projectData.title);
  defaultOptions.app.windowTitle = Packager.getWindowTitleFromFileName(projectData.title);
  defaultOptions.extensions = projectData.project.analysis.extensions;
  const options = writablePersistentStore(`PackagerOptions.${projectData.uniqueId}`, defaultOptions);

  // Compatibility with https://github.com/TurboWarp/packager/commit/f66199abd1c896c11aa69247275a1594fdfc95b8
  $options.extensions = $options.extensions.map(i => {
    if (typeof i === 'object' && i) return i.url || '';
    return i;
  });

  $: if ($options && typeof $options.target === 'string') {
    const t = $options.target;
    if (t !== 'html' && t !== 'node-cli' && !t.startsWith('electron-')) {
      $options.target = 'html';
    }
  }

  $: if (!$options.wb) {
    $options.wb = deepClone(defaultOptions.wb);
  }
  $: if (!$options.wb.codeSigning) {
    $options.wb.codeSigning = deepClone(defaultOptions.wb.codeSigning);
  }

  const hasMagicComment = (magic) => projectData.project.analysis.stageComments.find(
    (text) => text.split('\n').find((line) => line.endsWith(magic))
  );
  const hasSettingsStoredInProject = hasMagicComment(' // _twconfig_');

  let result = null;
  let previewer = null;
  let showPlugins = false;
  let pluginDir = '';
  let pluginEntries = [];
  let pluginDebug = [];
  let lastPackagerInfo = null;
  let signingTools = null;
  let signingToolsError = '';
  const resetResult = () => {
    previewer = null;
    if (result) {
      URL.revokeObjectURL(result.url);
    }
    result = null;
  }
  $: if (previewer) {
    previewer.setProgress($progress.progress, $progress.text);
  }
  $: $options, resetResult(), currentTask.abort();

  const icon = fileStore.writableFileStore(`PackagerOptions.icon.${projectData.uniqueId}`);
  $: $options.app.icon = $icon;

  const customCursorIcon = fileStore.writableFileStore(`PackagerOptions.customCursorIcon.${projectData.uniqueId}`);
  $: $options.cursor.custom = $customCursorIcon;

  const loadingScreenImage = fileStore.writableFileStore(`PackagerOptions.loadingScreenImage.${projectData.uniqueId}`);
  $: $options.loadingScreen.image = $loadingScreenImage;

  $: title = $options.app.windowTitle;

  const setOptions = (newOptions) => {
    $options = newOptions;
    $icon = $options.app.icon;
    $customCursorIcon = $options.cursor.custom;
    $loadingScreenImage = $options.loadingScreen.image;
  };

  const otherEnvironmentsInitiallyOpen = ![
    'html',
    'node-cli',
    'electron-win64',
    'electron-mac',
    'electron-linux64',
    'electron-win32'
  ].includes($options.target);

  const advancedOptionsInitiallyOpen = (
    $options.compiler.enabled !== defaultOptions.compiler.enabled ||
    $options.compiler.warpTimer !== defaultOptions.compiler.warpTimer ||
    $options.extensions.length !== 0 ||
    $options.bakeExtensions !== defaultOptions.bakeExtensions ||
    $options.custom.css !== '' ||
    $options.custom.js !== '' ||
    $options.projectId !== defaultOptions.projectId ||
    $options.packagedRuntime !== defaultOptions.packagedRuntime ||
    $options.maxTextureDimension !== defaultOptions.maxTextureDimension
  );

  const automaticallyCenterCursor = () => {
    const icon = $customCursorIcon;
    const url = URL.createObjectURL(icon)
    const image = new Image();
    const cleanup = () => {
      image.onerror = null;
      image.onload = null;
      URL.revokeObjectURL(url);
    };
    image.onload = () => {
      $options.cursor.center.x = Math.round(image.width / 2);
      $options.cursor.center.y = Math.round(image.height / 2);
      cleanup();
    };
    image.onerror = () => {
      cleanup();
      $error = new Error('Image could not be loaded');
      throw $error;
    };
    image.src = url;
  };

  const runPackager = async (task, options) => {
    const packager = new Packager();
    packager.options = options;
    packager.project = projectData.project;

    task.addEventListener('abort', () => {
      packager.abort();
    });

    task.setProgressText($_('progress.loadingScripts'));

    packager.addEventListener('fetch-extensions', ({detail}) => {
      task.setProgressText($_('progress.downloadingExtensions'));
      task.setProgress(detail.progress);
    });
    packager.addEventListener('large-asset-fetch', ({detail}) => {
      let thing;
      if (detail.asset.startsWith('electron-')) {
        thing = 'Electron';
      } else if (detail.asset === 'steamworks.js') {
        thing = 'Steamworks.js';
      }
      if (thing) {
        task.setProgressText($_('progress.loadingLargeAsset').replace('{thing}', thing));
      }
      task.setProgress(detail.progress);
    });
    packager.addEventListener('zip-progress', ({detail}) => {
      task.setProgressText($_('progress.compressingProject'));
      task.setProgress(detail.progress);
    });
    packager.addEventListener('wb-packager-info', ({detail}) => {
      lastPackagerInfo = detail;
    });

    const result = await packager.package();
    result.blob = new Blob([result.data], {
      type: result.type
    });
    result.url = URL.createObjectURL(result.blob);
    return result;
  };

  const pack = async () => {
    resetResult();
    let optionsClone = deepClone($options);
    while (true) {
      const task = new Task();
      try {
        result = await task.do(runPackager(task, optionsClone));
        downloadURL(result.filename, result.url);
        return;
      } catch (e) {
        if (e && e.name === 'WBCustomExtensionsError' && Array.isArray(e.customExtensions)) {
          const items = e.customExtensions
            .map(i => i && typeof i.id === 'string' && typeof i.url === 'string' ? `${i.id}: ${i.url}` : null)
            .filter(i => i);
          const text = items.length ? items.join('\n') : '(unknown)';
          const ok = confirm(
            `检测到项目包含自定义拓展（权限极高，可能联网/读写/执行任意 JS）。\n\n${text}\n\n确定：允许继续打包并在运行时自动加载这些自定义拓展。\n取消：继续打包但移除这些自定义拓展（作品功能可能缺失）。`
          );
          optionsClone.wb.allowCustomExtensionsFromProject = ok;
          optionsClone.wb.stripCustomExtensionsFromProject = !ok;
          if (!Array.isArray(optionsClone.wb.unsandboxedExtensionUrlKeywords)) {
            optionsClone.wb.unsandboxedExtensionUrlKeywords = [];
          }
          continue;
        }
        throw e;
      } finally {
        task.done();
      }
    }
  };

  const preview = async () => {
    resetResult();
    previewer = new Preview();
    const task = new Task();
    const optionsClone = deepClone($options);
    optionsClone.target = 'html';
    try {
      result = await task.do(runPackager(task, optionsClone));
      task.done();
      previewer.setContent(result.blob);
    } catch (e) {
      previewer.close();
    }
  };

  const resetOptions = (properties) => {
    for (const key of properties) {
      let current = $options;
      let defaults = defaultOptions;
      const parts = key.split('.');
      const lastPart = parts.pop();
      for (const i of parts) {
        current = current[i];
        defaults = defaults[i];
      }
      current[lastPart] = deepClone(defaults[lastPart]);
    }
    $options = $options;
  };

  const resetAll = () => {
    if (confirm($_('reset.confirmAll'))) {
      resetOptions(Object.keys($options));
      $icon = null;
      $customCursorIcon = null;
      $loadingScreenImage = null;
    }
  };

  const exportOptions = async () => {
    const exported = await recursivelySerializeBlobs($options);
    const blob = new Blob([JSON.stringify(exported)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const formattedAppName = APP_NAME
      .replace(/[^a-z0-9 ]/gi, '')
      .replace(/ /g, '-')
      .toLowerCase();
    downloadURL(`${formattedAppName}-settings.json`, url);
    URL.revokeObjectURL(url);
  };
    
  const importOptions = async () => {
    const input = document.createElement("input");
    input.type = 'file';
    input.accept = '.json';
    input.addEventListener('change', (e) => {
      importOptionsFromDataTransfer(e.target);
    });
    document.body.appendChild(input);
    input.click();
    input.remove();
  };

  const importOptionsFromDataTransfer = async (dataTransfer) => {
    const file = dataTransfer.files[0];
    if (!file) {
      // Should never happen.
      return;
    }
    try {
      const text = await readAsText(file);
      const parsed = JSON.parse(text);
      const deserialized = recursivelyDeserializeBlobs(parsed);
      const copiedDefaultOptions = deepClone(defaultOptions);
      const mergedWithDefaults = merge(deserialized, copiedDefaultOptions);

      const isUnsafe = Packager.usesUnsafeOptions(mergedWithDefaults);
      if (!isUnsafe || confirm($_('options.confirmImportUnsafe'))) {
        setOptions(mergedWithDefaults);
      }
    } catch (e) {
      $error = e;
    }
  };

  onDestroy(() => {
    if (result) {
      URL.revokeObjectURL(result.url);
    }
  });

  const loadPlugins = async () => {
    pluginDebug = [];
    const addDebug = (...args) => {
      const line = args.map((i) => {
        try {
          if (typeof i === 'string') return i;
          return JSON.stringify(i);
        } catch (e) {
          try { return String(i); } catch (e2) { return '[unserializable]'; }
        }
      }).join(' ');
      pluginDebug = [...pluginDebug, line];
      try { console.log('[plugins]', line); } catch (e) {}
      try {
        const logger = (typeof window !== 'undefined') ? (window.EditorPreload && window.EditorPreload.wbLog) : null;
        if (typeof logger === 'function') logger('info', line, {scope: 'plugins'});
      } catch (e) {}
    };
    addDebug('loadPlugins start', {IsDesktop: typeof window !== 'undefined' && !!window.IsDesktop});
    let api = (typeof window !== 'undefined') ? window.PackagerPluginsPreload : null;
    addDebug('PackagerPluginsPreload exists', !!api);
    if (!api) {
      try {
        const inNode = typeof process === 'object' && process && process.versions && !!process.versions.node;
        const nodeRequire = (typeof __non_webpack_require__ === 'function') ? __non_webpack_require__ : (typeof require === 'function' ? require : null);
        addDebug('node environment', {inNode, hasNodeRequire: typeof nodeRequire === 'function'});
        if (inNode && typeof nodeRequire === 'function') {
          const fs = nodeRequire('fs');
          const path = nodeRequire('path');
          const dirName = ($options && $options.wb && $options.wb.pluginDir) ? $options.wb.pluginDir : 'plugins';
          const dirPath = path.resolve(process.cwd(), dirName);
          addDebug('resolved dir', {dirName, dirPath});
          api = {
            dir: dirPath,
            getDir: () => Promise.resolve(dirPath),
            list: () => Promise.resolve((() => {
              let entries;
              try {
                entries = fs.readdirSync(dirPath, {withFileTypes: true});
              } catch (e) {
                addDebug('readdirSync failed', String(e && (e.stack || e)));
                return [];
              }
              const out = [];
              for (const entry of entries) {
                if (!entry || !entry.isFile()) continue;
                const name = entry.name;
                if (!name || name.startsWith('.')) continue;
                if (!name.endsWith('.js') && !name.endsWith('.cjs')) continue;
                let size = 0;
                try {
                  size = fs.statSync(path.join(dirPath, name)).size;
                } catch (e) {}
                out.push({name, size});
              }
              addDebug('plugins found', out.map((i) => i.name));
              return out;
            })()),
            read: (name) => Promise.resolve(fs.readFileSync(path.join(dirPath, String(name)), 'utf8'))
          };
          window.PackagerPluginsPreload = api;
          addDebug('fallback preload installed', true);
        }
      } catch (e) {
        addDebug('fallback error', String(e && (e.stack || e)));
      }
    }
    if (!api || typeof api.list !== 'function') {
      pluginDir = '';
      pluginEntries = [];
      addDebug('no api.list -> unsupported');
      return;
    }
    if (typeof api.getDir === 'function') {
      try {
        pluginDir = await api.getDir();
      } catch (e) {
        pluginDir = '';
        addDebug('getDir failed', String(e && (e.stack || e)));
      }
    } else {
      pluginDir = api.dir || '';
    }
    try {
      pluginEntries = await api.list();
      addDebug('list ok', {count: pluginEntries.length});
    } catch (e) {
      pluginEntries = [];
      addDebug('list failed', String(e && (e.stack || e)));
    }
  };

  const openPlugins = async () => {
    await loadPlugins();
    showPlugins = true;
  };

  const detectSigningTools = async () => {
    signingToolsError = '';
    signingTools = null;
    try {
      const api = typeof window !== 'undefined' ? window.PackagerSigningPreload : null;
      if (!api || typeof api.detectTools !== 'function') {
        signingToolsError = '签名功能仅在桌面版可用。';
        return;
      }
      signingTools = await api.detectTools();
      if (!signingTools || signingTools.ok === false) {
        signingToolsError = (signingTools && signingTools.error) ? String(signingTools.error) : '检测失败';
      }
    } catch (e) {
      signingToolsError = String(e && (e.stack || e));
    }
  };

  onMount(() => {
    if (typeof window !== 'undefined' && window.IsDesktop && $options && $options.wb) {
      $options.wb.enablePluginDir = true;
      detectSigningTools();
    }
  });
</script>

<style>
  .option {
    display: block;
    margin: 4px 0;
  }
  .group {
    margin: 12px 0;
  }
  p {
    margin: 8px 0;
  }
  .group:last-child, .option:last-child, p:last-child {
    margin-bottom: 0;
  }
  textarea {
    box-sizing: border-box;
    width: 100%;
    min-width: 100%;
    height: 150px;
  }
  input[type="text"] {
    width: 200px;
  }
  input[type="text"].shorter {
    width: 150px;
  }
  input[type="number"] {
    width: 50px;
  }
  input:invalid, .version:placeholder-shown {
    outline: 2px solid red;
  }
  .warning {
    font-weight: bold;
    background: yellow;
    color: black;
    padding: 10px;
    border-radius: 10px;
  }
  .buttons {
    display: flex;
  }
  .button {
    margin-right: 4px;
  }
  .side-buttons {
    display: flex;
    margin-left: auto;
  }
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
  }
  .modal {
    width: min(700px, calc(100vw - 32px));
    max-height: calc(100vh - 32px);
    overflow: auto;
    background: #1a1a1a;
    color: white;
    border-radius: 12px;
    padding: 16px;
    box-sizing: border-box;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    white-space: pre-wrap;
    word-break: break-word;
  }
</style>

<Section
  accent="#FFAB19"
  reset={() => {
    resetOptions([
      'turbo',
      'framerate',
      'interpolation',
      'highQualityPen',
      'maxClones',
      'fencing',
      'miscLimits',
      'stageWidth',
      'stageHeight',
      'resizeMode',
      'username'
    ]);
  }}
>
  <div>
    <h2>{$_('options.runtimeOptions')}</h2>

    {#if hasSettingsStoredInProject}
      <div class="group">
        {$_('options.storedWarning')}
      </div>
    {/if}

    <label class="option">
      <input type="checkbox" bind:checked={$options.turbo}>
      {$_('options.turbo')}
    </label>
    <div class="option">
      <label>
        {$_('options.framerate')}
        <input type="number" min="0" max="240" bind:value={$options.framerate}>
      </label>
      <LearnMore slug="custom-fps" />
    </div>
    <div class="option">
      <label>
        <input type="checkbox" bind:checked={$options.interpolation}>
        {$_('options.interpolation')}
      </label>
      <LearnMore slug="interpolation" />
    </div>
    <div class="option">
      <label>
        <input type="checkbox" bind:checked={$options.highQualityPen}>
        {$_('options.highQualityPen')}
      </label>
      <LearnMore slug="high-quality-pen" />
    </div>
    <div class="option">
      <label>
        <input type="checkbox" checked={$options.maxClones === ALMOST_INFINITY} on:change={(e) => {
          $options.maxClones = e.target.checked ? ALMOST_INFINITY : 300;
        }}>
        {$_('options.infiniteClones')}
      </label>
      <LearnMore slug="infinite-clones" />
    </div>
    <div class="option">
      <label>
        <input type="checkbox" checked={!$options.fencing} on:change={(e) => {
          $options.fencing = !e.target.checked;
        }}>
        {$_('options.removeFencing')}
      </label>
      <LearnMore slug="remove-fencing" />
    </div>
    <div class="option">
      <label>
        <input type="checkbox" checked={!$options.miscLimits} on:change={(e) => {
          $options.miscLimits = !e.target.checked;
        }}>
        {$_('options.removeMiscLimits')}
      </label>
      <LearnMore slug="remove-misc-limits" />
    </div>
    <label class="option">
      {$_('options.username')}
      <input type="text" class="shorter" bind:value={$options.username}>
    </label>
    {#if $options.username !== defaultOptions.username && cloudVariables.length !== 0}
      <p class="warning">
        {$_('options.customUsernameWarning')}
      </p>
    {/if}
    <label class="option">
      <input type="checkbox" bind:checked={$options.closeWhenStopped}>
      {$_('options.closeWhenStopped')}
    </label>

    <h3>{$_('options.stage')}</h3>
    <label class="option">
      {$_('options.stageSize')}
      <input type="number" min="1" max="4096" step="1" bind:value={$options.stageWidth}>
      &times;
      <input type="number" min="1" max="4096" step="1" bind:value={$options.stageHeight}>
      <LearnMore slug="custom-stage-size" />
    </label>
    <div class="group">
      <label class="option">
        <input type="radio" name="resize-mode" value="preserve-ratio" bind:group={$options.resizeMode}>
        {$_('options.preserveRatio')}
      </label>
      <label class="option">
        <input type="radio" name="resize-mode" value="stretch" bind:group={$options.resizeMode}>
        {$_('options.stretch')}
      </label>
      <label class="option">
        <input type="radio" name="resize-mode" value="dynamic-resize" bind:group={$options.resizeMode}>
        {$_('options.dynamicResize')}
        <LearnMore slug="packager/dynamic-stage-resize" />
      </label>
    </div>
  </div>
</Section>

<Section
  accent="#9966FF"
  reset={() => {
    $icon = null;
    $loadingScreenImage = null;
    resetOptions([
      'app.windowTitle',
      'app.writeWindowsExeIcon',
      'app.exportWindowsIco',
      'app.writeMacElectronIcns',
      'app.exportLinuxDesktopFile',
      'loadingScreen',
      'autoplay',
      'controls',
      'appearance',
      'monitors',
    ]);
  }}
>
  <div>
    <h2>{$_('options.playerOptions')}</h2>

    <label class="option">
      {$_('options.pageTitle')}
      <input type="text" bind:value={$options.app.windowTitle}>
    </label>
    <div class="option">
      {$_('options.icon')}
      <ImageInput bind:file={$icon} previewSizes={[[64, 64], [32, 32], [16, 16]]} />
    </div>
    {#if $options.target.startsWith('electron-win')}
      <label class="option">
        <input type="checkbox" bind:checked={$options.app.writeWindowsExeIcon}>
        {$_('options.writeWindowsExeIcon')}
      </label>
      <p>{$_('options.writeWindowsExeIconHelp')}</p>
      <label class="option">
        <input type="checkbox" bind:checked={$options.app.exportWindowsIco}>
        {$_('options.exportWindowsIco')}
      </label>
      <p>{$_('options.exportWindowsIcoHelp')}</p>
    {/if}
    {#if $options.target.startsWith('electron-mac')}
      <label class="option">
        <input type="checkbox" bind:checked={$options.app.writeMacElectronIcns}>
        {$_('options.writeMacElectronIcns')}
      </label>
      <p>{$_('options.writeMacElectronIcnsHelp')}</p>
    {/if}
    {#if $options.target.startsWith('electron-linux')}
      <label class="option">
        <input type="checkbox" bind:checked={$options.app.exportLinuxDesktopFile}>
        {$_('options.exportLinuxDesktopFile')}
      </label>
      <p>{$_('options.exportLinuxDesktopFileHelp')}</p>
    {/if}

    <h3>{$_('options.loadingScreen')}</h3>
    <label class="option">
      <input type="checkbox" bind:checked={$options.loadingScreen.progressBar}>
      {$_('options.showProgressBar')}
    </label>
    <label class="option">
      {$_('options.loadingScreenText')}
      <input type="text" bind:value={$options.loadingScreen.text} placeholder={$_('options.loadingScreenTextPlaceholder')}>
    </label>
    <div class="option">
      {$_('options.loadingScreenImage')}
      <!-- Display preview at image's native size -->
      <ImageInput bind:file={$loadingScreenImage} previewSizes={[['', '']]} />
    </div>
    {#if $loadingScreenImage}
      <label class="option">
        <input type="radio" name="loading-screen-mode" value="normal" bind:group={$options.loadingScreen.imageMode}>
        {$_('options.sizeNormal')}
      </label>
      <label class="option">
        <input type="radio" name="loading-screen-mode" value="stretch" bind:group={$options.loadingScreen.imageMode}>
        {$_('options.sizeStretch')}
      </label>
    {/if}

    <h3>{$_('options.controls')}</h3>
    <div class="group">
      <label class="option">
        <input type="checkbox" bind:checked={$options.autoplay}>
        {$_('options.autoplay')}
      </label>
      {#if $options.autoplay}
        {$_('options.autoplayHint')}
      {/if}
    </div>
    <label class="option">
      <input type="checkbox" bind:checked={$options.controls.greenFlag.enabled}>
      {$_('options.showFlag')}
    </label>
    <label class="option">
      <input type="checkbox" bind:checked={$options.controls.stopAll.enabled}>
      {$_('options.showStop')}
    </label>
    <label class="option">
      <input type="checkbox" bind:checked={$options.controls.pause.enabled}>
      {$_('options.showPause')}
    </label>
    <label class="option">
      <input type="checkbox" bind:checked={$options.controls.fullscreen.enabled}>
      {$_('options.showFullscreen')}
    </label>
    <p>{$_('options.controlsHelp')}</p>

    <h3>{$_('options.colors')}</h3>
    <!-- svelte-ignore a11y-label-has-associated-control -->
    <label class="option">
      <ColorPicker bind:value={$options.appearance.background} />
      {$_('options.backgroundColor')}
    </label>
    <!-- svelte-ignore a11y-label-has-associated-control -->
    <label class="option">
      <ColorPicker bind:value={$options.appearance.foreground} />
      {$_('options.foregroundColor')}
    </label>
    <!-- svelte-ignore a11y-label-has-associated-control -->
    <label class="option">
      <ColorPicker bind:value={$options.appearance.accent} />
      {$_('options.accentColor')}
    </label>

    <h3>{$_('options.monitors')}</h3>
    <label class="option">
      <input type="checkbox" bind:checked={$options.monitors.editableLists}>
      {$_('options.editableLists')}
    </label>
    <!-- svelte-ignore a11y-label-has-associated-control -->
    <label class="option">
      <ColorPicker bind:value={$options.monitors.variableColor} />
      {$_('options.variableColor')}
    </label>
    <!-- svelte-ignore a11y-label-has-associated-control -->
    <label class="option">
      <ColorPicker bind:value={$options.monitors.listColor} />
      {$_('options.listColor')}
    </label>
  </div>
</Section>

<Section
  accent="#4CBFE6"
  reset={() => {
    $customCursorIcon = null;
    resetOptions([
      'cursor',
      'chunks',
    ]);
  }}
>
  <div>
    <h2>{$_('options.interaction')}</h2>
    <div class="group">
      <label class="option">
        <input type="radio" name="cursor-type" bind:group={$options.cursor.type} value="auto">
        {$_('options.normalCursor')}
      </label>
      <label class="option">
        <input type="radio" name="cursor-type" bind:group={$options.cursor.type} value="none">
        {$_('options.noCursor')}
      </label>
      <label class="option">
        <input type="radio" name="cursor-type" bind:group={$options.cursor.type} value="custom">
        {$_('options.customCursor')}
      </label>
    </div>
    {#if $options.cursor.type === 'custom'}
      <div in:slide|self class="option">
        <ImageInput bind:file={$customCursorIcon} previewSizes={[[32, 32], [16, 16]]} />
        <p>{$_('options.cursorHelp')}</p>
        <label class="option">
          {$_('options.cursorCenter')}
          <!-- X: and Y: intentionally not translated -->
          X: <input type="number" min="0" bind:value={$options.cursor.center.x}>
          Y: <input type="number" min="0" bind:value={$options.cursor.center.y}>
          <button
            on:click={automaticallyCenterCursor}
            disabled={!$customCursorIcon}
          >
            {$_('options.automaticallyCenter')}
          </button>
        </label>
      </div>
    {/if}

    <div class="group">
      <label class="option">
        <input type="checkbox" bind:checked={$options.chunks.pointerlock}>
        {$_('options.pointerlock')}
      </label>
      <a href="https://experiments.turbowarp.org/pointerlock/" target="_blank" rel="noopener noreferrer">
        {$_('options.pointerlockHelp')}
      </a>
    </div>

    <div class="group">
      <label class="option">
        <input type="checkbox" bind:checked={$options.chunks.gamepad}>
        {$_('options.gamepad')}
      </label>
      <a href="https://turbowarp.org/addons#gamepad" target="_blank" rel="noopener noreferrer">
        {$_('options.gamepadHelp')}
      </a>
    </div>
  </div>
</Section>

<Section
  accent="#FF8C1A"
  reset={cloudVariables.length === 0 ? null : () => {
    resetOptions([
      'cloudVariables'
    ]);
  }}
>
  <div>
    <h2>{$_('options.cloudVariables')}</h2>

    {#if cloudVariables.length > 0}
      <label class="option">
        {$_('options.mode')}
        <select bind:value={$options.cloudVariables.mode}>
          <option value="ws">{$_('options.cloudVariables-ws')}</option>
          <option value="local">{$_('options.cloudVariables-local')}</option>
          <option value="">{$_('options.cloudVariables-ignore')}</option>
          <option value="custom">{$_('options.cloudVariables-custom')}</option>
        </select>
      </label>

      {#if $options.cloudVariables.mode === "custom"}
        <div transition:fade|local>
          {#each cloudVariables as variable}
            <label class="option">
              <select bind:value={$options.cloudVariables.custom[variable]}>
                <option value="ws">{$_('options.cloudVariables-ws')}</option>
                <option value="local">{$_('options.cloudVariables-local')}</option>
                <option value="">{$_('options.cloudVariables-ignore')}</option>
              </select>
              {variable}
            </label>
          {/each}
        </div>
      {/if}

      {#if $options.cloudVariables.mode === 'ws' || $options.cloudVariables.mode === 'custom'}
        <div transition:fade|local>
          <label class="option">
            {$_('options.cloudVariablesHost')}
            <!-- Examples of valid values: -->
            <!-- wss://clouddata.turbowarp.org -->
            <!-- ws:localhost:8080 -->
            <input type="text" bind:value={$options.cloudVariables.cloudHost} pattern="wss?:.*">
          </label>
        </div>
      {/if}

      <p>{$_('options.cloudVariables-ws-help')}</p>
      <p>{$_('options.cloudVariables-local-help')}</p>
      <p>{$_('options.cloudVariables-ignore-help')}</p>
      <p>{$_('options.cloudVariables-custom-help')}</p>

      <div class="option">
        <label>
          <input type="checkbox" bind:checked={$options.cloudVariables.specialCloudBehaviors}>
          {$_('options.specialCloudBehaviors')}
        </label>
        <LearnMore slug="packager/special-cloud-behaviors" />
      </div>

      <div class="option">
        <label>
          <input type="checkbox" bind:checked={$options.cloudVariables.unsafeCloudBehaviors}>
          {$_('options.unsafeCloudBehaviors')}
        </label>
        <LearnMore slug="packager/special-cloud-behaviors#eval" />
      </div>
      {#if $options.cloudVariables.unsafeCloudBehaviors}
        <p class="warning">{$_('options.unsafeCloudBehaviorsWarning')}</p>
      {/if}
      <p>{$_('options.implicitCloudHint').replace('{cloud}', '☁')}</p>
    {:else}
      <p>{$_('options.noCloudVariables')}</p>
    {/if}
  </div>
</Section>

<Section
  accent="#FF6680"
  reset={() => {
    resetOptions([
      'compiler',
      'extensions',
      'bakeExtensions',
      'custom',
      'projectId',
      'maxTextureDimension',
      'wb'
    ]);
  }}
>
  <div>
    <h2>{$_('options.advancedOptions')}</h2>
    <details open={advancedOptionsInitiallyOpen}>
      <summary>{$_('options.advancedSummary')}</summary>

      <div class="option">
        <label>
          <input type="checkbox" bind:checked={$options.compiler.enabled}>
          {$_('options.enableCompiler')}
        </label>
        <LearnMore slug="disable-compiler" />
      </div>
      <div class="option">
        <label>
          <input type="checkbox" bind:checked={$options.compiler.warpTimer}>
          {$_('options.warpTimer')}
        </label>
        <LearnMore slug="warp-timer" />
      </div>

      <!-- Ignore because CustomExtensions will have a <textarea> inside it -->
      <!-- svelte-ignore a11y-label-has-associated-control -->
      <label class="option">
        {$_('options.customExtensions')}
        <!-- TODO: use the user-facing documentation when that becomes available -->
        <LearnMore slug="development/custom-extensions" />
        <CustomExtensions bind:extensions={$options.extensions} />
        <p class="warning">{$_('options.customExtensionsSecurity')}</p>
      </label>

      <label class="option">
        <input type="checkbox" bind:checked={$options.bakeExtensions}>
        {$_('options.bakeExtensions')}
      </label>

      <label class="option">
        {$_('options.customCSS')}
        <textarea bind:value={$options.custom.css}></textarea>
      </label>
      <label class="option">
        {$_('options.customJS')}
        <textarea bind:value={$options.custom.js}></textarea>
      </label>

      <label class="option">
        {$_('options.projectId')}
        <input type="text" bind:value={$options.projectId}>
      </label>
      <p>{$_('options.projectIdHelp')}</p>

      <label class="option">
        <input type="checkbox" bind:checked={$options.packagedRuntime} />
        {$_('options.packagedRuntime')}
      </label>

      <h3>保护 / 混淆</h3>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.obfuscateNames} />
        混淆变量/列表/广播名称
      </label>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.opcodeObfuscation} />
        混淆 opcode（必须引入wb-scratchvm依赖才能使用 不然会导致作品卡死）
      </label>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.splitElectronEntry} />
        拆分 Electron 入口（将主进程/预加载拆成多个分片加载）
      </label>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.packResourcesXor} />
        资源 XOR 封包（仅 assets/extensions/static_assets，不包含 project.json；路径不变）
      </label>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.encryptProject} />
        加密项目数据（AES-GCM；导出时动态生成密钥）
      </label>
      {#if $options.wb.encryptProject}
        <label class="option">
          <input type="checkbox" bind:checked={$options.wb.encryptRuntime} />
          加密运行时脚本（Electron；将 script/内联脚本打包为加密负载）
        </label>
        <label class="option">
          <input type="checkbox" bind:checked={$options.wb.shredWbResources} />
          分片打散（配合加密；减少固定结构特征）
        </label>
        <label class="option">
          <input type="checkbox" bind:checked={$options.wb.obfuscateUnpack} />
          混淆解包引导脚本（会增加体积与启动时间）
        </label>
        <p class="warning">提示：加密相关选项仅对 Electron / Node-CLI 生效，HTML 目标会被忽略。</p>
      {/if}
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.compileProjectToJS} />
        将项目数据封装到 JS 文件中（部分环境中不再单独打包 project.json）
      </label>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.compileProjectRuntimeJS} />
        预编译脚本为 JS 并剥离积木结构（实验功能）
      </label>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.allowCustomExtensionsFromProject} />
        允许从项目自动加载自定义拓展（有安全风险）
      </label>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.disableExtensionSecurity} />
        打包运行时关闭扩展安全限制（仅限内部自用）
      </label>
      {#if $options.wb.allowCustomExtensionsFromProject}
        <label class="option">
          unsandboxed 扩展 URL 关键字（每行一个，匹配则以 unsandboxed 加载）
          <CustomExtensions bind:extensions={$options.wb.unsandboxedExtensionUrlKeywords} />
        </label>
      {/if}
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.debugLog} />
        输出运行时/资源加载诊断日志
      </label>
      {#if $options.wb.debugLog}
        <label class="option">
          <input type="checkbox" bind:checked={$options.wb.debugLogVerbose} />
          详细日志（会输出更多路径与读文件结果）
        </label>
      {/if}
      <label class="option">
        扩展加载策略（secure CSP 下建议使用“文件”）
        <select bind:value={$options.wb.extensionLoadStrategy}>
          <option value="auto">自动</option>
          <option value="file">文件</option>
          <option value="data">data URL</option>
        </select>
      </label>

      <h3>签名 / 发行</h3>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.codeSigning.enabled} />
        导出后执行代码签名（仅桌面版；需本机安装签名工具）
      </label>
      {#if $options.wb.codeSigning.enabled}
        <div class="group">
          <Button on:click={detectSigningTools} secondary text="检测本机签名工具" />
        </div>
        {#if signingTools && signingTools.platform}
          <p class="mono">当前平台：{signingTools.platform}</p>
        {/if}
        {#if signingToolsError}
          <p class="warning">{signingToolsError}</p>
        {/if}

        <details class="group">
          <summary>Windows（signtool）</summary>
          <p>需要 Windows SDK（signtool.exe）。官方文档：<a href="https://learn.microsoft.com/windows/win32/seccrypto/signtool" target="_blank" rel="noreferrer">Signtool</a></p>
          <label class="option">
            模式
            <select bind:value={$options.wb.codeSigning.windows.mode}>
              <option value="pfx">PFX 文件</option>
              <option value="store">证书库（Subject 名称）</option>
            </select>
          </label>
          {#if $options.wb.codeSigning.windows.mode === 'pfx'}
            <label class="option">
              PFX 路径（桌面版本机路径）
              <input type="text" class="shorter" bind:value={$options.wb.codeSigning.windows.pfxPath} />
            </label>
            <p>密码会在导出时弹窗输入，不会保存到配置。</p>
          {:else}
            <label class="option">
              证书 Subject 名称
              <input type="text" class="shorter" bind:value={$options.wb.codeSigning.windows.certSubject} />
            </label>
          {/if}
          <label class="option">
            时间戳 URL
            <input type="text" bind:value={$options.wb.codeSigning.windows.timestampUrl} />
          </label>
          <label class="option">
            描述（/d）
            <input type="text" class="shorter" bind:value={$options.wb.codeSigning.windows.description} />
          </label>
          <label class="option">
            <input type="checkbox" bind:checked={$options.wb.codeSigning.windows.signAllFiles} />
            尝试签名目录内所有 exe/dll（较慢）
          </label>
          <p class="mono">提示：Windows 签名只能在 Windows 上执行。</p>
        </details>

        <details class="group">
          <summary>macOS（codesign）</summary>
          <p>需要 Xcode Command Line Tools（codesign）以及 zip。官方：<a href="https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution" target="_blank" rel="noreferrer">Notarization</a></p>
          <label class="option">
            codesign identity（Keychain 中的签名身份）
            <input type="text" bind:value={$options.wb.codeSigning.mac.identity} />
          </label>
          <label class="option">
            <input type="checkbox" bind:checked={$options.wb.codeSigning.mac.hardenedRuntime} />
            hardened runtime（--options runtime）
          </label>
          <label class="option">
            <input type="checkbox" bind:checked={$options.wb.codeSigning.mac.timestamp} />
            time-stamp（--timestamp）
          </label>
          <label class="option">
            <input type="checkbox" bind:checked={$options.wb.codeSigning.mac.deep} />
            deep（--deep）
          </label>
          <p class="mono">提示：macOS 签名只能在 macOS 上执行。</p>
        </details>

        <details class="group">
          <summary>Linux（GPG 签名文件）</summary>
          <p>Linux 没有统一的 zip 代码签名；这里会生成 SHA256SUMS，并可选用 GPG 生成 detached signature。GnuPG：<a href="https://gnupg.org/download/" target="_blank" rel="noreferrer">Download</a></p>
          <label class="option">
            工具
            <select bind:value={$options.wb.codeSigning.linux.tool}>
              <option value="gpg">gpg</option>
            </select>
          </label>
          <label class="option">
            key id（可选；为空则只生成 SHA256SUMS）
            <input type="text" class="shorter" bind:value={$options.wb.codeSigning.linux.keyId} />
          </label>
          <label class="option">
            <input type="checkbox" bind:checked={$options.wb.codeSigning.linux.armor} />
            ASCII armor（--armor）
          </label>
          <p class="mono">提示：Linux 签名只能在 Linux 上执行。</p>
        </details>
      {/if}

      {#if lastPackagerInfo}
        <details class="group">
          <summary>最近一次导出摘要</summary>
          <div class="mono">
            target: {lastPackagerInfo.target}{'\n'}
            buildId: {lastPackagerInfo.buildId}{'\n'}
            packageName: {lastPackagerInfo.packageName}{'\n'}
            macos.icnsWritten: {lastPackagerInfo.macos && lastPackagerInfo.macos.icnsWritten}{'\n'}
            linux.desktopWritten: {lastPackagerInfo.linux && lastPackagerInfo.linux.desktopWritten}{'\n'}
            embeddedExtensions.files: {lastPackagerInfo.embeddedExtensions && lastPackagerInfo.embeddedExtensions.files}{'\n'}
            {'\n'}
            {#each (lastPackagerInfo.logLines || []) as line}
              {line}{'\n'}
            {/each}
          </div>
        </details>
      {/if}
      <div class="group">
        <Button on:click={openPlugins} secondary text="插件系统" />
      </div>
    </details>
  </div>
</Section>

{#if showPlugins}
  <div class="modal-backdrop" in:fade|local on:click={() => showPlugins = false}>
    <div class="modal" on:click|stopPropagation>
      <h2>插件系统</h2>
      <label class="option">
        <input type="checkbox" bind:checked={$options.wb.enablePluginDir} />
        启用 plugins 目录（导出时生效）
      </label>
      <p class="mono">示例插件：plugins-available/legal-notice-and-integrity.cjs</p>
      <p class="mono">插件 API：wb-packager/docs/plugin-api.md</p>
      {#if pluginDir}
        <p class="mono">{pluginDir}</p>
      {:else}
        <p>当前环境不支持自动读取 plugins 目录。</p>
      {/if}
      {#if pluginDebug.length > 0}
        <details class="group">
          <summary>诊断日志</summary>
          <div class="mono">
            {#each pluginDebug as line}
              {line}{'\n'}
            {/each}
          </div>
        </details>
      {/if}
      {#if pluginEntries.length > 0}
        <div class="mono">
          {#each pluginEntries as p}
            {p.name}{p.size ? ` (${p.size} bytes)` : ''}{'\n'}
          {/each}
        </div>
      {:else}
        <p>未检测到插件。</p>
      {/if}
      <div class="buttons">
        <div class="button">
          <Button on:click={loadPlugins} secondary text="刷新" />
        </div>
        <div class="side-buttons">
          <Button on:click={() => showPlugins = false} text="关闭" />
        </div>
      </div>
    </div>
  </div>
{/if}

<Section
  accent="#0FBD8C"
  reset={() => {
    resetOptions([
      'target'
    ])
  }}
>
  <div>
    <h2>{$_('options.environment')}</h2>

    <div class="group">
      <label class="option">
        <input type="radio" name="environment" bind:group={$options.target} value="html">
        {$_('options.html')}
      </label>
      <label class="option">
        <input type="radio" name="environment" bind:group={$options.target} value="node-cli">
        Node.js CLI（无图形）
      </label>
    </div>

    <div class="group">
      <label class="option">
        <input type="radio" name="environment" bind:group={$options.target} value="electron-win64">
        {$_('options.application-win64').replace('{type}', 'Electron')}
      </label>
      <label class="option">
        <input type="radio" name="environment" bind:group={$options.target} value="electron-mac">
        {$_('options.application-mac').replace('{type}', 'Electron')}
      </label>
      <label class="option">
        <input type="radio" name="environment" bind:group={$options.target} value="electron-linux64">
        {$_('options.application-linux64').replace('{type}', 'Electron')}
      </label>
    </div>

    <details open={otherEnvironmentsInitiallyOpen}>
      <summary>其他架构</summary>
      <div class="group">
        <label class="option">
          <input type="radio" name="environment" bind:group={$options.target} value="electron-win32">
          {$_('options.application-win32').replace('{type}', 'Electron')}
        </label>
      </div>
    </details>
  </div>
</Section>

{#if $options.target.startsWith('electron-')}
  <div in:fade|local>
    <Section
      accent="#FF661A"
      reset={() => {
        resetOptions([
          'app.packageName',
          'app.windowMode',
          'app.escapeBehavior',
          'app.backgroundThrottling'
        ]);
      }}
    >
      <div>
        <h2>{$_('options.applicationSettings')}</h2>
        <label class="option">
          {$_('options.packageName')}
          <input type="text" bind:value={$options.app.packageName} pattern="[\w \-]+" minlength="1">
        </label>
        <p>{$_('options.packageNameHelp')}</p>

        <label class="option">
          {$_('options.version')}
          <input type="text" class="version" bind:value={$options.app.version} pattern="\d+\.\d+\.\d+" placeholder="1.0.0" minlength="1">
        </label>
        <p>{$_('options.versionHelp')}</p>

        <label class="option">
          {$_('options.initalWindowSize')}
          <select bind:value={$options.app.windowMode}>
            <option value="window">{$_('options.startWindow')}</option>
            <option value="maximize">{$_('options.startMaximized')}</option>
            <option value="fullscreen">{$_('options.startFullscreen')}</option>
          </select>
        </label>

        <label class="option">
          {$_('options.escapeBehavior')}
          <select bind:value={$options.app.escapeBehavior}>
            <option value="unfullscreen-only">{$_('options.unFullscreenOnly')}</option>
            <option value="exit-only">{$_('options.exitOnly')}</option>
            <option value="unfullscreen-or-exit">{$_('options.unFullscreenOrExit')}</option>
            <option value="nothing">{$_('options.doNothing')}</option>
          </select>
        </label>

        <label class="option">
          {$_('options.windowControls')}
          <select bind:value={$options.app.windowControls}>
            <option value="default">{$_('options.defaultControls')}</option>
            <option value="frameless">{$_('options.noControls')}</option>
          </select>
        </label>

        <label class="option">
          <input type="checkbox" bind:checked={$options.app.backgroundThrottling}>
          {$_('options.backgroundThrottling')}
        </label>

        <div class="warning">
          <div>Electron 产物体积较大且发布需要签名。建议：</div>
          <ul>
            <li>仅在确实需要“离线桌面应用壳”时使用 Electron</li>
            <li>发布给用户前使用本页面的签名功能（需要本机安装签名工具）</li>
          </ul>
        </div>

        {#if $options.target.includes('win')}
          <div>
            <h2>Windows</h2>
            <p>未签名的 exe 会触发 SmartScreen。建议在桌面版开启“签名 / 发行”并配置 signtool。</p>
          </div>
        {:else if $options.target.includes('mac')}
          <div>
            <h2>macOS</h2>
            <p>未签名的 app 会触发 Gatekeeper。建议在 macOS 上执行 codesign（如需分发再做 notarize）。</p>
          </div>
        {:else if $options.target.includes('linux')}
          <div>
            <h2>Linux</h2>
            <p>Linux 通常以校验/签名文件形式发布（SHA256SUMS + GPG）。</p>
          </div>
        {/if}
      </div>
    </Section>
  </div>
{/if}

{#if projectData.project.analysis.usesSteamworks}
  <Section
    accent="#136C9F"
    reset={() => {
      resetOptions([
        'steamworks'
      ]);
    }}
  >
    <h2>{$_('options.steamworksExtension')}</h2>
    {#if ['electron-win64', 'electron-linux64', 'electron-mac'].includes($options.target)}
      <p>{$_('options.steamworksAvailable').replace('{n}', '480')}</p>
      <label class="option">
        {$_('options.steamworksAppId')}
        <input pattern="\d+" minlength="1" bind:value={$options.steamworks.appId}>
      </label>
      <label class="option">
        {$_('options.steamworksOnError')}
        <select bind:value={$options.steamworks.onError}>
          <option value="ignore">{$_('options.steamworksIgnore')}</option>
          <option value="warning">{$_('options.steamworksWarning')}</option>
          <option value="error">{$_('options.steamworksError')}</option>
        </select>
      </label>

      {#if $options.target === 'electron-mac'}
        <p class="warning">
          {$_('options.steamworksMacWarning')}
        </p>
      {/if}
    {:else}
      <p>{$_('options.steamworksUnavailable')}</p>
      <ul>
        <li>{$_('options.application-win64').replace('{type}', 'Electron')}</li>
        <li>
          {$_('options.application-mac').replace('{type}', 'Electron')}
          <br>
          {$_('options.steamworksMacWarning')}
        </li>
        <li>{$_('options.application-linux64').replace('{type}', 'Electron')}</li>
      </ul>
    {/if}

    <p>
      <a href="https://extensions.turbowarp.org/steamworks">{$_('options.steamworksDocumentation')}</a>
    </p>
  </Section>
{/if}

<Section>
  <DropArea on:drop={(e) => importOptionsFromDataTransfer(e.detail)}>
    <div class="buttons">
      <div class="button">
        <Button on:click={exportOptions} secondary text={$_('options.export')} />
      </div>
      <div class="button">
        <Button on:click={importOptions} secondary text={$_('options.import')} />
      </div>
      <div class="side-buttons">
        <Button on:click={resetAll} dangerous text={$_('options.resetAll')} />
      </div>
    </div>
  </DropArea>
</Section>

<Section>
  <div class="buttons">
    <div class="button">
      <Button on:click={pack} text={$_('options.package')} />
    </div>
    <div clas="button">
      <Button on:click={preview} secondary text={$_('options.preview')} />
    </div>
  </div>
</Section>

{#if result}
  <Downloads
    name={result ? result.filename : null}
    url={result ? result.url : null}
    blob={result ? result.blob : null}
  />
{:else if !$progress.visible}
  <Section caption>
    <p>{$_('options.downloadsWillAppearHere')}</p>
  </Section>
{/if}
