const getNodeRequire = () => {
  if (typeof __non_webpack_require__ === 'function') return __non_webpack_require__;
  if (typeof require === 'function') return require;
  return null;
};

const isNode = () => {
  try {
    return typeof process === 'object' && process && typeof process.versions === 'object' && !!process.versions.node;
  } catch (e) {
    return false;
  }
};

const normalizePlugin = (mod) => {
  if (!mod) return null;
  if (mod.default && typeof mod.default === 'object') return mod.default;
  if (typeof mod === 'object') return mod;
  return null;
};

const callHook = async (plugin, hookName, value, context) => {
  const hooks = plugin && plugin.hooks && typeof plugin.hooks === 'object' ? plugin.hooks : null;
  const fn = (plugin && typeof plugin[hookName] === 'function') ? plugin[hookName] : (hooks && typeof hooks[hookName] === 'function' ? hooks[hookName] : null);
  if (!fn) return value;
  const result = await fn(value, context);
  return (typeof result === 'undefined') ? value : result;
};

export const loadPluginsFromDir = async (dirPath) => {
  if (!isNode()) return [];
  const nodeRequire = getNodeRequire();
  if (!nodeRequire) return [];
  const fs = nodeRequire('fs');
  const path = nodeRequire('path');
  let entries;
  try {
    entries = fs.readdirSync(dirPath, {withFileTypes: true});
  } catch (e) {
    return [];
  }
  const plugins = [];
  for (const entry of entries) {
    if (!entry || !entry.isFile()) continue;
    const name = entry.name;
    if (!name || name.startsWith('.')) continue;
    if (!name.endsWith('.js') && !name.endsWith('.cjs')) continue;
    const fullPath = path.join(dirPath, name);
    let mod;
    try {
      mod = nodeRequire(fullPath);
    } catch (e) {
      continue;
    }
    const plugin = normalizePlugin(mod);
    if (!plugin) continue;
    plugins.push(plugin);
  }
  return plugins;
};

export const loadPluginsFromDesktopPreload = async () => {
  try {
    if (typeof window !== 'object' || !window) return [];
  } catch (e) {
    return [];
  }
  const api = window.PackagerPluginsPreload;
  if (!api || typeof api.list !== 'function' || typeof api.read !== 'function') return [];
  const entries = await api.list();
  const plugins = [];
  for (const entry of entries) {
    if (!entry || typeof entry.name !== 'string') continue;
    const code = await api.read(entry.name);
    if (!code || typeof code !== 'string') continue;
    const exportsObj = {};
    const moduleObj = {exports: exportsObj};
    const requireFn = () => {
      throw new Error('require is not available in this environment');
    };
    let mod;
    try {
      const fn = new Function('module', 'exports', 'require', String(code));
      fn(moduleObj, exportsObj, requireFn);
      mod = moduleObj.exports;
    } catch (e) {
      continue;
    }
    const plugin = normalizePlugin(mod);
    if (!plugin) continue;
    plugins.push(plugin);
  }
  return plugins;
};

export const runHookChain = async (plugins, hookName, initialValue, context) => {
  let value = initialValue;
  for (const plugin of plugins) {
    value = await callHook(plugin, hookName, value, context);
  }
  return value;
};
