import path from 'path';
import fs from 'fs';
import os from 'os';
import {loadPluginsFromDir, runHookChain} from '../../src/packager/plugin-system';

test('loadPluginsFromDir loads cjs plugins', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'packer-plugins-'));
  const pluginPath = path.join(tmp, 'a.cjs');
  fs.writeFileSync(pluginPath, "module.exports = { name: 'a', hooks: { transformProjectJson: (pj) => { pj.x = 1; return pj; } } };");
  const plugins = await loadPluginsFromDir(tmp);
  expect(Array.isArray(plugins)).toBe(true);
  expect(plugins.length).toBe(1);
  expect(plugins[0].name).toBe('a');
  const out = await runHookChain(plugins, 'transformProjectJson', {y: 2}, {phase: 'test'});
  expect(out).toEqual({y: 2, x: 1});
});

