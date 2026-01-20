import Packager from '../../src/packager/packager';
import path from 'path';

test('legal notice plugin transforms electron main', async () => {
  const packager = new Packager();
  const pluginDir = path.resolve(__dirname, '..', '..', 'plugins-available');
  packager.options = {
    target: 'zip',
    wb: {
      enablePluginDir: true,
      pluginDir
    }
  };
  await packager.loadPlugins();
  expect(Array.isArray(packager.plugins)).toBe(true);
  expect(packager.plugins.length).toBeGreaterThan(0);

  const input = `'use strict';\nconst {app, dialog} = require('electron');\nconst verifyIntegrity = () => {\n  app.exit(2);\n  return false;\n};\n`;
  const out = await packager.runPluginHook('transformElectronMain', input, {phase: 'test'});
  expect(out).toContain('WB_LEGAL_NOTICE_B64');
  expect(out).toContain('wbShowLegalWarning');
  expect(out).toContain(`wbShowLegalWarning('Integrity check failed')`);
});
