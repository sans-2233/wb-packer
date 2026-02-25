const fs = require('fs');

const g = typeof globalThis !== 'undefined' ? globalThis : global;
if (g) {
  if (!g.window) g.window = g;
  if (!g.self) g.self = g;
  if (!g.navigator) g.navigator = {userAgent: 'node'};
}

const VirtualMachine = require('../../../vendor/scratch-vm/src/index');

const file = process.argv[2];
if (!file) {
  throw new Error('Invalid file');
}

const runProject = async (buffer) => {
  const vm = new VirtualMachine();
  try {
    const p = vm.runtime && vm.runtime._primitives;
    if (p && typeof p === 'object') {
      const log = (text) => {
        try {
          const s = (text === null || typeof text === 'undefined') ? '' : String(text);
          if (s) console.log(s);
        } catch (e) {}
      };
      const getMsg = (args) => {
        if (!args || typeof args !== 'object') return '';
        if (Object.prototype.hasOwnProperty.call(args, 'MESSAGE')) return args.MESSAGE;
        if (Object.prototype.hasOwnProperty.call(args, 'TEXT')) return args.TEXT;
        return '';
      };
      p.looks_say = (args) => log(getMsg(args));
      p.looks_think = (args) => log(getMsg(args));
      p.looks_sayforsecs = (args) => log(getMsg(args));
      p.looks_thinkforsecs = (args) => log(getMsg(args));
    }
  } catch (e) {}
  vm.runtime.on('SAY', (target, type, text) => {
    console.log(text);
  });
  vm.setCompatibilityMode(true);
  vm.clear();
  await vm.loadProject(buffer);
  vm.start();
  vm.greenFlag();
  await new Promise(resolve => {
    const interval = setInterval(() => {
      let active = 0;
      const threads = vm.runtime.threads;
      for (let i = 0; i < threads.length; i++) {
        if (!threads[i].updateMonitor) {
          active += 1;
        }
      }
      if (active === 0) {
        clearInterval(interval);
        resolve();
      }
    }, 50);
  });
  vm.stopAll();
  vm.quit();
};

runProject(fs.readFileSync(file));
