import Packager from './packager';

const ensureBase64 = () => {
  if (typeof globalThis.btoa !== 'function') {
    globalThis.btoa = (str) => Buffer.from(String(str), 'binary').toString('base64');
  }
  if (typeof globalThis.atob !== 'function') {
    globalThis.atob = (b64) => Buffer.from(String(b64), 'base64').toString('binary');
  }
};

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

describe('XOR resource pack', () => {
  test('key sharding can be reconstructed', () => {
    ensureBase64();
    const {buildXorResourcePackMeta, xorCrypt} = Packager._test;
    const key = new Uint8Array(32);
    const salt = new Uint8Array(16);
    for (let i = 0; i < key.length; i++) key[i] = (i * 13 + 7) & 0xff;
    for (let i = 0; i < salt.length; i++) salt[i] = (i * 17 + 3) & 0xff;

    const meta = buildXorResourcePackMeta('p4-test', key, salt, 8);
    const saltBytes = b64ToBytes(meta.salt);
    const shards = [];
    for (let i = 0; i < meta.parts.length; i++) {
      const physical = meta.order[i];
      const obf = b64ToBytes(meta.parts[physical]);
      shards.push(xorCrypt(obf, saltBytes, i & 0xff));
    }
    const total = shards.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const s of shards) {
      out.set(s, off);
      off += s.length;
    }
    expect(Buffer.from(out)).toEqual(Buffer.from(key));
  });

  test('resource key normalization', () => {
    const {normalizePackedResourceKey} = Packager._test;
    expect(normalizePackedResourceKey('project.json')).toBe('project.json');
    expect(normalizePackedResourceKey('assets/project.json')).toBe('project.json');
    expect(normalizePackedResourceKey('assets/abc.png')).toBe('abc.png');
    expect(normalizePackedResourceKey('foo/bar/baz.svg')).toBe('baz.svg');
  });
});

