const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const getJSZip = async () => {
  const mod = await import('@turbowarp/jszip');
  return mod.default || mod;
};

const sha256Hex = (bytes) => crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');

const stableManifestString = (manifest) => {
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

const buildManifestForPrefix = async (zip, resourcesPrefix, excludeRel) => {
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
      sha256: sha256Hex(data),
      size: data.length
    };
  }
  return {v: 1, kid: '', files};
};

const pickKeyMaterial = () => {
  const kid = String(process.env.WB_INTEGRITY_KEY_ID || 'prod');
  const privPem = process.env.WB_INTEGRITY_PRIVATE_KEY_PEM || null;
  const privPath = process.env.WB_INTEGRITY_PRIVATE_KEY_PATH || null;
  const pubJson = process.env.WB_INTEGRITY_PUBLIC_KEYS_JSON || null;
  const pubPath = process.env.WB_INTEGRITY_PUBLIC_KEYS_PATH || null;

  if (!privPem && !privPath) {
    throw new Error('Missing signing key: set WB_INTEGRITY_PRIVATE_KEY_PEM or WB_INTEGRITY_PRIVATE_KEY_PATH');
  }
  const pem = privPem || fs.readFileSync(path.resolve(privPath), 'utf8');
  const privateKey = crypto.createPrivateKey(pem);

  let publicKeys = {};
  if (pubJson) {
    publicKeys = JSON.parse(pubJson);
  } else if (pubPath) {
    publicKeys = JSON.parse(fs.readFileSync(path.resolve(pubPath), 'utf8'));
  } else {
    const pubPem = crypto.createPublicKey(privateKey).export({type: 'spki', format: 'pem'}).toString('utf8');
    publicKeys = {[kid]: pubPem};
  }

  return {kid, privateKey, publicKeys};
};

const usage = () => {
  process.stderr.write(`Usage: node src/build/sign-integrity.js <input.zip> [output.zip]\n`);
  process.stderr.write(`Env:\n`);
  process.stderr.write(`  WB_INTEGRITY_PRIVATE_KEY_PEM or WB_INTEGRITY_PRIVATE_KEY_PATH (required)\n`);
  process.stderr.write(`  WB_INTEGRITY_KEY_ID (optional, default prod)\n`);
  process.stderr.write(`  WB_INTEGRITY_PUBLIC_KEYS_JSON or WB_INTEGRITY_PUBLIC_KEYS_PATH (optional)\n`);
};

const run = async () => {
  const input = process.argv[2];
  const output = process.argv[3] || input;
  if (!input) {
    usage();
    process.exit(2);
  }
  const inputBytes = fs.readFileSync(path.resolve(input));
  const JSZip = await getJSZip();
  const zip = await JSZip.loadAsync(inputBytes);

  const allPaths = Object.keys(zip.files || {});
  const electronMainPath = allPaths.find((p) => /electron-main\.js$/i.test(p));
  if (!electronMainPath) {
    throw new Error('Cannot locate electron-main.js in zip');
  }
  const resourcesPrefix = electronMainPath.replace(/electron-main\.js$/i, '');

  const {kid, privateKey, publicKeys} = pickKeyMaterial();
  const manifestName = 'wb-integrity.json';
  const signatureName = 'wb-integrity.sig';
  const exclude = new Set([manifestName, signatureName]);

  const manifest = await buildManifestForPrefix(zip, resourcesPrefix, exclude);
  manifest.kid = kid;
  const manifestText = stableManifestString(manifest);
  const manifestBytes = Buffer.from(manifestText, 'utf8');
  const signature = crypto.sign('sha256', manifestBytes, privateKey);

  zip.file(resourcesPrefix + manifestName, manifestText);
  zip.file(resourcesPrefix + signatureName, signature);

  const outputBytes = await zip.generateAsync({type: 'nodebuffer', compression: 'DEFLATE'});
  fs.writeFileSync(path.resolve(output), outputBytes);

  process.stdout.write(`Wrote ${output}\n`);
  process.stdout.write(`kid: ${kid}\n`);
  process.stdout.write(`publicKeys: ${Object.keys(publicKeys).join(', ')}\n`);
};

run().catch((err) => {
  process.stderr.write(String(err && err.stack ? err.stack : err) + '\n');
  process.exit(1);
});

