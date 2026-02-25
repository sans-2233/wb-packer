// This defines where files are fetched from when the packager needs to download files.
// Files fetched from an external server have a SHA-256 checksum used to validate the download.

// src is the URL that will be fetched to download the asset. If it's an array of URLs, each URL
// will be tried in succession if the previous one fails, perhaps because it's blocked by a school
// network filter.

// estimatedSize is used for the asset download progress bar if the server doesn't specify a
// Content-Length. It's size in bytes after decoding Content-Encoding. Real size does not need to
// match; this is just for the progress bar. estimatedSize is optional and can be omitted.
// Make sure to use size estimates from production builds, not development ones.

// useBuildId is used for various cache related things. It shouldn't be changed.

const externalFile = (name) => [
  // Hopefully one of these URLs will not be blocked.
  `https://packagerdata.turbowarp.org/${name}`,
  `https://blobs.turbowarp.xyz/${name}`
];

const relativeScaffolding = (name) => `scaffolding/${name}`;

export default {
  'electron-win32': {
    src: externalFile('electron-v22.3.27-win32-ia32.zip'),
    sha256: '47bd498e5513529c5e141394fc9fd610cba1dcdea9e6dbb165edf929cbfd9af2',
    estimatedSize: 90856612
  },
  'electron-win64': {
    src: externalFile('electron-v22.3.27-win32-x64.zip'),
    sha256: '1a02c0f7af9664696f790dcce05948f0458a2f4f2d48c685f911d2eb99a4c9da',
    estimatedSize: 96605498
  },
  'electron-mac': {
    src: externalFile('electron-v22.3.27-macos-universal.zip'),
    sha256: '598b35f9030fe30f81b4041be048cd0374f675bd1bc0f172c26cf2808e80a3d9',
    estimatedSize: 160882083
  },
  'electron-linux64': {
    src: externalFile('electron-v22.3.27-linux-x64.zip'),
    sha256: '631d8eb08098c48ce2b29421e74c69ac0312b1e42f445d8a805414ba1242bf3a',
    estimatedSize: 93426892
  },
  'steamworks.js': {
    src: externalFile('steamworks.js-0.3.2.zip'),
    sha256: 'fd8bc80a97cd880d71113dfc5f81b124b6e212335393db73e3df168c5c546fbc',
    estimatedSize: 3279554,
  },
  scaffolding: {
    src: relativeScaffolding('scaffolding-full.js'),
    estimatedSize: 4564032,
    useBuildId: true
  },
  'scaffolding-min': {
    src: relativeScaffolding('scaffolding-min.js'),
    estimatedSize: 2530463,
    useBuildId: true
  },
  addons: {
    src: relativeScaffolding('addons.js'),
    estimatedSize: 19931,
    useBuildId: true
  },
  'node-cli-runtime': {
    src: relativeScaffolding('node-cli-runtime.js'),
    useBuildId: true
  }
};
