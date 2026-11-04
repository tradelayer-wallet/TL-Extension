// Builds the unpacked extension whose key handling runs on tl-wallet-core (WebAssembly).
//
//   node rust/tl-extension-app/build.mjs --out <dir> --node-modules <dir> --wasm <file> [--mode=development|release]
//
// It stages the same files as the legacy build.js (the legacy tree is read, never written),
// then bundles popup/popup.js with esbuild while swapping two modules:
//   lib/walletUtils.js -> rust/tl-extension-app/shim/walletUtils.js  (key functions on wasm)
//   lib/vault.js       -> rust/tl-extension-app/shim/vault.js        (vault on wasm)
// and adds `wasm-unsafe-eval` to the extension-page CSP. The legacy build (`npm run build`) is
// unchanged and keeps using the crypto-js implementations.
//
// --node-modules points at a `npm ci --ignore-scripts` install made outside the clone
// (see WORKER_BRIEF); nothing is installed here.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const SHIM = path.join(HERE, 'shim');

const arg = (name, fallback) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (hit) return hit.slice(name.length + 3);
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
};

const outDir = path.resolve(arg('out', ''));
const nodeModules = path.resolve(arg('node-modules', ''));
const wasmFile = path.resolve(arg('wasm', ''));
const mode = arg('mode', 'development');
if (!arg('out') || !arg('node-modules') || !arg('wasm')) {
  throw new Error('usage: build.mjs --out <dir> --node-modules <dir> --wasm <file> [--mode=development|release]');
}
if (!['release', 'development'].includes(mode)) throw new Error(`Unsupported build mode: ${mode}`);
if (outDir.startsWith(ROOT + path.sep)) throw new Error('--out must be outside the repository');

const requireFrom = createRequire(path.join(nodeModules, 'noop.js'));
const esbuild = requireFrom('esbuild');
const wasmPlugin = requireFrom('esbuild-plugin-wasm').default;

const RELEASE_MATCHES = [
  'https://layerwallet.com/*',
  'https://www.layerwallet.com/*',
  'https://testnet.layerwallet.com/*',
];
const DEVELOPMENT_MATCHES = [...RELEASE_MATCHES, 'http://localhost/*', 'http://127.0.0.1/*'];
// Same list as build.js.
const PACKAGE_PATHS = [
  'background',
  'contentScript.js',
  'dist',
  'images',
  'options.html',
  'popup',
  'readyPromise.js',
  'rules.json',
  'styles.css',
  'window.js',
];

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });
for (const rel of PACKAGE_PATHS) {
  fs.cpSync(path.join(ROOT, rel), path.join(outDir, rel), { recursive: true });
}

// manifest: same match patterns as the legacy build, plus the CSP the wasm module needs.
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const matches = mode === 'development' ? DEVELOPMENT_MATCHES : RELEASE_MATCHES;
manifest.content_scripts[0].matches = matches;
manifest.web_accessible_resources[0].matches = matches;
manifest.content_security_policy = {
  extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';",
};
fs.writeFileSync(path.join(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

// background: development origin flag, exactly as build.js does it.
const bgPath = path.join(outDir, 'background', 'background.js');
const flag = 'const ALLOW_DEVELOPMENT_ORIGINS = false;';
const bg = fs.readFileSync(bgPath, 'utf8');
if (!bg.includes(flag)) throw new Error('Background development-origin marker is missing.');
fs.writeFileSync(
  bgPath,
  bg.replace(flag, `const ALLOW_DEVELOPMENT_ORIGINS = ${mode === 'development'};`)
);

// the wasm core
fs.mkdirSync(path.join(outDir, 'wasm'), { recursive: true });
fs.copyFileSync(wasmFile, path.join(outDir, 'wasm', 'tl_extension_wasm.wasm'));

const isShimImporter = (importer) => importer && path.resolve(importer).startsWith(SHIM + path.sep);

const rustShims = {
  name: 'tl-rust-shims',
  setup(build) {
    build.onResolve({ filter: /^legacy-wallet-utils$/ }, () => ({
      path: path.join(ROOT, 'lib', 'walletUtils.js'),
    }));
    build.onResolve({ filter: /^legacy-store$/ }, () => ({
      path: path.join(ROOT, 'store', 'store.js'),
    }));
    build.onResolve({ filter: /(^|\/)walletUtils(\.js)?$/ }, (args) => {
      if (isShimImporter(args.importer)) return null;
      return { path: path.join(SHIM, 'walletUtils.js') };
    });
    build.onResolve({ filter: /(^|\/)lib\/vault(\.js)?$|^\.\/vault(\.js)?$/ }, (args) => {
      if (isShimImporter(args.importer)) return null;
      return { path: path.join(SHIM, 'vault.js') };
    });
  },
};

const nodePolyfills = {
  name: 'node-polyfills',
  setup(build) {
    build.onResolve({ filter: /^stream$/ }, () => ({ path: requireFrom.resolve('stream-browserify') }));
    build.onResolve({ filter: /^stream\/transform$/ }, () => ({ path: requireFrom.resolve('stream-browserify/transform') }));
    build.onResolve({ filter: /^cipher-base$/ }, () => ({ path: requireFrom.resolve('cipher-base') }));
    build.onResolve({ filter: /^buffer$/ }, () => ({ path: requireFrom.resolve('buffer/') }));
    build.onResolve({ filter: /^vm$/ }, () => ({ path: requireFrom.resolve('vm-browserify') }));
    build.onResolve({ filter: /^events$/ }, () => ({ path: requireFrom.resolve('events/') }));
  },
};

await esbuild.build({
  entryPoints: [path.join(ROOT, 'popup', 'popup.js')],
  bundle: true,
  outfile: path.join(outDir, 'dist', 'bundle.js'),
  minify: true,
  platform: 'browser',
  format: 'esm',
  external: ['stream', 'buffer', 'process'],
  nodePaths: [nodeModules],
  plugins: [rustShims, nodePolyfills, wasmPlugin()],
  target: 'esnext',
  inject: [
    requireFrom.resolve('stream-browserify'),
    requireFrom.resolve('process/browser'),
    path.join(ROOT, 'shims', 'global.js'),
    path.join(ROOT, 'shims', 'process-polyfill.js'),
    path.join(nodeModules, 'buffer', 'index.js'),
    path.join(nodeModules, 'events', 'events.js'),
  ],
  loader: { '.js': 'jsx', '.wasm': 'binary', '.png': 'dataurl' },
  sourcemap: true,
  logLevel: 'info',
});

console.log(`EXTENSION_BUILD_OK ${outDir}`);
