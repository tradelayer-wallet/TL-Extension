const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const esbuild = require('esbuild');
const wasmPlugin = require('esbuild-plugin-wasm').default;

const ROOT = __dirname;
const ARTIFACTS_DIR = path.join(ROOT, 'artifacts');
const BUILD_LOCK_PATH = path.join(ARTIFACTS_DIR, '.build.lock');
const RELEASE_MATCHES = [
  'https://layerwallet.com/*',
  'https://www.layerwallet.com/*',
  'https://testnet.layerwallet.com/*',
];
const DEVELOPMENT_MATCHES = [
  ...RELEASE_MATCHES,
  'http://localhost/*',
  'http://127.0.0.1/*',
];
const PACKAGE_PATHS = [
  'background',
  'contentScript.js',
  'dist',
  'images',
  'lib/networks.js',
  'options.html',
  'popup',
  'readyPromise.js',
  'rules.json',
  'styles.css',
  'window.js',
];

const modeFlag = process.argv.find((arg) => arg.startsWith('--mode='));
const mode = modeFlag ? modeFlag.slice('--mode='.length) : 'release';
const skipBundle = process.argv.includes('--skip-bundle');

if (!['release', 'development'].includes(mode)) {
  throw new Error(`Unsupported build mode: ${mode}`);
}

const ensureDir = (directory) => fs.mkdirSync(directory, { recursive: true });

const acquireBuildLock = () => {
  ensureDir(ARTIFACTS_DIR);

  try {
    return fs.openSync(BUILD_LOCK_PATH, 'wx');
  } catch (error) {
    if (error?.code === 'EEXIST') {
      throw new Error('Another extension package build is already running. Wait for it to finish.');
    }
    throw error;
  }
};

const releaseBuildLock = (lock) => {
  fs.closeSync(lock);
  fs.rmSync(BUILD_LOCK_PATH, { force: true });
};

const copyPackageSources = (outputDir) => {
  for (const relativePath of PACKAGE_PATHS) {
    fs.cpSync(path.join(ROOT, relativePath), path.join(outputDir, relativePath), {
      recursive: true,
    });
  }
};

const writeManifest = (outputDir, matches) => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  manifest.content_scripts[0].matches = matches;
  manifest.web_accessible_resources[0].matches = matches;
  fs.writeFileSync(
    path.join(outputDir, 'manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`
  );
};

const configureBackground = (outputDir, development) => {
  const backgroundPath = path.join(outputDir, 'background', 'background.js');
  const source = fs.readFileSync(backgroundPath, 'utf8');
  const flag = 'const ALLOW_DEVELOPMENT_ORIGINS = false;';

  if (!source.includes(flag)) {
    throw new Error('Background development-origin marker is missing.');
  }

  fs.writeFileSync(
    backgroundPath,
    source.replace(flag, `const ALLOW_DEVELOPMENT_ORIGINS = ${development};`)
  );
};

const buildPopup = async (outputDir) => {
  await esbuild.build({
    entryPoints: [path.join(ROOT, 'popup', 'popup.js')],
    bundle: true,
    outfile: path.join(outputDir, 'dist', 'bundle.js'),
    minify: true,
    platform: 'browser',
    format: 'esm',
    external: ['stream', 'buffer', 'process'],
    plugins: [
      {
        name: 'node-polyfills',
        setup(build) {
          build.onResolve({ filter: /^stream$/ }, () => ({ path: require.resolve('stream-browserify') }));
          build.onResolve({ filter: /^stream\/transform$/ }, () => ({ path: require.resolve('stream-browserify/transform') }));
          build.onResolve({ filter: /^cipher-base$/ }, () => ({ path: require.resolve('cipher-base') }));
          build.onResolve({ filter: /^buffer$/ }, () => ({ path: require.resolve('buffer/') }));
          build.onResolve({ filter: /^vm$/ }, () => ({ path: require.resolve('vm-browserify') }));
          build.onResolve({ filter: /^events$/ }, () => ({ path: require.resolve('events/') }));
        },
      },
      wasmPlugin(),
    ],
    target: 'esnext',
    inject: [
      require.resolve('stream-browserify'),
      require.resolve('process/browser'),
      path.join(ROOT, 'shims', 'global.js'),
      path.join(ROOT, 'shims', 'process-polyfill.js'),
      path.join(ROOT, 'node_modules', 'buffer', 'index.js'),
      path.join(ROOT, 'node_modules', 'events', 'events.js'),
    ],
    loader: {
      '.js': 'jsx',
      '.wasm': 'binary',
      '.png': 'dataurl',
    },
    sourcemap: true,
    logLevel: 'info',
  });
};

const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0);
  }
  return value >>> 0;
});

const crc32 = (buffer) => {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value = (value >>> 8) ^ crcTable[(value ^ byte) & 0xff];
  }
  return (value ^ 0xffffffff) >>> 0;
};

const zipPackage = (sourceDir, archivePath) => {
  const files = [];
  const collect = (directory) => {
    const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
      a.name === b.name ? 0 : a.name < b.name ? -1 : 1
    );
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        collect(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  };

  collect(sourceDir);
  const localRecords = [];
  const centralRecords = [];
  let offset = 0;

  for (const file of files) {
    const name = path.relative(sourceDir, file).replaceAll(path.sep, '/');
    const nameBuffer = Buffer.from(name);
    const data = fs.readFileSync(file);
    const compressed = zlib.deflateRawSync(data, { level: 9 });
    const checksum = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0x0021, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    local.writeUInt16LE(0, 28);
    localRecords.push(local, nameBuffer, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x0021, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuffer.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralRecords.push(central, nameBuffer);
    offset += local.length + nameBuffer.length + compressed.length;
  }

  const centralSize = centralRecords.reduce((size, record) => size + record.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  fs.writeFileSync(archivePath, Buffer.concat([...localRecords, ...centralRecords, end]));
};

const verifyReleaseManifest = (outputDir) => {
  const manifest = JSON.parse(fs.readFileSync(path.join(outputDir, 'manifest.json'), 'utf8'));
  const manifestMatches = manifest.content_scripts[0].matches;
  const resourcesMatches = manifest.web_accessible_resources[0].matches;
  const background = fs.readFileSync(path.join(outputDir, 'background', 'background.js'), 'utf8');

  if (
    JSON.stringify(manifestMatches) !== JSON.stringify(RELEASE_MATCHES) ||
    JSON.stringify(resourcesMatches) !== JSON.stringify(RELEASE_MATCHES) ||
    manifestMatches.some((match) => !match.startsWith('https://')) ||
    !background.includes('const ALLOW_DEVELOPMENT_ORIGINS = false;')
  ) {
    throw new Error('Release package origin policy validation failed.');
  }
};

const main = async () => {
  const lock = acquireBuildLock();
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
    const suffix = mode === 'development' ? '-dev' : '';
    const packageName = `tl-extension-${manifest.version}${suffix}`;
    const outputDir = path.join(ARTIFACTS_DIR, packageName);
    const archivePath = path.join(ARTIFACTS_DIR, `${packageName}.zip`);

    fs.rmSync(outputDir, { recursive: true, force: true });
    fs.rmSync(archivePath, { force: true });
    ensureDir(outputDir);
    copyPackageSources(outputDir);
    writeManifest(outputDir, mode === 'development' ? DEVELOPMENT_MATCHES : RELEASE_MATCHES);
    configureBackground(outputDir, mode === 'development');
    if (!skipBundle) {
      await buildPopup(outputDir);
    }

    if (mode === 'release') {
      verifyReleaseManifest(outputDir);
    }

    zipPackage(outputDir, archivePath);
    const archiveSize = fs.statSync(archivePath).size;
    if (archiveSize === 0) {
      throw new Error('Release archive was created empty.');
    }
    const archiveHash = crypto
      .createHash('sha256')
      .update(fs.readFileSync(archivePath))
      .digest('hex');
    console.log(`Built ${mode} extension package: ${archivePath}`);
    console.log(`SHA256: ${archiveHash}`);
  } finally {
    releaseBuildLock(lock);
  }
};

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
