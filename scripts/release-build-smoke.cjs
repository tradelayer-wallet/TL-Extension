const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const packageManifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
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

const build = (mode) => {
  execFileSync(process.execPath, ['build.js', `--mode=${mode}`], {
    cwd: ROOT,
    stdio: 'inherit',
  });

  const suffix = mode === 'development' ? '-dev' : '';
  return path.join(ROOT, 'artifacts', `tl-extension-${packageManifest.version}${suffix}`);
};

const readPackage = (directory) => ({
  manifest: JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8')),
  background: fs.readFileSync(path.join(directory, 'background', 'background.js'), 'utf8'),
});

const release = readPackage(build('release'));
assert.deepEqual(release.manifest.content_scripts[0].matches, RELEASE_MATCHES);
assert.deepEqual(release.manifest.web_accessible_resources[0].matches, RELEASE_MATCHES);
assert.ok(release.manifest.content_scripts[0].matches.every((match) => match.startsWith('https://')));
assert.match(release.background, /const ALLOW_DEVELOPMENT_ORIGINS = false;/);

const development = readPackage(build('development'));
assert.deepEqual(development.manifest.content_scripts[0].matches, DEVELOPMENT_MATCHES);
assert.deepEqual(development.manifest.web_accessible_resources[0].matches, DEVELOPMENT_MATCHES);
assert.match(development.background, /const ALLOW_DEVELOPMENT_ORIGINS = true;/);

console.log('[unit] release build origin policy smoke test passed');
