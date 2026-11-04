// Drives the built extension in Chrome for Testing over CDP (Node 24, no dependencies beyond
// the signature check in the install given by --node-modules):
//   create wallet, import wallet, unlock (testnet address view), legacy crypto-js vault
//   import + migration, and provider requests from a local page: connect, signMessage,
//   signPsbt, signTransaction. Synthetic keys only; the browser resolver is blocked for every
//   host except loopback, so nothing leaves the machine.
//
//   node e2e-browser.mjs --chrome <chrome.exe> --ext <unpacked dir> --node-modules <dir> --profile <scratch dir>
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import path from 'node:path';

const arg = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0 || !process.argv[i + 1]) throw new Error(`missing --${name}`);
  return process.argv[i + 1];
};
const chromeExe = arg('chrome');
const extDir = path.resolve(arg('ext'));
const nodeModules = path.resolve(arg('node-modules'));
const profile = path.resolve(arg('profile'));
const requireFrom = createRequire(path.join(nodeModules, 'noop.js'));
const { secp256k1 } = requireFrom('@noble/curves/secp256k1');

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'.split(' ');
const ABANDON_LTCTEST = 'tltc1q6rz28mcfaxtmd6v789l9rrlrusdprr9pesrjxk'; // tl-wallet-core legacy_vectors.txt
const LEGACY_BLOB = 'U2FsdGVkX18Ilk95oR6SPnbycD/2lt2Q+gAe116q0xvdvgurgmnQNJUR0Jt4+nSgpl4u98r/Eopm8PC4O/b37e77jw0PIcP0lWE7OLUjHrO35Dd1SmwlaCyhZAoTkypm2KISXsIAFEgVH9w3s1g3sQ==';
const LEGACY_PASSWORD = 'correct horse battery staple';
const PW = 'e2e-synthetic-pw-1';

const log = (...a) => console.log('[e2e]', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const sha256d = (b) => sha256(sha256(b));

// ------------------------------------------------------------------ CDP client
class Cdp {
  constructor(wsUrl) {
    this.nextId = 1;
    this.pending = new Map();
    this.handlers = [];
    this.ws = new WebSocket(wsUrl);
    this.ready = new Promise((res, rej) => {
      this.ws.addEventListener('open', res);
      this.ws.addEventListener('error', rej);
    });
    this.ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id) {
        const p = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`));
        else p.resolve(msg.result);
      } else {
        for (const h of this.handlers) h(msg);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }
  on(h) { this.handlers.push(h); }
}

const problems = [];
const dialogs = [];
let cdp;

async function attach(targetId) {
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Page.enable', {}, sessionId);
  return sessionId;
}
const evaluate = async (sid, expression) => {
  const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sid);
  if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
  return r.result.value;
};
async function waitFor(sid, expression, what, timeout = 30000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      last = await evaluate(sid, expression);
      if (last) return last;
    } catch (e) { last = e.message; }
    await sleep(150);
  }
  throw new Error(`timeout waiting for ${what} (last: ${JSON.stringify(last)})`);
}
const bodyHas = (sid, text, timeout) =>
  waitFor(sid, `document.body && document.body.innerText.includes(${JSON.stringify(text)})`, `text "${text}"`, timeout).catch(async (e) => {
    const snap = await evaluate(sid, 'document.location.href + " :: " + (document.body ? document.body.innerText.slice(0, 300) : "no body")').catch(() => '?');
    throw new Error(`${e.message}; page: ${snap}`);
  });
const clickButton = (sid, text) =>
  evaluate(sid, `(() => { const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === ${JSON.stringify(text)}); if (!b) return false; b.click(); return true; })()`)
    .then((ok) => assert.ok(ok, `button "${text}" not found`));
const setValue = (sid, selector, value) =>
  evaluate(sid, `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false;
    const proto = el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true })); return true; })()`)
    .then((ok) => assert.ok(ok, `input ${selector} not found`));
const targets = async () => (await cdp.send('Target.getTargets')).targetInfos;
const usedTargets = new Set();
async function waitPopup(substr, timeout = 30000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const t = (await targets()).find((x) => x.type === 'page' && x.url.includes(substr) && !usedTargets.has(x.targetId));
    if (t) { usedTargets.add(t.targetId); return attach(t.targetId); }
    await sleep(150);
  }
  throw new Error('timeout waiting for popup ' + substr);
}
async function waitTarget(match, timeout = 30000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const t = (await targets()).find((x) => x.type === 'page' && match(x.url));
    if (t) return t;
    await sleep(150);
  }
  throw new Error('timeout waiting for target');
}

// ------------------------------------------------------------------ helpers for checks
const bech32Chars = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function bech32Program(addr) {
  const data = addr.slice(addr.lastIndexOf('1') + 1).split('').map((c) => bech32Chars.indexOf(c));
  assert.ok(data.every((v) => v >= 0), 'bech32 chars');
  const five = data.slice(1, -6); // drop witness version and 6-char checksum
  let acc = 0, bits = 0; const out = [];
  for (const v of five) { acc = (acc << 5) | v; bits += 5; while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); } }
  return Buffer.from(out);
}
const varint = (n) => (n < 0xfd ? Buffer.from([n]) : Buffer.from([0xfd, n & 255, n >> 8]));
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };

function verifyBip137(addressProgram, pubkeyHex, message, sigB64) {
  const sig = Buffer.from(sigB64, 'base64');
  assert.equal(sig.length, 65);
  const header = sig[0];
  assert.ok(header >= 39 && header <= 42, `p2wpkh header, got ${header}`);
  const magic = Buffer.from('Litecoin Signed Message:\n');
  const msg = Buffer.from(message);
  const digest = sha256d(Buffer.concat([varint(magic.length), magic, varint(msg.length), msg]));
  const s = secp256k1.Signature.fromCompact(sig.subarray(1).toString('hex')).addRecoveryBit(header - 39);
  const recovered = Buffer.from(s.recoverPublicKey(digest).toRawBytes(true)).toString('hex');
  assert.equal(recovered, pubkeyHex, 'recovered key is the account key');
  assert.ok(secp256k1.verify(s.toCompactHex(), digest, pubkeyHex));
}

function buildPsbtHex(ownProgram, valueSats) {
  const ownScript = Buffer.concat([Buffer.from([0x00, 0x14]), ownProgram]);
  const destScript = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 0x44)]);
  const prevTxid = Buffer.alloc(32, 0x33);
  const outValue = valueSats - 10000;
  const tx = Buffer.concat([
    u32(2), varint(1), prevTxid, u32(0), varint(0), u32(0xffffffff),
    varint(1), u64(outValue), varint(destScript.length), destScript, u32(0),
  ]);
  const utxo = Buffer.concat([u64(valueSats), varint(ownScript.length), ownScript]);
  const kv = (key, val) => Buffer.concat([varint(key.length), key, varint(val.length), val]);
  const psbt = Buffer.concat([
    Buffer.from('70736274ff', 'hex'),
    kv(Buffer.from([0x00]), tx), Buffer.from([0x00]),
    kv(Buffer.from([0x01]), utxo), Buffer.from([0x00]),
    Buffer.from([0x00]),
  ]);
  return { hex: psbt.toString('hex'), prevTxid, outValue, destScript, ownScript };
}

function verifySignedTx(rawHex, ctx, pubkeyHex, ownProgram, valueSats, txid) {
  const raw = Buffer.from(rawHex, 'hex');
  assert.equal(raw.readUInt32LE(0), 2, 'version 2');
  assert.deepEqual([...raw.subarray(4, 6)], [0, 1], 'segwit marker and flag');
  let o = 6;
  assert.equal(raw[o++], 1, 'one input');
  assert.ok(raw.subarray(o, o + 32).equals(ctx.prevTxid), 'spends the supplied outpoint');
  o += 36;
  assert.equal(raw[o++], 0, 'empty scriptSig');
  o += 4;
  const nout = raw[o++];
  for (let i = 0; i < nout; i += 1) { o += 8; const l = raw[o++]; o += l; }
  const witnessStart = o;
  assert.equal(raw[o++], 2, 'two witness items');
  const sl = raw[o++];
  const sigAll = raw.subarray(o, o + sl); o += sl;
  const pl = raw[o++];
  const pub = raw.subarray(o, o + pl); o += pl;
  assert.equal(pub.toString('hex'), pubkeyHex, 'witness carries the account pubkey');
  assert.equal(sigAll[sigAll.length - 1], 0x01, 'SIGHASH_ALL');
  const der = sigAll.subarray(0, -1);
  const lockTime = raw.readUInt32LE(o);
  assert.equal(lockTime, 0);
  assert.equal(o + 4, raw.length);
  const stripped = Buffer.concat([raw.subarray(0, 4), raw.subarray(6, witnessStart), raw.subarray(o, o + 4)]);
  assert.equal(Buffer.from(sha256d(stripped)).reverse().toString('hex'), txid, 'txid matches the transaction');
  const outpoint = Buffer.concat([ctx.prevTxid, u32(0)]);
  const outputs = Buffer.concat([u64(ctx.outValue), varint(ctx.destScript.length), ctx.destScript]);
  const scriptCode = Buffer.concat([Buffer.from([0x19, 0x76, 0xa9, 0x14]), ownProgram, Buffer.from([0x88, 0xac])]);
  assert.equal(nout, 1);
  const preimage = Buffer.concat([u32(2), sha256d(outpoint), sha256d(u32(0xffffffff)), outpoint, scriptCode, u64(valueSats), u32(0xffffffff), sha256d(outputs), u32(0), u32(1)]);
  const sighash = sha256d(preimage);
  assert.ok(secp256k1.verify(secp256k1.Signature.fromDER(der.toString('hex')), sighash, pubkeyHex), 'BIP143 signature verifies');
}

// ------------------------------------------------------------------ local test page
const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'text/html');
  res.end('<!doctype html><title>provider test page</title><body>TradeLayer provider test page</body>');
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const pagePort = server.address().port;
const pageOrigin = `http://127.0.0.1:${pagePort}`;

// ------------------------------------------------------------------ launch Chrome for Testing
fs.rmSync(profile, { recursive: true, force: true });
fs.mkdirSync(profile, { recursive: true });
const chrome = spawn(chromeExe, [
  `--user-data-dir=${profile}`,
  '--remote-debugging-port=0',
  `--load-extension=${extDir}`,
  `--disable-extensions-except=${extDir}`,
  '--headless=new',
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-background-networking',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1',
  'about:blank',
], { stdio: 'ignore' });
let exited = false;
chrome.on('exit', () => { exited = true; });

const portFile = path.join(profile, 'DevToolsActivePort');
for (let i = 0; i < 100 && !fs.existsSync(portFile); i += 1) await sleep(200);
assert.ok(fs.existsSync(portFile), 'Chrome did not start');
const [port, wsPath] = fs.readFileSync(portFile, 'utf8').trim().split(/\r?\n/);
cdp = new Cdp(`ws://127.0.0.1:${port}${wsPath}`);
await cdp.ready;
cdp.on((msg) => {
  if (msg.method === 'Page.javascriptDialogOpening') {
    dialogs.push(msg.params.message);
    log('dialog:', msg.params.message);
    cdp.send('Page.handleJavaScriptDialog', { accept: true }, msg.sessionId).catch(() => {});
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    const d = msg.params.exceptionDetails;
    problems.push(`${d.text} ${d.exception?.description || ''}`.slice(0, 300));
  }
});

async function main() {
  // extension id from the service worker target
  let sw;
  for (let i = 0; i < 100 && !sw; i += 1) {
    sw = (await targets()).find((t) => t.type === 'service_worker' && t.url.includes('/background/background.js'));
    if (!sw) await sleep(200);
  }
  assert.ok(sw, 'service worker not found: extension did not load');
  const extId = new URL(sw.url).host;
  const popupUrl = `chrome-extension://${extId}/popup/popup.html`;
  log('extension id', extId);

  const open = async (url) => {
    const { targetId } = await cdp.send('Target.createTarget', { url });
    return { targetId, sid: await attach(targetId) };
  };

  // -------------------------------------------------- 1. create wallet through the original UI
  let { sid: pop } = await open(popupUrl);
  await bodyHas(pop, 'Step 1: Generate Seed Phrase');
  await clickButton(pop, 'Generate Seed Phrase');
  await bodyHas(pop, 'Your Seed Phrase');
  const words = await evaluate(pop, `[...document.querySelectorAll('.seed-word')].map(e => e.textContent)`);
  assert.equal(words.length, 12);
  await clickButton(pop, 'Next');
  await bodyHas(pop, 'Step 3: Confirm Seed Phrase');
  await clickButton(pop, 'Confirm');
  await bodyHas(pop, 'Set Up Your Password');
  await setValue(pop, '#password', PW);
  await setValue(pop, '#confirmPassword', PW);
  // The submit handlers run synchronously inside the click, so the click call spans the Rust work.
  let t0 = Date.now();
  await clickButton(pop, 'Submit');
  const tCreate = Date.now() - t0;
  await waitFor(pop, `!!document.querySelector('.password-prompt-select')`, 'password prompt');
  await setValue(pop, '.password-prompt-select', 'LTCTEST');
  await setValue(pop, '.password-prompt-input', PW);
  t0 = Date.now();
  await clickButton(pop, 'Submit');
  const tUnlock = Date.now() - t0;
  await bodyHas(pop, 'Balance and Positions');
  const created = await waitFor(pop, `document.querySelector('.wallet-text')?.title || ''`, 'address view');
  log(`timing in headless Chrome (scrypt N=2^15 inside the page): create vault click ${tCreate} ms, unlock click ${tUnlock} ms`);
  assert.match(created, /^tltc1q[a-z0-9]{38}$/);
  log('create: testnet address view', created);

  let storage = await evaluate(pop, `JSON.stringify(Object.fromEntries(Object.entries(localStorage)))`).then(JSON.parse);
  assert.ok(storage['vault.v1'].startsWith('tlvault:'), 'sealed vault written');
  assert.equal(storage.encryptedSeed, undefined, 'no legacy blob for a new wallet');
  assert.match(storage['vault.record'], /^tlrec1;/);
  log('record', storage['vault.record']);
  const everything = JSON.stringify(storage) + JSON.stringify(await evaluate(pop, `new Promise(r => chrome.storage.local.get(null, r))`));
  for (const w of new Set(words)) assert.ok(!everything.includes(`"${w}"`) && !everything.includes(` ${w} `), 'no plaintext seed word in storage');
  const scan = everything.replace(/"vault\.v1":"[^"]*"/, '');
  assert.ok(!/(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/.test(scan), 'no 32-byte hex key in storage (66-hex public keys are fine)');
  assert.ok(!/[A-Za-z0-9+/]{43}=/.test(scan), 'no base64 32-byte key cache in storage');
  assert.equal(storage.encryptedKey, '', 'unlock caches no derived key');
  log('create: storage holds only the sealed vault; keys:', Object.keys(storage).join(', '));

  // wrong password on unlock is refused
  await evaluate(pop, `localStorage.removeItem('encryptedKey'); true`);
  await open(popupUrl).then(async ({ sid }) => {
    await waitFor(sid, `!!document.querySelector('.password-prompt-select')`, 'prompt');
    await setValue(sid, '.password-prompt-select', 'LTCTEST');
    await setValue(sid, '.password-prompt-input', 'not-the-password');
    await clickButton(sid, 'Submit');
    await waitFor(sid, 'true', 'wrong password dialog');
    await sleep(500);
  });
  assert.ok(dialogs.some((d) => d.includes('Incorrect password or corrupted data')), 'wrong password is refused with the legacy alert');
  log('unlock: wrong password refused');

  // -------------------------------------------------- 2. import wallet (public abandon phrase) on a clean profile state
  await evaluate(pop, `localStorage.clear(); new Promise(r => chrome.storage.local.clear(r))`);
  await evaluate(pop, `location.reload(); true`).catch(() => {});
  await sleep(500);
  await bodyHas(pop, 'Step 1: Generate Seed Phrase');
  await clickButton(pop, 'Import Seed Phrase');
  await bodyHas(pop, 'Import Seed Phrase');
  for (let i = 0; i < 12; i += 1) await setValue(pop, `input[placeholder="Word ${i + 1}"]`, ABANDON[i]);
  await clickButton(pop, 'Import Seed Phrase');
  await bodyHas(pop, 'Set Up Your Password');
  await setValue(pop, '#password', PW);
  await setValue(pop, '#confirmPassword', PW);
  await clickButton(pop, 'Submit');
  await waitFor(pop, `!!document.querySelector('.password-prompt-select')`, 'password prompt (import)');
  await setValue(pop, '.password-prompt-select', 'LTCTEST');
  await setValue(pop, '.password-prompt-input', PW);
  await clickButton(pop, 'Submit');
  await bodyHas(pop, 'Balance and Positions');
  const imported = await waitFor(pop, `document.querySelector('.wallet-text')?.title || ''`, 'address view (import)');
  assert.equal(imported, ABANDON_LTCTEST, 'imported phrase derives the known testnet address');
  log('import: testnet address view', imported);

  // an invalid phrase (bad checksum) is refused at password setup
  await evaluate(pop, `localStorage.clear(); new Promise(r => chrome.storage.local.clear(r))`);
  await evaluate(pop, `location.reload(); true`).catch(() => {});
  await sleep(500);
  await bodyHas(pop, 'Step 1: Generate Seed Phrase');
  await clickButton(pop, 'Import Seed Phrase');
  for (let i = 0; i < 12; i += 1) await setValue(pop, `input[placeholder="Word ${i + 1}"]`, 'abandon');
  await clickButton(pop, 'Import Seed Phrase');
  await bodyHas(pop, 'Set Up Your Password');
  await setValue(pop, '#password', PW);
  await setValue(pop, '#confirmPassword', PW);
  const before = dialogs.length;
  await clickButton(pop, 'Submit');
  await waitFor(pop, `true`, 'dialog');
  await sleep(500);
  assert.ok(dialogs.slice(before).some((d) => d.includes('not a valid 12-word BIP-39 phrase')), 'invalid checksum phrase refused');
  assert.equal(await evaluate(pop, `localStorage.getItem('vault.v1')`), null);
  log('import: invalid phrase refused, nothing stored');

  // -------------------------------------------------- 3. legacy crypto-js vault opens and migrates
  await evaluate(pop, `localStorage.clear(); new Promise(r => chrome.storage.local.clear(r))`);
  await evaluate(pop, `localStorage.setItem('encryptedSeed', ${JSON.stringify(LEGACY_BLOB)}); location.reload(); true`).catch(() => {});
  await sleep(500);
  await waitFor(pop, `!!document.querySelector('.password-prompt-select')`, 'password prompt routed from legacy vault');
  await setValue(pop, '.password-prompt-select', 'LTCTEST');
  await setValue(pop, '.password-prompt-input', LEGACY_PASSWORD);
  await clickButton(pop, 'Submit');
  await bodyHas(pop, 'Balance and Positions');
  const legacy = await waitFor(pop, `document.querySelector('.wallet-text')?.title || ''`, 'address view (legacy)');
  assert.equal(legacy, ABANDON_LTCTEST, 'legacy vault opens to the same address');
  storage = await evaluate(pop, `JSON.stringify(Object.fromEntries(Object.entries(localStorage)))`).then(JSON.parse);
  assert.equal(storage.encryptedSeed, undefined, 'legacy blob retired');
  assert.equal(storage['vault.legacy_backup'], LEGACY_BLOB, 'legacy blob kept as backup');
  assert.ok(storage['vault.v1'].startsWith('tlvault:'));
  assert.match(storage['vault.record'], /^tlrec1;retired/i);
  log('legacy: opened and migrated in place; record', storage['vault.record'].slice(0, 20));

  // -------------------------------------------------- 4. provider requests from a local page
  const { sid: page } = await open(pageOrigin + '/');
  await waitFor(page, `!!window.tradelayer`, 'injected provider');
  await evaluate(page, `window.__connect = window.tradelayer.connect('LTCTEST').then(r => ({ ok: true, r }), e => ({ ok: false, e: String(e.message || e) })); true`);
  const approval = await waitPopup('popup/popup.html?step=17');
  await bodyHas(approval, 'Connect Site');
  assert.ok((await evaluate(approval, 'document.body.innerText')).includes(pageOrigin));
  await clickButton(approval, 'Approve');
  const connected = await evaluate(page, `window.__connect`);
  assert.equal(connected.ok, true, JSON.stringify(connected));
  const account = connected.r[0];
  assert.equal(account.address, ABANDON_LTCTEST);
  assert.match(account.pubkey, /^0[23][0-9a-f]{64}$/);
  log('provider: connect approved, account', account.address);
  const program = bech32Program(account.address);

  // signMessage
  const message = 'hello from the e2e page';
  await evaluate(page, `window.__sign = window.tradelayer.request({ method: 'signMessage', params: { network: 'LTCTEST', message: ${JSON.stringify(message)} } }).then(r => ({ ok: true, r }), e => ({ ok: false, e: String(e.message || e) })); true`);
  let sidSign = await waitPopup('popup/popup.html?step=13');
  await bodyHas(sidSign, 'Sign Message');
  assert.ok((await evaluate(sidSign, 'document.body.innerText')).includes(message));
  await setValue(sidSign, '#password', LEGACY_PASSWORD);
  await clickButton(sidSign, 'Approve');
  const signed = await evaluate(page, `window.__sign`);
  assert.equal(signed.ok, true, JSON.stringify(signed));
  verifyBip137(program, account.pubkey, message, signed.r);
  log('provider: signMessage returned a BIP-137 signature that recovers the account key');

  // signMessage with a wrong password does not sign (popup alerts; request stays pending until closed)
  await evaluate(page, `window.__sign2 = window.tradelayer.request({ method: 'signMessage', params: { network: 'LTCTEST', message: 'second' } }).then(r => ({ ok: true, r }), e => ({ ok: false, e: String(e.message || e) })); true`);
  sidSign = await waitPopup('popup/popup.html?step=13');
  await bodyHas(sidSign, 'Sign Message');
  const dBefore = dialogs.length;
  await setValue(sidSign, '#password', 'wrong-password');
  await clickButton(sidSign, 'Approve');
  await sleep(800);
  assert.ok(dialogs.slice(dBefore).some((d) => d.includes('Invalid password')), 'wrong password blocks signing');
  await clickButton(sidSign, 'Reject');
  const rejected = await evaluate(page, `window.__sign2`);
  assert.equal(rejected.ok, false);
  log('provider: wrong password refused, reject propagates:', rejected.e);

  // signPsbt
  const valueSats = 100_000_000;
  const psbt = buildPsbtHex(program, valueSats);
  await evaluate(page, `window.__psbt = window.tradelayer.request({ method: 'signPsbt', params: { network: 'LTCTEST', psbtHex: ${JSON.stringify(psbt.hex)} } }).then(r => ({ ok: true, r }), e => ({ ok: false, e: String(e.message || e) })); true`);
  const sidPsbt = await waitPopup('popup/popup.html?step=16');
  await bodyHas(sidPsbt, 'Sign PSBT');
  await bodyHas(sidPsbt, 'Estimated Fee');
  await setValue(sidPsbt, '#password', LEGACY_PASSWORD);
  await clickButton(sidPsbt, 'Approve');
  const psbtRes = await evaluate(page, `window.__psbt`);
  assert.equal(psbtRes.ok, true, JSON.stringify(psbtRes));
  assert.equal(psbtRes.r.isFinished, true);
  verifySignedTx(psbtRes.r.rawTx, psbt, account.pubkey, program, valueSats, psbtRes.r.txid);
  assert.match(psbtRes.r.txid, /^[0-9a-f]{64}$/);
  log('provider: signPsbt returned a final transaction whose BIP143 signature verifies; txid', psbtRes.r.txid);

  // signTransaction (legacy payload shape)
  const ownScriptHex = psbt.ownScript.toString('hex');
  const txPayload = {
    fromKeyPair: { address: account.address },
    toKeyPair: { address: account.address },
    amount: 0.1,
    inputs: [{ txid: '55'.repeat(32), vout: 1, amount: 1, scriptPubKey: ownScriptHex, confirmations: 3 }],
  };
  await evaluate(page, `window.__tx = window.tradelayer.request({ method: 'signTransaction', params: { network: 'LTCTEST', transaction: ${JSON.stringify(txPayload)} } }).then(r => ({ ok: true, r }), e => ({ ok: false, e: String(e.message || e) })); true`);
  const sidTx = await waitPopup('popup/popup.html?step=13');
  await bodyHas(sidTx, 'Review Legacy Transaction');
  await setValue(sidTx, '#password', LEGACY_PASSWORD);
  await clickButton(sidTx, 'Approve');
  const txRes = await evaluate(page, `window.__tx`);
  assert.equal(txRes.ok, true, JSON.stringify(txRes));
  assert.match(txRes.r.rawTx, /^02000000000101/);
  assert.match(txRes.r.txid, /^[0-9a-f]{64}$/);
  log('provider: signTransaction returned a signed legacy-shape transaction; txid', txRes.r.txid);

  // -------------------------------------------------- 5. settings: expose seed, reset password
  const { sid: pop2 } = await open(popupUrl);
  await waitFor(pop2, `!!document.querySelector('.password-prompt-select')`, 'prompt');
  await setValue(pop2, '.password-prompt-select', 'LTCTEST');
  await setValue(pop2, '.password-prompt-input', LEGACY_PASSWORD);
  await clickButton(pop2, 'Submit');
  await bodyHas(pop2, 'Balance and Positions');
  await waitFor(pop2, `!!document.querySelector('.settings-button button')`, 'settings button');
  await evaluate(pop2, `document.querySelector('.settings-button button').click(); true`);
  await bodyHas(pop2, 'Settings');
  await clickButton(pop2, 'Expose Seed Phrase');
  await bodyHas(pop2, 'Your Seed Phrase');
  const dBeforeSeed = dialogs.length;
  await setValue(pop2, '#password', 'wrong-password');
  await clickButton(pop2, 'Submit');
  await sleep(500);
  assert.ok(dialogs.slice(dBeforeSeed).some((d) => d.includes('Incorrect password')), 'expose seed refuses a wrong password');
  await setValue(pop2, '#password', LEGACY_PASSWORD);
  await clickButton(pop2, 'Submit');
  const shown = await waitFor(pop2, `(() => { const w = [...document.querySelectorAll('.seed-word')].map(e => e.textContent); return w.length === 12 ? w : null; })()`, 'seed words');
  assert.deepEqual(shown, ABANDON);
  log('settings: expose seed shows the phrase only after the right password');
  await clickButton(pop2, 'Next');
  await bodyHas(pop2, 'Settings');
  await clickButton(pop2, 'Reset Password');
  await bodyHas(pop2, 'Current Password');
  await setValue(pop2, '#currentPassword', LEGACY_PASSWORD);
  await setValue(pop2, '#newPassword', 'new-synthetic-pw-2');
  await setValue(pop2, '#confirmNewPassword', 'new-synthetic-pw-2');
  const dBeforeReset = dialogs.length;
  await clickButton(pop2, 'Reset Password');
  await sleep(1500);
  assert.ok(dialogs.slice(dBeforeReset).some((d) => d.includes('Password has been reset successfully')), 'password reset succeeds');
  const { sid: pop3 } = await open(popupUrl);
  await waitFor(pop3, `!!document.querySelector('.password-prompt-select')`, 'prompt after reset');
  await setValue(pop3, '.password-prompt-select', 'LTCTEST');
  const dBeforeOld = dialogs.length;
  await setValue(pop3, '.password-prompt-input', LEGACY_PASSWORD);
  await clickButton(pop3, 'Submit');
  await sleep(1200);
  assert.ok(dialogs.slice(dBeforeOld).some((d) => d.includes('Incorrect password or corrupted data')), 'old password no longer opens the vault');
  await setValue(pop3, '.password-prompt-input', 'new-synthetic-pw-2');
  await clickButton(pop3, 'Submit');
  await bodyHas(pop3, 'Balance and Positions');
  assert.equal(await waitFor(pop3, `document.querySelector('.wallet-text')?.title || ''`, 'address after reset'), ABANDON_LTCTEST);
  log('settings: password reset re-seals the vault; old password refused, new password opens it');

  log('E2E_OK');
}

let failure = null;
try { await main(); } catch (e) { failure = e; }
if (problems.length) log('page exceptions seen:', problems.slice(0, 5));
try { await cdp.send('Browser.close'); } catch { /* closing */ }
await sleep(500);
if (!exited) chrome.kill();
server.close();
if (failure) { console.error(failure); process.exit(1); }
