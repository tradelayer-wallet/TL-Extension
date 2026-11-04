// Runs the built wasm core under Node with an in-memory Storage: the same ABI, JS host
// functions and vault paths the popup uses, without a browser.
//   node scripts/core-node-test.mjs <path to tl_extension_wasm.wasm>
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { webcrypto } from 'node:crypto';
import { createCore } from '../shim/core-factory.mjs';

const wasmPath = process.argv[2];
if (!wasmPath) throw new Error('usage: core-node-test.mjs <tl_extension_wasm.wasm>');

class MemStorage {
  constructor() { this.m = new Map(); }
  get length() { return this.m.size; }
  key(i) { return [...this.m.keys()][i] ?? null; }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
}

// Fixture from rust/tl-wallet-core/tests/fixtures/vault_legacy_vectors.txt (crypto-js 4.2.0):
// the public BIP-39 phrase "abandon ... about" under the password "correct horse battery staple".
const LEGACY_BLOB = 'U2FsdGVkX18Ilk95oR6SPnbycD/2lt2Q+gAe116q0xvdvgurgmnQNJUR0Jt4+nSgpl4u98r/Eopm8PC4O/b37e77jw0PIcP0lWE7OLUjHrO35Dd1SmwlaCyhZAoTkypm2KISXsIAFEgVH9w3s1g3sQ==';
const LEGACY_PASSWORD = 'correct horse battery staple';
const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const boot = async (storage) =>
  createCore({ wasm: fs.readFileSync(wasmPath), storage, crypto: webcrypto });

// 1. native vault: generate, create, unlock, sign, wrong password
{
  const storage = new MemStorage();
  const { call } = await boot(storage);
  assert.equal(call({ op: 'status' }).exists, false);
  const gen = call({ op: 'generate_mnemonic' });
  assert.equal(gen.ok, true);
  assert.equal(gen.phrase.split(' ').length, 12);
  assert.equal(call({ op: 'create', phrase: gen.phrase, password: 'pw-js' }).ok, true);
  assert.ok(storage.getItem('vault.v1').startsWith('tlvault:'));
  assert.equal(storage.getItem('encryptedSeed'), null);
  const u = call({ op: 'unlock', password: 'pw-js', network: 'LTCTEST' });
  assert.equal(u.ok, true);
  assert.match(u.address, /^tltc1q/);
  assert.equal(call({ op: 'unlock', password: 'nope', network: 'LTCTEST' }).code, 'WrongPasswordOrTampered');
  const s = call({ op: 'sign_message', password: 'pw-js', network: 'LTCTEST', origin: 'http://127.0.0.1:4181', message: 'hi' });
  assert.equal(s.ok, true);
  assert.equal(Buffer.from(s.signature, 'base64').length, 65);
  assert.equal(s.address, u.address);
  // every response is plain data: no key material field
  assert.ok(!JSON.stringify(u).includes('private'));
}

// 2. legacy crypto-js blob in localStorage opens, then is migrated in place
{
  const storage = new MemStorage();
  storage.setItem('encryptedSeed', LEGACY_BLOB);
  storage.setItem('encryptedKey', 'cached-junk');
  storage.setItem('unrelated', 'kept');
  const { call } = await boot(storage);
  const st = call({ op: 'status' });
  assert.deepEqual([st.exists, st.source], [true, 'legacy']);
  assert.equal(call({ op: 'unlock', password: 'wrong-28', network: 'LTC' }).ok, false);
  assert.equal(storage.getItem('encryptedSeed'), LEGACY_BLOB);
  const u = call({ op: 'unlock', password: LEGACY_PASSWORD, network: 'LTCTEST' });
  assert.equal(u.ok, true);
  assert.equal(u.migration.phase, 'Retired');
  assert.equal(storage.getItem('encryptedSeed'), null);
  assert.equal(storage.getItem('vault.legacy_backup'), LEGACY_BLOB);
  assert.equal(storage.getItem('unrelated'), 'kept');
  assert.equal(call({ op: 'expose_seed', password: LEGACY_PASSWORD }).phrase, ABANDON);
  assert.equal(call({ op: 'status' }).source, 'sealed');
}

// 3. a store whose compare-and-swap fails stops the write and reports it
{
  const storage = new MemStorage();
  const { call } = await boot(storage);
  const orig = storage.setItem.bind(storage);
  storage.setItem = () => { throw new Error('quota'); };
  const r = call({ op: 'create', phrase: ABANDON, password: 'x' });
  assert.equal(r.ok, false);
  storage.setItem = orig;
  assert.equal(storage.getItem('vault.v1'), null);
}

// 4. malformed requests
{
  const { call } = await boot(new MemStorage());
  assert.equal(call({}).ok, false);
  assert.equal(call({ op: 'sign_message', password: 'x', network: 'LTCTEST', message: 'm' }).ok, false);
}

console.log('CORE_NODE_TEST_OK');
