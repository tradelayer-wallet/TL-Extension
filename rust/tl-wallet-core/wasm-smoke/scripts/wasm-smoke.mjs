// Loads the wasm32 build of tl-wallet-core-wasm-smoke and checks results against the
// native test vectors in tests/address_message.rs. Usage: node wasm-smoke.mjs <file.wasm>
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const bytes = readFileSync(process.argv[2]);
const { instance } = await WebAssembly.instantiate(bytes, {});
const w = instance.exports;
const mem = () => new Uint8Array(w.memory.buffer);
const enc = new TextEncoder();
const dec = new TextDecoder();

function withBytes(data, fn) {
  const p = w.tlw_alloc(data.length);
  assert.notEqual(p, 0);
  mem().set(data, p);
  try { return fn(p, data.length); } finally { w.tlw_free(p, data.length); }
}

const LTC_TEST = 1, LTC = 0;
const good = 'tltc1q6rz28mcfaxtmd6v789l9rrlrusdprr9pesrjxk';
const check = (net, s) => withBytes(enc.encode(s), (p, n) => w.tlw_validate_address(net, p, n));

assert.equal(check(LTC_TEST, good), 1);
assert.equal(check(LTC_TEST, good.toUpperCase()), 1);
assert.equal(check(LTC_TEST, 'T' + good.slice(1)), 0);          // mixed case
assert.equal(check(LTC_TEST, good.slice(0, -1) + 'q'), 0);      // bad checksum
assert.equal(check(LTC, good), 0);                               // wrong network
assert.equal(check(99, good), -1);                               // unknown network

function mnemonic(entropy) {
  return withBytes(entropy, (ep) => {
    const cap = 256;
    const out = w.tlw_alloc(cap);
    try {
      const n = w.tlw_mnemonic(ep, out, cap);
      assert.ok(n > 0);
      return dec.decode(mem().slice(out, out + n));
    } finally { w.tlw_free(out, cap); }
  });
}
assert.equal(mnemonic(new Uint8Array(16)),
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
assert.equal(mnemonic(new Uint8Array(16).fill(0xff)),
  'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');

console.log('WASM_SMOKE_OK', bytes.length, 'bytes');
