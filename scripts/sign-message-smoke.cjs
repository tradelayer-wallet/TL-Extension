// Regression smoke test for signMessage (run under plain Node, offline; throwaway keys only):
//   - a message is signed as the network's signed message (Bitcoin Core signmessage / BIP-137): a 65-byte
//     recoverable signature, base64, over sha256d(messagePrefix || varint(len) || message), recovering to the key
//   - a message can never be a transaction signature. The fixture below is a spend of the wallet's UTXO whose
//     nLockTime was ground until sha256(BIP143 preimage) is valid UTF-8; signing sha256(message) directly (an earlier
//     version of signMessage) returned a valid witness signature for that spend
//   - the header byte names the wallet's address type (P2WPKH on BIP84 paths, compressed P2PKH on BIP44)
// walletUtils.js is bundled from the real source. The only substitution is the key-cache lookup, which is replaced by
// a hook that returns a throwaway key. SIGN_MESSAGE_WALLET_UTILS points at another copy, so the same assertions can be
// run against old behaviour.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { isUtf8 } = require('node:buffer');
const esbuild = require('esbuild');
const bitcoin = require('bitcoinjs-lib');
const ecc = require('@bitcoinerlab/secp256k1');
const { secp256k1 } = require('@noble/curves/secp256k1');

const ROOT = path.resolve(__dirname, '..');
const WALLET_SOURCE = process.env.SIGN_MESSAGE_WALLET_UTILS || path.join(ROOT, 'lib', 'walletUtils.js');
const LTCTEST = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'tltc',
  bip32: { public: 0x043587cf, private: 0x04358394 },
  pubKeyHash: 0x6f,
  scriptHash: 0x3a,
  wif: 0xef,
};

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const sha256d = (b) => sha256(sha256(b));
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };

// Throwaway fixture keys: fixed so the ground nLockTime below stays valid.
const USER_KEY = sha256(Buffer.from('TL-Extension sign-message smoke: user key'));
const ATTACKER_KEY = sha256(Buffer.from('TL-Extension sign-message smoke: attacker key'));
const PREV_TXID_LE = sha256(Buffer.from('TL-Extension sign-message smoke: prevout'));
// The first nLockTime >= 500000000 for which sha256 of this spend's BIP143 preimage is valid UTF-8.
const GROUND_LOCKTIME = 534356050;
const userPubkey = Buffer.from(ecc.pointFromScalar(USER_KEY, true));

const bundleWalletUtils = async () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sign-message-smoke-'));
  const outfile = path.join(outDir, 'walletUtils.cjs');
  await esbuild.build({
    entryPoints: [WALLET_SOURCE],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    outfile,
    logLevel: 'silent',
    nodePaths: [path.join(ROOT, 'node_modules')],
    plugins: [
      {
        name: 'sign-message-test-seams',
        setup(build) {
          build.onLoad({ filter: /walletUtils[^/\\]*\.js$/ }, (args) => {
            let text = fs.readFileSync(args.path, 'utf8');
            // bitcoinjs-lib v7 has no TransactionBuilder export; the import is unused.
            text = text.replace('import { TransactionBuilder, networks,Psbt, payments }', 'import { networks,Psbt, payments }');
            text = text.replace(
              'export async function getSigningKeyBase64(password, network) {',
              'export async function getSigningKeyBase64(password, network) {\n' +
                '  if (globalThis.__TL_TEST_SIGNING_KEY_B64__) return globalThis.__TL_TEST_SIGNING_KEY_B64__;'
            );
            if (!text.includes('__TL_TEST_SIGNING_KEY_B64__')) {
              throw new Error('smoke: key-lookup seam not found in walletUtils.js');
            }
            return { contents: text, loader: 'js', resolveDir: path.dirname(args.path) };
          });
        },
      },
    ],
  });
  return require(outfile);
};

const signedMessageDigest = (prefix, message) => {
  const body = Buffer.from(message, 'utf8');
  if (body.length >= 0xfd) throw new Error('test messages are short');
  return sha256d(Buffer.concat([Buffer.from(prefix, 'latin1'), Buffer.from([body.length]), body]));
};

// Decodes a base64 65-byte recoverable signature: { header, recid, compact (r || s) }.
const decodeCompact = (signature) => {
  assert.equal(typeof signature, 'string', 'signMessage must return a base64 string');
  const raw = Buffer.from(signature, 'base64');
  assert.equal(raw.length, 65, `a recoverable signature is 65 bytes, got ${raw.length}`);
  assert.equal(raw.toString('base64'), signature, 'the signature is not canonical base64');
  return { header: raw[0], compact: raw.subarray(1) };
};

const recoverPubkey = (compact, recid, digest) =>
  Buffer.from(secp256k1.Signature.fromCompact(compact).addRecoveryBit(recid).recoverPublicKey(digest).toRawBytes(true));

// The spend the fixture was ground for: the wallet's 1 tLTC UTXO, all of it to the attacker.
const groundSpend = () => {
  const attackerScript = Buffer.from(
    bitcoin.payments.p2wpkh({ pubkey: Buffer.from(ecc.pointFromScalar(ATTACKER_KEY, true)), network: LTCTEST }).output
  );
  const value = 100_000_000n;
  const seq = 0xfffffffd;
  const outValue = value - 10_000n;
  const scriptCode = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), Buffer.from(bitcoin.crypto.hash160(userPubkey)), Buffer.from([0x88, 0xac])]);
  const outpoint = Buffer.concat([PREV_TXID_LE, u32(0)]);
  const serOutputs = Buffer.concat([u64(outValue), Buffer.from([attackerScript.length]), attackerScript]);
  const preimage = Buffer.concat([
    u32(2), sha256d(outpoint), sha256d(u32(seq)), outpoint, Buffer.from([scriptCode.length]), scriptCode,
    u64(value), u32(seq), sha256d(serOutputs), u32(GROUND_LOCKTIME), u32(bitcoin.Transaction.SIGHASH_ALL),
  ]);
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.locktime = GROUND_LOCKTIME;
  tx.addInput(PREV_TXID_LE, 0, seq);
  tx.addOutput(attackerScript, outValue);
  const sighash = Buffer.from(tx.hashForWitnessV0(0, scriptCode, value, bitcoin.Transaction.SIGHASH_ALL));
  assert.ok(sighash.equals(sha256d(preimage)), 'fixture preimage is not the library BIP143 preimage');
  return { preimage, sighash };
};

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
let wallet = null;

test('a message is signed as a Litecoin signed message that recovers to the wallet key', async () => {
  const message = 'Sign in to TradeLayer: nonce 7f3a';
  const { header, compact } = decodeCompact(await wallet.signMessage(message, 'pw', 'LTCTEST'));
  assert.ok(header === 39 || header === 40, `a P2WPKH (BIP-137) header is 39 or 40, got ${header}`);
  const digest = signedMessageDigest(LTCTEST.messagePrefix, message);
  assert.ok(recoverPubkey(compact, header - 39, digest).equals(userPubkey), 'the signature does not recover to the wallet key');
  assert.ok(secp256k1.Signature.fromCompact(compact).s <= secp256k1.CURVE.n / 2n, 'the signature is not low-S');
});

test('a message ground to a spend sighash yields no transaction signature', async () => {
  const { preimage, sighash } = groundSpend();
  const h1 = sha256(preimage);
  assert.ok(isUtf8(h1), 'fixture: sha256(preimage) must be valid UTF-8');
  const message = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(h1);
  const signature = await wallet.signMessage(message, 'pw', 'LTCTEST');
  // Whatever form a signature takes, its (r, s) must not sign the spend.
  let rs;
  if (/^[0-9a-f]+$/i.test(signature) && signature.length % 2 === 0 && signature.startsWith('30')) {
    rs = Buffer.from(bitcoin.script.signature.decode(Buffer.concat([Buffer.from(signature, 'hex'), Buffer.from([1])])).signature);
  } else {
    rs = decodeCompact(signature).compact;
  }
  assert.equal(ecc.verify(sighash, userPubkey, rs), false, 'signMessage returned a valid signature for the spend sighash');
  const digest = signedMessageDigest(LTCTEST.messagePrefix, message);
  assert.ok(ecc.verify(digest, userPubkey, rs), 'the signature is not over the signed-message digest');
});

test('each network signs with its own prefix and its address type header', async () => {
  const message = 'network binding';
  const btc = decodeCompact(await wallet.signMessage(message, 'pw', 'BTCTEST'));
  assert.ok(btc.header === 39 || btc.header === 40, `BTC (BIP84) header ${btc.header}`);
  assert.ok(recoverPubkey(btc.compact, btc.header - 39, signedMessageDigest('\x18Bitcoin Signed Message:\n', message)).equals(userPubkey));
  const doge = decodeCompact(await wallet.signMessage(message, 'pw', 'DOGETEST'));
  assert.ok(doge.header === 31 || doge.header === 32, `DOGE (BIP44, compressed P2PKH) header ${doge.header}`);
  assert.ok(recoverPubkey(doge.compact, doge.header - 31, signedMessageDigest('\x19Dogecoin Signed Message:\n', message)).equals(userPubkey));
});

test('a message that is not a string, or a network without a prefix, is refused before the key is used', async () => {
  for (const bad of [{ toString: () => 'x' }, 42, null, Buffer.from('abc')]) {
    let message = null;
    try { await wallet.signMessage(bad, 'pw', 'LTCTEST'); } catch (error) { message = error.message; }
    assert.ok(message && /message string/.test(message), `message ${String(bad)} was not refused: ${message}`);
  }
  let refused = null;
  try { await wallet.signMessage('x', 'pw', 'NOT-A-NETWORK'); } catch (error) { refused = error.message; }
  assert.ok(refused, 'an unknown network was accepted');
});

(async () => {
  globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  globalThis.__TL_TEST_SIGNING_KEY_B64__ = USER_KEY.toString('base64');
  wallet = await bundleWalletUtils();
  let failed = 0;
  const log = console.log;
  for (const { name, fn } of tests) {
    console.log = () => {};
    try {
      await fn();
      console.log = log;
      console.log(`[sign-message] ok: ${name}`);
    } catch (error) {
      console.log = log;
      failed += 1;
      console.error(`[sign-message] FAIL: ${name}\n  ${error.message.split('\n')[0]}`);
    }
  }
  if (failed > 0) process.exit(1);
  console.log('[sign-message] all sign-message checks passed');
})();
