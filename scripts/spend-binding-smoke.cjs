// Regression smoke test for what a signing request may ask the wallet to sign
// (run under plain Node, offline; throwaway testnet keys only):
//   - a legacy transfer is funded only from the wallet's own address: a page
//     cannot route change to another address (R8 critical)
//   - a legacy transfer signs only inputs that pay to the wallet's own key
//   - PSBT signing uses SIGHASH_ALL on every input, whatever the PSBT asks for
//   - a witness script is attached only when the UTXO script commits to it; a
//     UTXO script is never rewritten (the signed sighash commits to it)
//   - popup approval messages are accepted only from extension pages
// walletUtils.js is bundled from the real source. The only substitution is the
// key-cache lookup, which is replaced by a hook that returns a throwaway key.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const esbuild = require('esbuild');
const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('@bitcoinerlab/secp256k1');

const ROOT = path.resolve(__dirname, '..');
const ECPair = ECPairFactory(ecc);
const LTCTEST = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'tltc',
  bip32: { public: 0x043587cf, private: 0x04358394 },
  pubKeyHash: 0x6f,
  scriptHash: 0x3a,
  wif: 0xef,
};

// The wallet module to test. R8_OLD_WALLET_UTILS points at a pre-fix copy, so the
// same assertions can be run against the old behavior.
const WALLET_SOURCE = process.env.R8_OLD_WALLET_UTILS || path.join(ROOT, 'lib', 'walletUtils.js');

const bundleWalletUtils = async () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spend-binding-smoke-'));
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
        name: 'spend-binding-test-seams',
        setup(build) {
          build.onLoad({ filter: /walletUtils\.js$/ }, (args) => {
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

const randomKey = () => ECPair.fromPrivateKey(crypto.randomBytes(32), { network: LTCTEST });
const p2wpkhScript = (kp) => Buffer.from(bitcoin.payments.p2wpkh({ pubkey: Buffer.from(kp.publicKey), network: LTCTEST }).output);
const p2wpkhAddress = (kp) => bitcoin.payments.p2wpkh({ pubkey: Buffer.from(kp.publicKey), network: LTCTEST }).address;

const user = randomKey();
const attacker = randomKey();
const recipient = randomKey();
const other = randomKey();
const userScriptHex = p2wpkhScript(user).toString('hex');

let wallet = null;
const useKey = () => {
  globalThis.__TL_TEST_SIGNING_KEY_B64__ = Buffer.from(user.privateKey).toString('base64');
};

const utxos = () => [
  { txid: '11'.repeat(32), vout: 0, amount: 0.6, scriptPubKey: userScriptHex, confirmations: 6 },
  { txid: '22'.repeat(32), vout: 1, amount: 0.5, scriptPubKey: userScriptHex, confirmations: 6 },
];
const decodeOutputs = (rawHex) =>
  bitcoin.Transaction.fromHex(rawHex).outs.map((o) => ({
    address: bitcoin.address.fromOutputScript(o.script, LTCTEST),
    sats: Number(o.value),
  }));

// Rejects unless the call fails with a message matching `pattern`. The message
// is reported on failure, so a wrong refusal is visible.
const expectRefusal = async (promise, pattern) => {
  let message = null;
  try {
    await promise;
  } catch (error) {
    message = error.message;
  }
  if (message === null) {
    throw new Error(`expected a refusal matching ${pattern}, but the call succeeded`);
  }
  if (!pattern.test(message)) {
    throw new Error(`refusal did not match ${pattern}: ${message.split('\n')[0]}`);
  }
};

const localStore = new Map();
const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('legacy transfer: funded from the wallet address, change returns to the wallet', async () => {
  useKey();
  const res = await wallet.signTransaction(
    { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 0.1, inputs: utxos() },
    'pw',
    'LTCTEST'
  );
  assert.equal(res.success, true);
  const outs = decodeOutputs(res.data.rawTx);
  assert.equal(outs[0].address, p2wpkhAddress(recipient));
  assert.equal(outs[0].sats, 10_000_000);
  assert.equal(outs[1].address, p2wpkhAddress(user));
});

test('legacy transfer: a page cannot route change to another address', async () => {
  useKey();
  await assert.rejects(
    wallet.signTransaction(
      { fromKeyPair: { address: p2wpkhAddress(attacker) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 0.1, inputs: utxos() },
      'pw',
      'LTCTEST'
    ),
    /must be funded from this wallet's address/
  );
});

test('legacy transfer: an input that does not pay to the wallet key is refused', async () => {
  useKey();
  const foreign = utxos();
  foreign[0].scriptPubKey = p2wpkhScript(other).toString('hex');
  await assert.rejects(
    wallet.signTransaction(
      { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 0.1, inputs: foreign },
      'pw',
      'LTCTEST'
    ),
    /does not pay to this wallet's key/
  );
});

const vanillaPsbt = (sighashType, utxoScript = p2wpkhScript(user)) => {
  const psbt = new bitcoin.Psbt({ network: LTCTEST });
  psbt.addInput({
    hash: Buffer.alloc(32, 7),
    index: 0,
    witnessUtxo: { script: utxoScript, value: 100000n },
    ...(sighashType === undefined ? {} : { sighashType }),
  });
  psbt.addOutput({ address: p2wpkhAddress(recipient), value: 90000n });
  return psbt.toHex();
};

test('PSBT: a SIGHASH_NONE|ANYONECANPAY input is refused, SIGHASH_ALL is signed', async () => {
  useKey();
  await expectRefusal(wallet.signInputsInPsbt(vanillaPsbt(0x82), 'LTCTEST', 'pw', true, undefined), /Sighash type is not allowed/);
  const ok = await wallet.signInputsInPsbt(vanillaPsbt(0x01), 'LTCTEST', 'pw', true, undefined);
  assert.equal(ok.success, true);
});

test('PSBT: a UTXO script that does not commit to the witness script is refused, not rewritten', async () => {
  useKey();
  const witnessScript = bitcoin.script.compile([
    bitcoin.opcodes.OP_2,
    Buffer.from(user.publicKey),
    Buffer.from(other.publicKey),
    bitcoin.opcodes.OP_2,
    bitcoin.opcodes.OP_CHECKMULTISIG,
  ]);
  const realUtxoScript = Buffer.from(bitcoin.payments.p2wsh({ redeem: { output: witnessScript }, network: LTCTEST }).output);
  const wrongUtxoScript = p2wpkhScript(attacker);

  const psbt = new bitcoin.Psbt({ network: LTCTEST });
  psbt.addInput({ hash: Buffer.alloc(32, 9), index: 0, witnessUtxo: { script: wrongUtxoScript, value: 100000n } });
  psbt.addOutput({ address: p2wpkhAddress(recipient), value: 90000n });
  await expectRefusal(
    wallet.signInputsInPsbt(psbt.toHex(), 'LTCTEST', 'pw', true, Buffer.from(witnessScript).toString('hex')),
    /does not match the witness script/
  );

  const good = new bitcoin.Psbt({ network: LTCTEST });
  good.addInput({ hash: Buffer.alloc(32, 9), index: 0, witnessUtxo: { script: realUtxoScript, value: 100000n } });
  good.addOutput({ address: p2wpkhAddress(recipient), value: 90000n });
  const signed = await wallet.signInputsInPsbt(good.toHex(), 'LTCTEST', 'pw', true, Buffer.from(witnessScript).toString('hex'));
  assert.equal(signed.success, true);
});

test('PSBT: a witness script already present in the PSBT still needs a UTXO script that commits to it', async () => {
  useKey();
  const witnessScript = bitcoin.script.compile([
    bitcoin.opcodes.OP_2,
    Buffer.from(user.publicKey),
    Buffer.from(other.publicKey),
    bitcoin.opcodes.OP_2,
    bitcoin.opcodes.OP_CHECKMULTISIG,
  ]);
  const psbt = new bitcoin.Psbt({ network: LTCTEST });
  psbt.addInput({
    hash: Buffer.alloc(32, 9),
    index: 0,
    witnessUtxo: { script: p2wpkhScript(attacker), value: 100000n },
    witnessScript,
  });
  psbt.addOutput({ address: p2wpkhAddress(recipient), value: 90000n });
  await expectRefusal(
    wallet.signInputsInPsbt(psbt.toHex(), 'LTCTEST', 'pw', true, Buffer.from(witnessScript).toString('hex')),
    /does not match the witness script/
  );
});

test('trade PSBT: amounts convert to whole satoshis exactly, as the UTXO and the output carry them', () => {
  // 0.29 * 1e8 is 28999999.999... in binary floating point; truncating it loses a satoshi
  // from the recorded UTXO value (which the signature commits to) and from the seller output.
  assert.equal(wallet.ltcToSats(0.29), 29_000_000);
  assert.equal(wallet.ltcToSats(1.1), 110_000_000);
  const built = wallet.buildUnsignedPSBT({
    buyerKeyPair: { address: p2wpkhAddress(user) },
    sellerKeyPair: { address: p2wpkhAddress(recipient) },
    amount: 0.29,
    payload: null,
    commitUTXOs: [{ txid: '11'.repeat(32), vout: 0, amount: 0.5, scriptPubKey: userScriptHex }],
    outputs: [],
    network: 'LTCTEST',
    sats: 0,
  });
  const psbt = bitcoin.Psbt.fromHex(built.psbt, { network: LTCTEST });
  assert.equal(psbt.data.inputs[0].witnessUtxo.value, 50_000_000n, 'the UTXO value is the UTXO value');
  assert.equal(Number(psbt.txOutputs[0].value), 50_000_000 - 29_000_000 - 10_000, 'buyer change');
  assert.equal(Number(psbt.txOutputs[1].value), 29_000_000, 'seller output is the agreed amount');

  const withPayload = wallet.buildUnsignedPSBT({
    buyerKeyPair: { address: p2wpkhAddress(user) },
    sellerKeyPair: { address: p2wpkhAddress(recipient) },
    amount: 0.29,
    payload: 'tl',
    commitUTXOs: [{ txid: '11'.repeat(32), vout: 0, amount: 0.5, scriptPubKey: userScriptHex }],
    outputs: [],
    network: 'LTCTEST',
    sats: 0,
  });
  const withData = bitcoin.Psbt.fromHex(withPayload.psbt, { network: LTCTEST });
  assert.equal(withData.txOutputs.length, 3, 'buyer change, seller output and the OP_RETURN payload');
  assert.equal(Number(withData.txOutputs[2].value), 0, 'the payload output carries no value');
});

test('approval summary: an input given as a full previous transaction shows its address and value', () => {
  // A PSBT input may name its UTXO by the whole previous transaction instead of witnessUtxo.
  // The approval screen must show that value, and must not trust a previous transaction that
  // does not hash to the outpoint the input spends.
  const prev = new bitcoin.Transaction();
  prev.version = 2;
  prev.addInput(Buffer.alloc(32, 3), 0);
  prev.addOutput(p2wpkhScript(user), 29_000_000n);
  const good = new bitcoin.Psbt({ network: LTCTEST });
  good.addInput({ hash: prev.getHash(), index: 0, nonWitnessUtxo: prev.toBuffer() });
  good.addOutput({ address: p2wpkhAddress(recipient), value: 28_900_000n });
  const shown = wallet.summarizePsbtForDisplay(good.toHex(), 'LTCTEST', []);
  assert.equal(shown.inputs[0].valueSats, 29_000_000, 'the spent value is shown');
  assert.equal(shown.inputs[0].address, p2wpkhAddress(user), 'the spent address is shown');
  assert.equal(shown.feeSats, 100_000);

  const other = new bitcoin.Transaction();
  other.version = 2;
  other.addInput(Buffer.alloc(32, 4), 0);
  other.addOutput(p2wpkhScript(attacker), 1_000_000_000n);
  const forged = new bitcoin.Psbt({ network: LTCTEST });
  forged.addInput({ hash: prev.getHash(), index: 0, nonWitnessUtxo: other.toBuffer() });
  forged.addOutput({ address: p2wpkhAddress(recipient), value: 28_900_000n });
  const hidden = wallet.summarizePsbtForDisplay(forged.toHex(), 'LTCTEST', []);
  assert.equal(hidden.inputs[0].valueSats, null, 'a previous transaction that is not the outpoint is not trusted');
  assert.equal(hidden.inputs[0].address, null);
});

test('approval summary: an input whose value the PSBT does not prove makes the totals unknown', () => {
  // A PSBT input with no witnessUtxo and no previous transaction has no value to show. A total
  // that leaves it out would look complete, so the totals and the fee are unknown (null) instead.
  const bare = new bitcoin.Psbt({ network: LTCTEST });
  bare.addInput({ hash: Buffer.alloc(32, 5), index: 0 });
  bare.addOutput({ address: p2wpkhAddress(recipient), value: 28_900_000n });
  const unproven = wallet.summarizePsbtForDisplay(bare.toHex(), 'LTCTEST', []);
  assert.equal(unproven.inputs[0].valueSats, null);
  assert.equal(unproven.totalInputSats, null, 'the total in is unknown, not 0');
  assert.equal(unproven.feeSats, null, 'the fee is unknown, not the outputs');
  assert.equal(unproven.totalOutputSats, 28_900_000);

  const mixed = new bitcoin.Psbt({ network: LTCTEST });
  mixed.addInput({ hash: Buffer.alloc(32, 6), index: 0, witnessUtxo: { script: p2wpkhScript(user), value: 29_000_000n } });
  mixed.addInput({ hash: Buffer.alloc(32, 7), index: 0 });
  mixed.addOutput({ address: p2wpkhAddress(recipient), value: 28_900_000n });
  const partial = wallet.summarizePsbtForDisplay(mixed.toHex(), 'LTCTEST', []);
  assert.equal(partial.inputs[0].valueSats, 29_000_000);
  assert.equal(partial.totalInputSats, null, 'one unproven input makes the total in unknown');
  assert.equal(partial.feeSats, null);
});

test('legacy transfer: Dogecoin is refused with the reason, before any key is used', async () => {
  useKey();
  await expectRefusal(
    wallet.signTransaction(
      { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 0.1, inputs: utxos() },
      'pw',
      'DOGETEST'
    ),
    /Legacy transfers are not supported on DOGETEST/
  );
});

test('popup: runtime senders are classified once, and only the popup may approve or sign', () => {
  const { senderClass } = require(path.join(ROOT, 'lib', 'senders.js'));
  const runtime = { id: 'ext', getURL: (file) => `chrome-extension://ext/${file}` };
  const popupUrl = 'chrome-extension://ext/popup/popup.html';
  assert.equal(senderClass({ id: 'ext', url: `${popupUrl}?step=13` }, runtime), 'popup');
  assert.equal(senderClass({ id: 'ext', tab: { id: 9 }, url: `${popupUrl}?step=13` }, runtime), 'popup', 'the approval window has a tab');
  assert.equal(senderClass({ id: 'ext', url: 'chrome-extension://ext/background/background.js' }, runtime), 'extension');
  assert.equal(senderClass({ id: 'ext', tab: { id: 3 }, url: 'chrome-extension://ext/options.html' }, runtime), 'extension');
  assert.equal(senderClass({ id: 'ext', tab: { id: 3 }, url: 'https://layerwallet.com/' }, runtime), 'page');
  assert.equal(senderClass({ id: 'other', url: popupUrl }, runtime), 'foreign');
  assert.equal(senderClass({ origin: 'https://layerwallet.com', url: 'https://layerwallet.com/', tab: { id: 4 } }, runtime), 'foreign');
  assert.equal(senderClass(undefined, runtime), 'foreign');
});

test('legacy transfer: two selected UTXOs from the wallet address, change returns to the wallet (honest)', async () => {
  useKey();
  const res = await wallet.signTransaction(
    { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 0.9, inputs: utxos() },
    'pw',
    'LTCTEST'
  );
  assert.equal(res.success, true);
  const tx = bitcoin.Transaction.fromHex(res.data.rawTx);
  assert.equal(tx.ins.length, 2);
  const outs = decodeOutputs(res.data.rawTx);
  assert.equal(outs[0].sats, 90_000_000);
  assert.equal(outs[1].address, p2wpkhAddress(user));
  assert.equal(outs[1].sats, 110_000_000 - 90_000_000 - 10_000);
});

test('legacy transfer: an exact send with no change output (honest)', async () => {
  useKey();
  const single = [{ txid: '33'.repeat(32), vout: 0, amount: 0.1, scriptPubKey: userScriptHex, confirmations: 6 }];
  // 0.1 LTC in, 0.0999 out, 10000 sat fee: the change is exactly zero, so there is no change output.
  const res = await wallet.signTransaction(
    { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 0.0999, inputs: single },
    'pw',
    'LTCTEST'
  );
  assert.equal(res.success, true);
  const outs = decodeOutputs(res.data.rawTx);
  assert.equal(outs.length, 1);
  assert.equal(outs[0].address, p2wpkhAddress(recipient));
});

test('PSBT: a P2WSH UTXO with no witnessScript in the PSBT is matched through the multisig registry (honest)', async () => {
  // Regression: the derivation used a P2WPKH-only decoder, which throws on a 34-byte P2WSH script,
  // so the honest PSBT was refused instead of matched to its registered channel.
  useKey();
  const witnessScript = bitcoin.script.compile([
    bitcoin.opcodes.OP_2,
    Buffer.from(user.publicKey),
    Buffer.from(other.publicKey),
    bitcoin.opcodes.OP_2,
    bitcoin.opcodes.OP_CHECKMULTISIG,
  ]);
  const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript }, network: LTCTEST });
  const psbt = new bitcoin.Psbt({ network: LTCTEST });
  psbt.addInput({ hash: Buffer.alloc(32, 5), index: 0, witnessUtxo: { script: Buffer.from(p2wsh.output), value: 100000n } });
  psbt.addOutput({ address: p2wpkhAddress(recipient), value: 90000n });
  localStore.set('multisigs', JSON.stringify([{ address: p2wsh.address, redeemScript: Buffer.from(witnessScript).toString('hex') }]));
  try {
    const signed = await wallet.signInputsInPsbt(psbt.toHex(), 'LTCTEST', 'pw', true, undefined);
    assert.equal(signed.success, true);
  } finally {
    localStore.delete('multisigs');
  }
});

test('legacy transfer: the amount signed is the amount named; a number and its string send the same', async () => {
  useKey();
  const sendAmount = async (amount) => {
    const res = await wallet.signTransaction(
      { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount, inputs: utxos() },
      'pw',
      'LTCTEST'
    );
    return decodeOutputs(res.data.rawTx)[0].sats;
  };
  assert.equal(await sendAmount(0.1), 10_000_000);
  assert.equal(await sendAmount('0.1'), 10_000_000);
});

test('legacy transfer: a zero, missing, or non-numeric amount is refused, as a number or a string', async () => {
  useKey();
  for (const amount of [0, '0', '', '  ', -1, '-1', NaN, 'NaN', 'LTC', true, null, undefined, Infinity]) {
    await expectRefusal(
      wallet.signTransaction(
        { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount, inputs: utxos() },
        'pw',
        'LTCTEST'
      ),
      /positive amount/
    );
  }
});

test('legacy transfer: an amount below the dust limit is refused', async () => {
  useKey();
  await expectRefusal(
    wallet.signTransaction(
      { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 1e-9, inputs: utxos() },
      'pw',
      'LTCTEST'
    ),
    /dust/
  );
});

test('legacy transfer: change below the dust limit is not added as an output (it is the fee)', async () => {
  useKey();
  // 0.100003 LTC in, 0.0999 out, 10000 sat fee: 300 sat of change is below the dust limit.
  const single = [{ txid: '44'.repeat(32), vout: 0, amount: 0.10000300, scriptPubKey: userScriptHex, confirmations: 6 }];
  const res = await wallet.signTransaction(
    { fromKeyPair: { address: p2wpkhAddress(user) }, toKeyPair: { address: p2wpkhAddress(recipient) }, amount: 0.0999, inputs: single },
    'pw',
    'LTCTEST'
  );
  const outs = decodeOutputs(res.data.rawTx);
  assert.equal(outs.length, 1);
  assert.equal(outs[0].sats, 9_990_000);
});

(async () => {
  // The PSBT path reads the multisig registry from localStorage. Tests seed it through this map.
  globalThis.localStorage = {
    getItem: (key) => (localStore.has(key) ? localStore.get(key) : null),
    setItem: (key, value) => localStore.set(key, String(value)),
    removeItem: (key) => localStore.delete(key),
  };
  wallet = await bundleWalletUtils();
  let failed = 0;
  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`[spend-binding] ok: ${name}`);
    } catch (error) {
      failed += 1;
      console.error(`[spend-binding] FAIL: ${name}\n  ${error.message.split('\n')[0]}`);
    }
  }
  if (failed > 0) {
    process.exit(1);
  }
  console.log('[spend-binding] all spend-binding checks passed');
})();