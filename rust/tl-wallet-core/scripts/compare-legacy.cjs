#!/usr/bin/env node
// Dependency-free legacy parity harness for tl-wallet-core.
//
// Loads only files that are checked into the TL-Extension repository:
//   * lib/walletUtils.js        -- read as TEXT; the network parameter objects are extracted
//                                  from it (the file itself imports npm packages and cannot
//                                  be require()d without them);
//   * dist/bitcoinjs.js          -- the vendored bitcoinjs-lib UMD bundle, require()d.
// It prints `key=value` vectors (synthetic keys only) to tests/fixtures/legacy_vectors.txt,
// or with --check compares the current output with the committed file.
//
//   node scripts/compare-legacy.cjs            # write fixture
//   node scripts/compare-legacy.cjs --check    # fail if the legacy code now disagrees

'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const repoRoot = path.resolve(__dirname, '..', '..', '..');
const fixturePath = path.resolve(__dirname, '..', 'tests', 'fixtures', 'legacy_vectors.txt');

const PINNED = {
  'lib/walletUtils.js': 'f72101b4fdb97783c598e1d9899dcad615b4d584',
};

function gitBlobSha(file) {
  let buf = fs.readFileSync(path.join(repoRoot, file));
  // The checkout may have CRLF line endings from autocrlf; the git blob is LF.
  const text = buf.toString('utf8');
  if (text.includes('\r\n')) buf = Buffer.from(text.replace(/\r\n/g, '\n'), 'utf8');
  const h = crypto.createHash('sha1');
  h.update(`blob ${buf.length}\0`);
  h.update(buf);
  return h.digest('hex');
}

for (const [file, sha] of Object.entries(PINNED)) {
  const got = gitBlobSha(file);
  if (got !== sha) {
    console.error(`legacy file ${file} changed: expected blob ${sha}, got ${got}`);
    process.exit(2);
  }
}

// ---- extract the legacy network objects from walletUtils.js source text
const src = fs.readFileSync(path.join(repoRoot, 'lib/walletUtils.js'), 'utf8');
function extractObject(name) {
  const re = new RegExp(`const ${name} = (\\{[\\s\\S]*?\\n\\s*\\});`);
  const m = src.match(re);
  if (!m) throw new Error(`cannot find ${name}`);
  return new Function(`return (${m[1]});`)();
}
const networks = {
  LTC: extractObject('litecoinNetwork'),
  LTCTEST: extractObject('litecoinTestnet'),
  BTC: extractObject('bitcoinMainnet'),
  BTCTEST: extractObject('bitcoinTestnet'),
  DOGE: extractObject('dogecoin'),
  DOGETEST: extractObject('dogecoinTestnet'),
};
const pathsSrc = src.match(/const networkPaths = (\{[\s\S]*?\n\});/)[1];
const networkPaths = new Function(`return (${pathsSrc});`)();

const bitcoin = require(path.join(repoRoot, 'dist', 'bitcoinjs.js'));

const hx = (b) => Buffer.from(b).toString('hex');
const out = [];
const put = (k, v) => out.push(`${k}=${v}`);
put('legacy.walletUtils.blob', PINNED['lib/walletUtils.js']);

// Synthetic compressed public keys: secp256k1 generator G, 2G, 3G (public constants).
const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const G2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const G3 = '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
// BIP84 "abandon ... about" first receive keys (public test mnemonic).
const abandon = {
  LTC: '02e49c9b9b5d0f127235dc26a0c252814c52fb333d651a946773f59d72c2da9904',
  LTCTEST: '02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319',
  BTC: '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c',
  BTCTEST: '02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319',
  DOGE: '02cc6b0dc33aabcf3a23643e5e2919a80c50fb3dd2129ce409bbc5f0d4643d05e0',
  DOGETEST: '02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6',
};

for (const [name, net] of Object.entries(networks)) {
  put(`params.${name}.path`, networkPaths[name]);
  put(`params.${name}.pubKeyHash`, net.pubKeyHash);
  put(`params.${name}.scriptHash`, net.scriptHash);
  put(`params.${name}.bech32`, net.bech32);
  put(`params.${name}.messagePrefixHex`, Buffer.from(net.messagePrefix, 'latin1').toString('hex'));
  const pub = Buffer.from(abandon[name], 'hex');
  const isDoge = name.startsWith('DOGE');
  const acct = isDoge
    ? bitcoin.payments.p2pkh({ pubkey: pub, network: net })
    : bitcoin.payments.p2wpkh({ pubkey: pub, network: net });
  put(`account.${name}.address`, acct.address);
  put(`account.${name}.script`, hx(acct.output));
  const p2pkhG = bitcoin.payments.p2pkh({ pubkey: Buffer.from(G, 'hex'), network: net });
  put(`p2pkh.${name}.G`, p2pkhG.address);
  const redeemHash = bitcoin.payments.p2pkh({ pubkey: Buffer.from(G2, 'hex'), network: net }).output;
  const p2sh = bitcoin.payments.p2sh({ hash: redeemHash.slice(3, 23), network: net });
  put(`p2sh.${name}.hash20`, hx(redeemHash.slice(3, 23)));
  put(`p2sh.${name}.address`, p2sh.address);
  if (net.bech32) {
    const ms = bitcoin.payments.p2ms({
      m: 2,
      pubkeys: [G, G2, G3].map((h) => Buffer.from(h, 'hex')),
      network: net,
    });
    const p2wsh = bitcoin.payments.p2wsh({ redeem: ms, network: net });
    put(`multisig.${name}.witnessScript`, hx(ms.output));
    put(`multisig.${name}.address`, p2wsh.address);
    put(`multisig.${name}.script`, hx(p2wsh.output));
    const toScript = bitcoin.address.toOutputScript(acct.address, net);
    put(`decode.${name}.script`, hx(toScript));
  } else {
    put(`decode.${name}.script`, hx(bitcoin.address.toOutputScript(acct.address, net)));
  }
}

// ---- PSBT build + BIP143 sighash on LTCTEST (legacy buildUnsignedPSBT/signTransaction shape)
{
  const net = networks.LTCTEST;
  const own = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(abandon.LTCTEST, 'hex'), network: net });
  const to = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(G, 'hex'), network: net });
  const txidA = '11'.repeat(32);
  const txidB = '22'.repeat(32);
  const psbt = new bitcoin.Psbt({ network: net });
  psbt.addInput({ hash: txidA, index: 0, witnessUtxo: { script: own.output, value: BigInt(50000) } });
  psbt.addOutput({ script: to.output, value: BigInt(30000) });
  psbt.addOutput({ script: own.output, value: BigInt(10000) });
  const embed = bitcoin.payments.embed({ data: [Buffer.from('TL', 'utf8')] });
  psbt.addOutput({ script: embed.output, value: BigInt(0) });
  const unsigned = hx(psbt.data.globalMap.unsignedTx.toBuffer());
  put('psbt.ltctest.unsigned_tx', unsigned);
  put('psbt.ltctest.recipient', to.address);
  put('psbt.ltctest.own', own.address);
  put('psbt.ltctest.txidA', txidA);
  put('psbt.ltctest.opreturn_script', hx(embed.output));
  let captured = null;
  const signer = {
    publicKey: Buffer.from(abandon.LTCTEST, 'hex'),
    sign(hash) {
      captured = Buffer.from(hash);
      return Buffer.alloc(64, 1);
    },
  };
  psbt.signInput(0, signer);
  put('psbt.ltctest.sighash_all_input0', hx(captured));
  void txidB;
}

const text = out.join('\n') + '\n';
if (process.argv.includes('--check')) {
  const have = fs.readFileSync(fixturePath, 'utf8').replace(/\r\n/g, '\n');
  if (have !== text) {
    console.error('legacy vectors differ from committed fixture');
    process.exit(1);
  }
  console.log('legacy vectors match committed fixture');
} else {
  fs.mkdirSync(path.dirname(fixturePath), { recursive: true });
  fs.writeFileSync(fixturePath, text);
  console.log(`wrote ${out.length} vectors to ${fixturePath}`);
}
