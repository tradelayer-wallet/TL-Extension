// Replacement for lib/walletUtils.js in the Rust build. Everything the legacy module exports
// is re-exported unchanged except the functions that derive, hold or use keys; those call the
// tl-wallet-core vault in WebAssembly. Same names, same arguments, same return shapes, so the
// React components are untouched.
//
// Differences a caller can observe (each is a repaired defect or versioned change in
// rust/tl-wallet-core/README.md):
//  * generateAddressFromSeed ignores its `encryptedSeed` argument (the vault is read from the
//    store by the core) and returns privateKey '' (no derived key is persisted; R19).
//  * checkPasswordMatch really checks the password (R16).
//  * signMessage returns a BIP-137 base64 signature (R4/V1) and refuses without an explicit network (R5).
//  * signTransaction pays change to the wallet's own address, never the page's (R1), and refuses
//    UTXOs the wallet does not own (R6).
//  * signInputsInPsbt no longer patches PSBTs from localStorage multisig records (R8).
export * from 'legacy-wallet-utils';

import core from './core.js';
import store from 'legacy-store';
import { describe } from './messages.js';

let lastNetwork = null;

const reduxState = () => {
  try {
    return store.getState() || {};
  } catch {
    return {};
  }
};

const fail = (r) => {
  const error = new Error(describe(r));
  error.code = r.code;
  throw error;
};

const need = (r) => (r.ok ? r : fail(r));

const networkLabel = (network) => {
  if (typeof network === 'string' && network) return network;
  throw new Error('Invalid network parameter. Must be a network id such as "LTCTEST".');
};

const isCoinString = (s) => /^[0-9]+(\.[0-9]{1,8})?$/.test(s);

// Legacy amounts are JS numbers in coin units; the core takes exact decimal strings.
const coinString = (value, what) => {
  if (typeof value === 'string' && isCoinString(value.trim())) return value.trim();
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value < 1e12) {
    const s = value.toFixed(8);
    if (Math.abs(Number(s) - value) < 1e-9) return s;
  }
  throw new Error(`${what} is not a plain decimal amount with at most 8 decimals.`);
};

const hexOf = (script) => {
  if (typeof script === 'string') return script;
  if (script && script.type === 'Buffer' && Array.isArray(script.data)) {
    return script.data.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  if (script instanceof Uint8Array) {
    return Array.from(script, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  throw new Error('scriptPubKey must be hex.');
};

export function generateMnemonic() {
  return need(core.call({ op: 'generate_mnemonic' })).phrase;
}

export const generateAddressFromSeed = (_encryptedSeed, network, password) => {
  const r = need(core.call({ op: 'unlock', password, network: networkLabel(network) }));
  lastNetwork = r.network;
  if (r.migration) console.info('Vault migration from the legacy format:', JSON.stringify(r.migration));
  return {
    address: r.address,
    publicKey: r.public_key,
    privateKey: '',
    derivationPath: r.derivation_path,
    network: r.network,
  };
};

export async function checkPasswordMatch(password, network, expectedAddress) {
  const r = core.call({
    op: 'check_password',
    password,
    network: networkLabel(network),
    address: String(expectedAddress || ''),
  });
  return r.ok === true;
}

export async function signMessage(message, password) {
  const state = reduxState();
  const network = state.network || lastNetwork;
  const r = need(
    core.call({
      op: 'sign_message',
      password,
      network: networkLabel(network),
      origin: state.requestOrigin || undefined,
      message: String(message),
    })
  );
  return r.signature;
}

export async function signTransaction(requestPayload, password, network) {
  const state = reduxState();
  const { toKeyPair, amount, inputs, payload } = requestPayload || {};
  if (!Array.isArray(inputs) || inputs.length === 0) {
    throw new Error('Transaction inputs (UTXOs) are required.');
  }
  const r = need(
    core.call({
      op: 'sign_payment',
      password,
      network: networkLabel(network || state.network),
      origin: state.requestOrigin || undefined,
      to: String(toKeyPair?.address || ''),
      amount: coinString(amount, 'amount'),
      utxos: inputs.map((u) => ({
        txid: u.txid,
        vout: u.vout,
        amount: coinString(u.amount, 'input amount'),
        script_pubkey: hexOf(u.scriptPubKey),
      })),
      payload: payload ? String(payload) : undefined,
    })
  );
  return { success: true, data: { rawTx: r.raw_tx, txid: r.txid } };
}

export const signInputsInPsbt = async (psbtHex, network, password, sellerFlag, witnessScript) => {
  const state = reduxState();
  const r = need(
    core.call({
      op: 'sign_psbt',
      password,
      network: networkLabel(network || state.network),
      origin: state.requestOrigin || undefined,
      psbt_hex: String(psbtHex),
      seller_flag: sellerFlag === true,
      witness_script: witnessScript || undefined,
    })
  );
  if (r.raw_tx) return { success: true, data: { rawTx: r.raw_tx, txid: r.txid } };
  return { success: true, data: { rawTx: r.psbt_hex } };
};
