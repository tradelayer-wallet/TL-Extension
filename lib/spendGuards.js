/**
 * Spend guards: the single place where a signing request is bound to the
 * wallet's own key before anything is signed.
 *
 * Requests that arrive from a web page can name any `fromKeyPair.address`
 * and any `inputs`. Change returns to the named address, so a page could route
 * the change of the user's own UTXOs to an address it controls while the
 * approval screen shows only the requested recipient. Every check here fails
 * closed.
 */
import * as bitcoin from '../dist/bitcoinjs.js';

export const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;

/** The P2WPKH address and output script of a signing key on `network`. */
export function ownP2wpkh(publicKey, network) {
  const payment = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(publicKey), network });
  return { address: payment.address, script: Buffer.from(payment.output) };
}

/**
 * A legacy transfer must be funded from this wallet's own address, and each
 * selected input must pay to this wallet's own key. `fromKeyPair` is optional,
 * but when present its address must be the wallet's own.
 */
export function assertLegacySpendOwned({ fromKeyPair, selectedInputs, ownAddress, ownScript }) {
  if (fromKeyPair && fromKeyPair.address !== undefined && fromKeyPair.address !== ownAddress) {
    throw new Error(
      `The transfer must be funded from this wallet's address ${ownAddress}; ` +
        `refusing to route change to another address.`
    );
  }

  const ownScriptHex = Buffer.from(ownScript).toString('hex');
  selectedInputs.forEach((input, index) => {
    const scriptPubKey =
      typeof input?.scriptPubKey === 'string' ? input.scriptPubKey.toLowerCase() : '';
    if (scriptPubKey !== ownScriptHex) {
      throw new Error(
        `Input ${index} does not pay to this wallet's key; refusing to sign an input the wallet does not own.`
      );
    }
  });
}

/**
 * Every signature is made with SIGHASH_ALL. The library default only holds
 * while callers pass no allow-list, so the allow-list is explicit here.
 */
export function signInputAllOutputs(psbt, index, keyPair) {
  psbt.signInput(index, keyPair, [SIGHASH_ALL]);
}

