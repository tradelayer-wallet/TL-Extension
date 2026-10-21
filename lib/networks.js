// The one table of network names and derivation paths. The service worker, the
// popup and the wallet all canonicalize through canonicalNetworkId, so a name
// means the same network everywhere and a path is written once.

export const NETWORK_ALIASES = {
  DOGE: ['DOGE', 'DOGECOIN'],
  DOGETEST: ['DOGETEST', 'DOGECOIN-TESTNET'],
  LTC: ['LTC', 'LITECOIN', 'MAINNET', 'LTCMAINNET'],
  LTCTEST: ['LTCTEST', 'LITECOIN-TESTNET', 'LITECOIN_TESTNET', 'TESTNET', 'TLTC', 'TLTCTEST'],
  BTC: ['BTC', 'BITCOIN'],
  BTCTEST: ['BTCTEST', 'BITCOIN-TESTNET'],
};

// Native SegWit account 0, receive index 0 (Dogecoin uses P2PKH on BIP44).
export const DERIVATION_PATHS = {
  LTC: "m/84'/2'/0'/0/0",
  LTCTEST: "m/84'/1'/0'/0/0",
  BTC: "m/84'/0'/0'/0/0",
  BTCTEST: "m/84'/1'/0'/0/0",
  DOGE: "m/44'/3'/0'/0/0",
  DOGETEST: "m/44'/1'/0'/0/0",
};

/**
 * Canonical network id for a name (case and surrounding whitespace ignored), or
 * null when the name is not one of ours. Callers decide what null means.
 * @param {unknown} name
 * @returns {string|null}
 */
export const canonicalNetworkId = (name) => {
  const value = String(name ?? '').trim().toUpperCase();
  return Object.keys(NETWORK_ALIASES).find((key) => NETWORK_ALIASES[key].includes(value)) ?? null;
};

/**
 * Like canonicalNetworkId, for names that must be kept as they are: an absent
 * name is LTC, and an unknown name is returned trimmed and upper-cased.
 * @param {unknown} name
 * @returns {string}
 */
export const networkIdOf = (name) => {
  const value = String(name || 'LTC').trim().toUpperCase();
  return canonicalNetworkId(value) ?? value;
};
