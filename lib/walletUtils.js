import * as bitcoin from "../dist/bitcoinjs.js";  // Bitcoinjs for all required functionality
import * as bip39 from 'bip39';  // Import bip39 separately
import BIP32Factory from 'bip32';
//import ECPair from 'ECPair'
import axios from 'axios';
//import ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import * as ecc from '@bitcoinerlab/secp256k1'; 
// or import ecc from 'tiny-secp256k1';

const ECPair = ECPairFactory(ecc);
import * as secp from '@noble/secp256k1';
import { ec } from 'elliptic';
import { sha256 } from '@noble/hashes/sha256';
import {
  encryptWithPassword,
  decryptWithPasswordInfo,
  maybeUpgradeStoredBlob,
  storeKeyCacheBlob,
  discardKeyCacheBlob,
  liveSeedOpensUnder,
  isStoredBlobConflictError,
  removeKeyCaches,
  PRIVATE_KEY_CACHE_PREFIX,
  PLAINTEXT_KIND,
} from './secureVault';
import { ethErrors, serializeError } from 'eth-rpc-errors';
console.log('ecc obj '+JSON.stringify(ecc))
const bip32 = BIP32Factory(ecc);
import { TransactionBuilder, networks,Psbt, payments } from 'bitcoinjs-lib';
import { assertLegacySpendOwned, ownP2wpkh, signInputAllOutputs } from './spendGuards.js';
import { canonicalNetworkId, DERIVATION_PATHS } from './networks.js';
const ecdsa = new ec('secp256k1');

const hashMessage = async (message) => {
  const encoder = new TextEncoder(); // Converts string to Uint8Array
  const data = encoder.encode(message); // Encode the message as Uint8Array
  const hashBuffer = await crypto.subtle.digest('SHA-256', data); // Hash the data
  return new Uint8Array(hashBuffer); // Convert ArrayBuffer to Uint8Array
};

const litecoinNetwork = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'ltc',
  bip32: {
    public: 0x019da462, // Litecoin's BIP32 public key
    private: 0x019d9cfe, // Litecoin's BIP32 private key
  },
  pubKeyHash: 0x30, // Litecoin's P2PKH prefix
  scriptHash: 0x32, // Litecoin's P2SH prefix
  wif: 0xb0, // Litecoin's WIF prefix
};

const litecoinTestnet = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'tltc',
  bip32: {
    public: 0x043587cf, // Litecoin Testnet BIP32 public key
    private: 0x04358394, // Litecoin Testnet BIP32 private key
  },
  pubKeyHash: 0x6f, // Litecoin Testnet P2PKH prefix
  scriptHash: 0x3a, // Litecoin Testnet P2SH prefix
  wif: 0xef, // Litecoin Testnet WIF prefix
};

const dogecoin = {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bech32: null, // Dogecoin doesn't use bech32
    bip32: {
        public: 0x02facafd, // Public key prefix
        private: 0x02fac398, // Private key prefix
    },
    pubKeyHash: 0x1e, // P2PKH address prefix (starts with 'D')
    scriptHash: 0x16, // P2SH address prefix (starts with '9')
    wif: 0x9e, // WIF prefix
};

const dogecoinTestnet = {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bech32: null, // Dogecoin does not use Bech32 addresses
    bip32: {
        public: 0x043587cf, // Public key prefix for testnet
        private: 0x04358394, // Private key prefix for testnet
    },
    pubKeyHash: 0x71, // P2PKH address prefix (starts with 'n' or 'm')
    scriptHash: 0xc4, // P2SH address prefix (starts with '2')
    wif: 0xf1, // WIF prefix for private keys
};

const bitcoinMainnet = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc', // Bech32 prefix for SegWit addresses
    bip32: {
        public: 0x0488b21e, // BIP32 public key prefix
        private: 0x0488ade4, // BIP32 private key prefix
    },
    pubKeyHash: 0x00, // P2PKH address prefix (starts with '1')
    scriptHash: 0x05, // P2SH address prefix (starts with '3')
    wif: 0x80, // WIF prefix for private keys
};

const bitcoinTestnet = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb', // Bech32 prefix for SegWit addresses on testnet
    bip32: {
        public: 0x043587cf, // BIP32 public key prefix for testnet
        private: 0x04358394, // BIP32 private key prefix for testnet
    },
    pubKeyHash: 0x6f, // P2PKH address prefix (starts with 'm' or 'n')
    scriptHash: 0xc4, // P2SH address prefix (starts with '2')
    wif: 0xef, // WIF prefix for private keys
};

/**
 * Resolves any network input (string, object, or undefined) to { normalized, network }
 */
function resolveNetwork(networkInput) {
  let normalized;
  let network;

  if (typeof networkInput === 'string') {
    normalized = normalizeNetwork(networkInput);
    network = networkList[normalized];
  } else if (typeof networkInput === 'object' && networkInput !== null) {
    normalized = extractNetworkName(networkInput);
    network = networkInput;
  } else {
    console.warn('No network provided, defaulting to LTCTEST');
    normalized = 'LTCTEST';
    network = litecoinTestnet;
  }

  if (!network) {
    throw new Error(`Could not resolve network for input: ${networkInput}`);
  }

  return { normalized, network };
}


// Map standard keys to network objects
const networkList = {
    DOGE: dogecoin,
    DOGETEST: dogecoinTestnet,
    LTC: litecoinNetwork,
    LTCTEST: litecoinTestnet,
    BTC: bitcoinMainnet,
    BTCTEST: bitcoinTestnet,
};

const privateKeyCacheLabel = (networkName, path) => {
  const safePath = String(path || '').replace(/[^a-zA-Z0-9]+/g, '_');
  return `${PRIVATE_KEY_CACHE_PREFIX}:${networkName}:${safePath}`;
};

const zeroBuffer = (buf) => {
  if (buf && typeof buf.fill === 'function') {
    buf.fill(0);
  }
};

function normalizeNetwork(networkString) {
    // Fail closed: never guess a default network for unknown inputs, so a
    // request can't silently be signed/derived for the wrong chain.
    const normalized = canonicalNetworkId(networkString);
    if (!normalized) {
        throw new Error(`Unknown network: ${networkString}. Refusing to guess a default network.`);
    }

    return normalized;
}


function getNetwork(networkString) {
    return networkList[networkString];
}


function generateLitecoinAddress() {
  const keyPair = bitcoin.ECPair.makeRandom({ network: litecoinNetwork });
  const { address } = bitcoin.payments.p2pkh({
    pubkey: keyPair.publicKey,
    network: litecoinNetwork,
  });

  console.log('Litecoin Address:', address);
  return address;
}

const encodeSignature = (signature) => {
  const { r, s, recoveryParam } = signature;

  // Concatenate r and s
  const rBuffer = Buffer.from(r, 'hex');
  const sBuffer = Buffer.from(s, 'hex');

  // Combine into a single hex string
  const combinedSignature = Buffer.concat([rBuffer, sBuffer]);

  // Optionally append the recovery param if needed
  const fullSignature = recoveryParam !== undefined
    ? Buffer.concat([combinedSignature, Buffer.from([recoveryParam])])
    : combinedSignature;

  return fullSignature.toString('hex'); // Return the signature in hex
};

const signString = async (privateKeyHex, message) => {
  const key = ecdsa.keyFromPrivate(privateKeyHex);
  const messageHash = ecdsa.hash().update(message).digest('hex');
  const signature = key.sign(messageHash);
  // Low-S normalization (BIP-62 canonical form): elliptic returns high-S
  // signatures ~2/3 of the time. Enforce s = min(s, n - s) so signatures are
  // non-malleable and low-S-only verifiers accept them. Flipping s flips the
  // parity of R used for public-key recovery, so recoveryParam flips too.
  const n = ecdsa.curve.n;
  if (signature.s.cmp(n.ushrn(1)) > 0) {
    signature.s = n.sub(signature.s);
    if (signature.recoveryParam !== undefined && signature.recoveryParam !== null) {
      signature.recoveryParam ^= 1;
    }
  }
  return signature;
};

function uint8ArrayToHex(uint8Array) {
  return Buffer.from(uint8Array).toString('hex');
}

function uint8ArrayToBase64(uint8Array) {
  return Buffer.from(uint8Array).toString('base64');
}

function extractNetworkName(network) {
  if (typeof network === 'string') {
    return network.toUpperCase(); // Return directly if already a string
  }

  if (typeof network === 'object' && network !== null) {
    // Map by bech32 prefix
    if (network.bech32 === 'ltc') return 'LTC';
    if (network.bech32 === 'tltc') return 'LTCTEST';
    if (network.bech32 === 'bc') return 'BTC';
    if (network.bech32 === 'tb') return 'BTCTEST';

    // Map Dogecoin based on fallback properties
    if (network.pubKeyHash === 0x1e && network.scriptHash === 0x16) return 'DOGE'; // Dogecoin mainnet
    if (network.pubKeyHash === 0x71 && network.scriptHash === 0xc4) return 'DOGETEST'; // Dogecoin testnet

    // Add additional checks here if more network types are introduced
  }
}

export const generateAddressFromSeed = async (encryptedSeed, network, password) => {
  //console.log('Seed:', seedPhrase);
    // Decrypts both v2 vault blobs and legacy CryptoJS blobs (auto-detected).
    // Legacy decryptions are only accepted when the plaintext is a valid BIP39
    // mnemonic (PLAINTEXT_KIND.SEED): wrong-password garbage is rejected as a
    // wrong password BEFORE any migration can overwrite the stored ciphertext.
    const { plaintext: decryptedSeed, legacy: legacySeedFormat } =
      await decryptWithPasswordInfo(encryptedSeed, password, PLAINTEXT_KIND.SEED);
    let serializedSeed = decryptedSeed.trim();
    if (!serializedSeed) {
      throw new Error('Failed to decrypt seed.');
    }

    if (legacySeedFormat) {
      // Transparent migration: upgrade legacy CryptoJS seed blobs to v2
      // (plaintext validated above; maybeUpgradeStoredBlob also refuses
      // invalid plaintext and keeps the old ciphertext as a backup).
      await maybeUpgradeStoredBlob('encryptedSeed', encryptedSeed, decryptedSeed, password, PLAINTEXT_KIND.SEED);
    }

    let normalizedNetwork
    let selectedNetwork
  if (typeof network === 'string') {
    normalizedNetwork = normalizeNetwork(network);
    selectedNetwork = networkList[normalizedNetwork];
  } else if (typeof network === 'object' && network !== null) {
    normalizedNetwork = extractNetworkName(network)
    selectedNetwork = network;
  } else {
    throw new Error('Invalid network parameter. Must be a string or a network object.');
  }

    // Get the derivation path for the selected network
    const path = DERIVATION_PATHS[normalizedNetwork];
    if (!path) {
        throw new Error(`No derivation path found for network: ${normalizedNetwork}`);
    }

  try {
    // Convert seed phrase into a seed buffer
    const seed = bip39.mnemonicToSeedSync(serializedSeed);

    // Create HD node from seed
    const hdNode = bip32.fromSeed(seed, selectedNetwork);

    if (hdNode.isNeutered()) {
      throw new Error('HD Node is neutered and lacks a private key.');
    }

    // Derive the keypair based on the BIP44 path
    const derivedNode = hdNode.derivePath(path);

    if (!derivedNode.privateKey) {
      throw new Error('Derived node lacks a private key.');
    }

    // Convert public key to hex
    const publicKeyHex = uint8ArrayToHex(derivedNode.publicKey);

    // Generate a Bitcoin address
    
    let address;

    // Generate a P2PKH address for Dogecoin
    if (normalizedNetwork === "DOGE" || normalizedNetwork === "DOGETEST") {
        const payment = bitcoin.payments.p2pkh({
            pubkey: derivedNode.publicKey,
            network: selectedNetwork, // Dogecoin network parameters
        });

        address = payment.address;
    }else{
         const payment = bitcoin.payments.p2wpkh({
        pubkey: derivedNode.publicKey,
        network: selectedNetwork,
        });

      address = payment.address; // Assign to the outer "address" variable
    }
    
    // Convert private key to base64 and encrypt it (v2 vault format)
    const privateKeyBase64 = uint8ArrayToBase64(derivedNode.privateKey);
   // console.log('Private key (base64):', privateKeyBase64);
    // v2 encryption requires a non-empty password. Legacy empty-password
    // wallets (allowed on the legacy read path) can still unlock; their key is
    // simply not cached until they set a password (Settings → Reset Password).
    const ciphertext = password === '' ? null : await encryptWithPassword(privateKeyBase64, password);

    // Clear sensitive data from memory
    seed.fill(0);
    hdNode.privateKey?.fill(0);
    derivedNode.privateKey?.fill(0);

    return {
      address,
      publicKey: publicKeyHex,
      privateKey: ciphertext, // Encrypted private key
      derivationPath: path,
      network: normalizedNetwork,
    };
  } catch (error) {
    console.error('Error generating address from seed:', error);
    throw error;
  }
};


export function addMultisigAddress(m, pubkeys, network) {
  if (pubkeys.length < m) {
    throw new Error('Not enough public keys to meet the required number of signatures');
  }

  // Properly resolve network using the helper
  const { normalized, network: selectedNetwork } = resolveNetwork(network);
  console.log('selected network in add multisig:', normalized, selectedNetwork.bech32);

  // Convert public keys from hex to buffers
  const pubkeyBuffers = pubkeys.map((hex) => Buffer.from(hex, 'hex'));

  // Generate the P2WSH address (bech32 only, no P2SH wrapping)
  const p2msData = bitcoin.payments.p2ms({
    m,
    pubkeys: pubkeyBuffers,
    network: selectedNetwork,
  });

  const p2wshData = bitcoin.payments.p2wsh({
    redeem: p2msData, // Multisig script as witnessScript
    network: selectedNetwork,
  });

  // Serialize the witness script
  const witnessScriptHex = Buffer.from(p2msData.output).toString('hex')
  const scriptPubKey = p2wshData.output.toString('hex');
  console.log(`Generated Bech32 (P2WSH) Multisig Address: ${p2wshData.address}`);
  console.log(`Serialized Witness Script (Hex): ${witnessScriptHex}`);

  const newMultisig = {
    address: p2wshData.address,
    redeemScript: witnessScriptHex,
    scriptPubKey: scriptPubKey,
    pubkeys,
    m,
    network: normalized,
  };

  // Save to localStorage (or elsewhere)
  const multisigs = JSON.parse(localStorage.getItem('multisigs') || '[]');
  multisigs.push(newMultisig);
  
  localStorage.setItem('multisigs', JSON.stringify(multisigs));
  
  // Update chrome.storage.local asynchronously
  (async () => {
    try {
      await new Promise((resolve, reject) => {
        chrome.storage.local.set({ multisigs }, () => {
          if (chrome.runtime.lastError) {
            console.error('Error saving multisig to chrome.storage.local:', chrome.runtime.lastError);
            reject(chrome.runtime.lastError);
          } else {
            console.log('Multisig Address saved to chrome.storage.local:', { multisigs });
            resolve();
          }
        });
      });
    } catch (err) {
      console.error('Failed to update chrome.storage.local:', err);
    }
  })();

  // Immediately return the new multisig object
  return newMultisig;
}


export function buildUnsignedPSBT({
  buyerKeyPair,
  sellerKeyPair,
  amount,
  payload,
  commitUTXOs,
  outputs,
  network,
  sats
}) {
  console.log("Building PSBT with params:", {
    buyerKeyPair,
    sellerKeyPair,
    amount,
    payload,
    commitUTXOs,
    outputs,
    network,
  });
  
  // Properly resolve network
  const { normalized, network: test } = resolveNetwork(network);
  console.log('buildUnsignedPSBT using network:', normalized, test.bech32);

  console.log('showing network config '+JSON.stringify(test))
  const allUTXOs = [...commitUTXOs, ...outputs];

  const buyerAddress = buyerKeyPair.address;
  const sellerAddress = sellerKeyPair.address;

  if (!buyerAddress || !sellerAddress) {
    throw new Error("Invalid buyer or seller address");
  }

  const satsPaid = Math.floor(amount * 1e8); // Convert LTC to satoshis
  const fee = 0.0001; // Example fee in LTC
  const feeInSats = Math.floor(fee * 1e8); // Fee in satoshis

  const commitInput = commitUTXOs[0];
  const requiredInputs = [commitInput];

  let remainingSats = satsPaid + feeInSats;
  remainingSats -= Math.floor(commitInput.amount * 1e8);

  console.log("Initial remainingSats (after commitUTXO):", remainingSats);

  for (const utxo of outputs) {
    if (remainingSats <= 0) break;
    requiredInputs.push(utxo);
    remainingSats -= Math.floor(utxo.amount * 1e8);
  }

  if (remainingSats > 0) {
    throw new Error("Not enough UTXOs to cover the payment amount and fees");
  }

  const inputSum = requiredInputs.reduce((sum, utxo) => sum + utxo.amount, 0); // LTC
  const buyerChange = inputSum - (satsPaid / 1e8) - fee;

  console.log("satsPaid (in satoshis):", satsPaid);
  console.log("Fee (in satoshis):", feeInSats);
  console.log("Input Sum (in LTC):", inputSum);
  console.log("Buyer Change (in LTC):", buyerChange);

  if (buyerChange < 0) {
    throw new Error("Insufficient funds after accounting for payment amount and fees");
  }

  const psbtOutputs = [
    { address: buyerAddress, value: Math.floor(buyerChange * 1e8) },
    { address: sellerAddress, value: satsPaid },
  ];

  console.log("PSBT Outputs:", psbtOutputs);

  const psbt = new bitcoin.Psbt({ network:test });



  for (const utxo of requiredInputs) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: {
        script: Uint8Array.from(Buffer.from(utxo.scriptPubKey, "hex")),
        value: BigInt(Math.floor(utxo.amount * 1e8)), 
      },
    });
  }

  console.log('psbt outputs '+JSON.stringify(psbtOutputs))

  for (const output of psbtOutputs) {
      console.log("Adding Output:", output);
    psbt.addOutput({
      address: output.address,
      value: output.value,
    });
  }

  if (payload) {
    const opReturnOutput = bitcoin.script.compile([
      bitcoin.opcodes.OP_RETURN,
      Buffer.from(payload, "utf8"),
    ]);
    psbt.addOutput({
      script: opReturnOutput,
      value: 0,
    });
  }

  console.log("Generated PSBT:", psbt.toBase64());
  return { psbt: psbt.toHex() };
}


// Helper function to select UTXOs
const selectInputs = (utxos, targetAmount) => {
  let total = 0;
  const selected = [];

  for (const utxo of utxos) {
    selected.push(utxo);
    total += utxo.amount;
    if (total >= targetAmount) break;
  }

  return total >= targetAmount ? selected : null;
}

/**
 * Build a LTC transaction using bitcoinjs-lib (or litecoinjs-lib).
 * @param {string} fromAddress - source address
 * @param {string} toAddress - destination address
 * @param {number} amount - in LTC
 * @param {array} utxos - array of { txid, vout, amount, scriptPubKey }
 * @param {number} fee - in LTC (or compute dynamically)
 * @param {Network} network - e.g. networks.LTCTEST
 */
export async function buildPsbtLocally({ fromAddress, toAddress, amount, utxos, fee, network }) {
  // Convert LTC to satoshis
  const amountInSats = Math.round(amount * 1e8);
  const feeInSats = Math.round(fee * 1e8);

  // 1) Choose enough inputs
  const { chosen, foundEnough } = selectInputs(utxos, amount + fee);
  if (!foundEnough) {
    throw new Error('Not enough funds');
  }

  // 2) Create a new PSBT
  const psbt = new bitcoin.Psbt({ network });

  // 3) Add each chosen input
  chosen.forEach((utxo) => {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      // For segwit LTC P2WPKH, provide witnessUtxo
      witnessUtxo: {
        script: Buffer.from(utxo.scriptPubKey, 'hex'),
        value: Math.round(utxo.amount * 1e8),  // satoshis
      },
    });
  });

  // 4) Calculate change
  const totalIn = chosen.reduce((sum, u) => sum + Math.round(u.amount * 1e8), 0);
  const change = totalIn - amountInSats - feeInSats;
  if (change < 0) {
    throw new Error('Not enough to cover amount + fee');
  }

  // 5) Add output to the recipient
  psbt.addOutput({
    address: toAddress,
    value: amountInSats,
  });

  // 6) If there's leftover, add change output
  if (change > 0) {
    psbt.addOutput({
      address: fromAddress, // send change back
      value: change,
    });
  }

  return psbt;
}



export const sendBTC = async (fromAddress, address, amount) => {
  try {

   
    console.log('From Address:', fromAddress);

    // Step 1: Fetch UTXOs (use your method to fetch UTXOs for the address)
    const utxos = await fetchUTXOs(fromAddress);  // Define this function to fetch UTXOs from a block explorer

    // Step 2: Create a transaction
    const txb = new bitcoin.TransactionBuilder();

    // Step 3: Add inputs from UTXOs (assuming they have the necessary information)
    utxos.forEach((utxo) => {
      txb.addInput(utxo.txid, utxo.vout);
    });

    // Add output: send to the specified address
    const amountInSatoshis = amount * 1e8; // Convert BTC to satoshis (1 BTC = 100000000 satoshis)
    txb.addOutput(address, amountInSatoshis);

    // Add change output (sending change to the same address)
    const changeAmount = utxos.reduce((sum, utxo) => sum + utxo.value, 0) - amountInSatoshis - 1000;  // Subtract fee (e.g., 1000 sats as the fee)
    txb.addOutput(fromAddress, changeAmount);

    // Step 6: Get the raw transaction hex
    const rawTx = txb.build().toHex();

    // Step 7: Decode the transaction (inputs, outputs, raw hex)
    const decodedTx = decodeTransaction(rawTx);  // This function decodes the transaction for display
    console.log('decoded '+JSON.stringify(decodedTx))
    // Step 7: Return the decoded transaction data for display
    return decodedTx
  } catch (error) {
    throw new Error('Error sending BTC: ' + error.message);
  }
};

// Function to decode the transaction and extract inputs, outputs, and raw hex
const decodeTransaction = (rawTx) => {
  const tx = bitcoin.Transaction.fromHex(rawTx);

  // Decode inputs and outputs
  const inputs = tx.ins.map((input) => ({
    txid: Buffer.from(input.hash).reverse().toString('hex'),
    vout: input.index,
    scriptSig: input.script.toString('hex'),
  }));

  const outputs = tx.outs.map((output) => ({
    value: output.value / 1e8,  // Convert from satoshis to BTC
    scriptPubKey: output.script.toString('hex'),
  }));

  // Return the decoded data
  return {
    hex: rawTx,       // Raw hex string of the transaction
    inputs: inputs,   // Array of input details
    outputs: outputs, // Array of output details
  };
};


// Example placeholder function to fetch UTXOs from a block explorer
export const fetchUTXOs = async (address) => {
  try {
    // Define BlockCypher API URL to fetch address details
    const url = `https://api.blockcypher.com/v1/btc/main/addrs/${address}/full`;

    // Fetch UTXOs for the given address using the BlockCypher API
    const response = await axios.post(url, address);
    const data = await response.json();

    // Ensure the response contains unspent outputs (UTXOs)
    if (!data || !data.txrefs) {
      throw new Error('No UTXOs found for the provided address');
    }

    // Map the UTXO data to the required format
    const utxos = data.txrefs.map((utxo) => ({
      txid: utxo.tx_hash,   // Transaction ID
      vout: utxo.tx_output_n,  // Output index
      value: utxo.value,    // Value in satoshis
    }));

    // Return the formatted UTXOs
    return utxos;
  } catch (error) {
    console.error('Error fetching UTXOs:', error.message);
    throw error;  // Re-throw the error to be handled by the caller
  }
};

// Generate a random 12-word mnemonic using BIP39
export function generateMnemonic() {
  const seed = bip39.generateMnemonic();  // Generates a 12-word mnemonic
  //console.log(seed);
  return seed
}


// Best-effort cache hygiene for unlock and setup (the same password, so a
// leftover cache is not a password-retirement problem). Password changes and
// restores do not rely on this: a seed write sweeps the caches itself, under
// the vault lock, and fails closed if the sweep fails (see secureVault.js).
export function clearPrivateKeyCaches() {
  try {
    removeKeyCaches(localStorage);
  } catch (_) {}
}


// Sign a message with the private key using ECDSA (secp256k1).
// The signing key is always derived/fetched for the REQUESTED network (the
// same getOrDeriveKeyPair flow used for PSBT signing), never from the
// last-unlocked network's cached key, so a request can't be signed by a key
// belonging to a different network.
export async function signMessage(message, password, network) {
  if (!network) {
    throw new Error('A target network is required to sign a message.');
  }

  let privateKeyBase64 = null;
  let keyBuffer = null;
  let privateKeyHex = null;
  try {
    // Resolving the network here fails closed on unknown network strings.
    privateKeyBase64 = await getSigningKeyBase64(password, network);

    // Same key-length validation as signTransaction / signInputsInPsbt:
    // the cached plaintext must be base64 of exactly 32 raw key bytes.
    keyBuffer = Buffer.from(privateKeyBase64, 'base64');
    privateKeyBase64 = null;
    if (keyBuffer.length !== 32) {
      throw new Error(`Invalid private key length: ${keyBuffer.length}`);
    }
    privateKeyHex = keyBuffer.toString('hex');
    zeroBuffer(keyBuffer);
    keyBuffer = null;

    const signature = await signString(privateKeyHex, message);
    // DER-encoded signature as hex (Signature.toString() is not a serializer).
    return signature.toDER('hex');
  } finally {
    zeroBuffer(keyBuffer);
    privateKeyBase64 = null;
    privateKeyHex = null;
    password = '';
  }
}


// Real password verification: decrypt the stored seed with the candidate
// password and report success only when decryption succeeds. Works for both
// the v2 vault format and legacy CryptoJS blobs.
// `network`/`expectedAddress` are kept for call-site compatibility.
export async function checkPasswordMatch(password, network, expectedAddress) {
  try {
    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!encryptedSeed) {
      return false;
    }
    // Must decrypt to a valid BIP39 mnemonic: legacy CryptoJS decryptions are
    // unauthenticated and wrong passwords can yield non-empty garbage.
    await decryptWithPasswordInfo(encryptedSeed, password, PLAINTEXT_KIND.SEED);
    return true;
  } catch (_) {
    return false;
  }
}


export async function getOrDeriveKeyPair(password, network) {
  const { normalized } = resolveNetwork(network);
  const path = DERIVATION_PATHS[normalized];
  const storageLabel = privateKeyCacheLabel(normalized, path);
  let encryptedPrivateKey = localStorage.getItem(storageLabel);

  if (!encryptedPrivateKey) {
    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!encryptedSeed) {
      throw new Error('No encrypted seed found.');
    }

    let address = await generateAddressFromSeed(encryptedSeed, network,password);
    if (!address || !address.privateKey) {
      // generateAddressFromSeed cannot cache a v2 key blob without a password
      // (legacy empty-password wallets): direct them to set one first.
      if (!password) {
        throw new Error('Signing needs a cached key: set a password first (Settings → Reset Password).');
      }
      throw new Error('Failed to derive private key from seed.');
    }
    // Cache the key as a v2 vault blob through the vault write primitive. It is
    // stored only if it opens under this password as a 32-byte key and the live
    // seed still opens under this password. If another page cached the key
    // first, that entry is used instead.
    encryptedPrivateKey = address.privateKey;
    try {
      await storeKeyCacheBlob(storageLabel, encryptedPrivateKey, password);
    } catch (error) {
      const cachedElsewhere = isStoredBlobConflictError(error) ? localStorage.getItem(storageLabel) : null;
      if (!cachedElsewhere) throw error;
      encryptedPrivateKey = cachedElsewhere;
    }
    password = null
    address = null
  }

  return encryptedPrivateKey
}


// Decrypts a key cache entry. Key caches must decrypt to base64 of exactly 32
// raw key bytes (validated by decryptWithPasswordInfo); anything else is null.
const openKeyCache = async (blob, password) => {
  try {
    return await decryptWithPasswordInfo(blob, password, PLAINTEXT_KIND.PRIVATE_KEY);
  } catch (_) {
    return null;
  }
};

// Decrypt the network's private key for signing, transparently upgrading
// legacy (CryptoJS) cache entries to the v2 vault format. Returns the raw
// private key as a base64 string; callers must clear their reference ASAP.
export async function getSigningKeyBase64(password, network) {
  const { normalized } = resolveNetwork(network);
  const path = DERIVATION_PATHS[normalized];
  const storageLabel = privateKeyCacheLabel(normalized, path);
  // A key cache is used only while the live seed also opens under this
  // password. Otherwise the cache is stale: it belongs to a password that the
  // seed no longer accepts (a retired password must not sign), or it was left
  // for a previous seed (then it is discarded and the key is derived again).
  let encryptedPrivateKey = await getOrDeriveKeyPair(password, normalized);
  let opened = await openKeyCache(encryptedPrivateKey, password);
  const seedOpens = await liveSeedOpensUnder(password);
  if (opened && !seedOpens) {
    await discardKeyCacheBlob(storageLabel, encryptedPrivateKey);
    throw new Error('The wallet does not open under this password.');
  }
  if (!opened) {
    if (!seedOpens) {
      throw new Error('Failed to decrypt vault data: wrong password or corrupted data.');
    }
    await discardKeyCacheBlob(storageLabel, encryptedPrivateKey);
    encryptedPrivateKey = await getOrDeriveKeyPair(password, normalized);
    opened = await openKeyCache(encryptedPrivateKey, password);
    if (!opened) {
      throw new Error('Failed to derive private key from seed.');
    }
  }
  const { plaintext, legacy } = opened;
  if (legacy) {
    // Transparent migration: rewrite legacy cached keys in the v2 format. The
    // primitive's cache guard applies, as for any cache write.
    await maybeUpgradeStoredBlob(storageLabel, encryptedPrivateKey, plaintext, password, PLAINTEXT_KIND.PRIVATE_KEY);
  }
  return plaintext;
}


export async function signTransaction(requestPayload, password, network) {
  let privateKeyBase64 = null;
  let keyBuffer = null;
  let keyPair = null;
  try {
    let {
      fromKeyPair,
      toKeyPair,
      amount,
      inputs,
      payload
    } = requestPayload;
    
    // Properly resolve network
    const { normalized, network: test } = resolveNetwork(network);
    console.log('signTransaction using network:', normalized, test.bech32);
    
    // Validate that inputs exists and provide helpful error
    if (!inputs || !Array.isArray(inputs)) {
      console.error('❌ No inputs (UTXOs) provided in request payload.');
      console.error('Inputs received:', inputs);
      console.error('From address:', fromKeyPair.address);
      console.error('💡 Tip: Use buildSignSendTxGrabUTXO or fetch UTXOs before signing');
      throw new Error(
        'Transaction inputs (UTXOs) are required. ' +
        'Received: ' + typeof inputs + '. ' +
        'Use buildSignSendTxGrabUTXO() or fetch UTXOs for address: ' + fromKeyPair.address
      );
    }
    
    if (inputs.length === 0) {
      console.error('❌ Inputs array is empty for address:', fromKeyPair.address);
      throw new Error('No UTXOs available for address: ' + fromKeyPair.address);
    }
    
    console.log('✅ Validated inputs:', inputs.length, 'UTXOs available');
    
    // 1) Derive or decrypt private key (v2 vault, with legacy cache migration)
    if(!amount||isNaN(amount)){
        amount = 0.0000546
    }
    privateKeyBase64 = await getSigningKeyBase64(password, test);
    password=null

    // Decode base64 into a raw buffer
    keyBuffer = Buffer.from(privateKeyBase64, 'base64');
    privateKeyBase64= null
  
    // Ensure the buffer has a valid private key length
    if (keyBuffer.length !== 32) {
      throw new Error(`Invalid private key length: ${keyBuffer.length}`);
    }

    // Create ECPair from private key buffer (pass a copy: ECPair keeps a
    // reference and the temporary buffer is zeroed immediately below)
    keyPair = ECPair.fromPrivateKey(Buffer.from(keyBuffer), { network: test });
    zeroBuffer(keyBuffer);
    keyBuffer = null
    password = null
    // The change address and every input come from the wallet's own key, never
    // from the page-supplied request (see spendGuards.js).
    const own = ownP2wpkh(keyPair.publicKey, test);
    // 2) Convert LTC => satoshis
    // Note: must create a BigInt for final `value` in witnessUtxo
    const satsNeeded = BigInt(Math.round(amount * 1e8));

    // We'll do a simple coin selection from the UTXOs
    let selectedInputs = [];
    let totalSat = 0n;
    // Sort descending (NOW SAFE - inputs is validated as an array)
    const sortedUtxos = inputs.sort((a, b) => b.amount - a.amount);
    for (const u of sortedUtxos) {
      selectedInputs.push(u);
      totalSat += BigInt(Math.round(u.amount * 1e8));
      // e.g. ~ 0.0001 LTC for fee
      if (totalSat >= satsNeeded + 10000n) {
        break;
      }
    }
    if (totalSat < satsNeeded) {
      throw new Error("Not enough funds.");
    }
    assertLegacySpendOwned({
      fromKeyPair,
      selectedInputs,
      ownAddress: own.address,
      ownScript: own.script,
    });
    console.log('about to make psbt '+JSON.stringify(test))
    // 3) Create a PSBT
    const psbt = new bitcoin.Psbt({ network: test });
    console.log('psbt naked '+JSON.stringify(psbt))
    // 4) Add inputs w/ witnessUtxo
    selectedInputs.forEach((inp) => {
      // Convert JSON { type: 'Buffer', data: [...] } to real Buffer if needed
      // If inp.scriptPubKey is a hex string, do Buffer.from(inp.scriptPubKey, 'hex')
      // If it's an object {type:'Buffer',data:...}, do Buffer.from(inp.scriptPubKey.data)
      // Below is a typical approach if scriptPubKey is hex:
      const scriptPubKeyBuffer = Buffer.from(inp.scriptPubKey, 'hex');

      // For value, we must use BigInt
      const valueBigInt = BigInt(Math.round(inp.amount * 1e8));

      psbt.addInput({
        hash: inp.txid,        // e.g. "8685042eed9..."
        index: inp.vout,       // e.g. 0
        witnessUtxo: {
          script: scriptPubKeyBuffer,
          value: valueBigInt,
        },
      });
    });

    console.log('selected Inputs:', selectedInputs);

    // 5) Calculate fee and change
    const feeSats = 10000n; // e.g. 0.0001 LTC
    const change = totalSat - satsNeeded - feeSats;
    console.log('to key pair in send/sign '+toKeyPair.address)
    
    // Helper to build a payment strictly for the selected network. If the
    // address does not parse on it, fail with a clear error instead of
    // silently retrying on a different network.
    const buildPayment = (paymentFn, address) => {
      try {
        return paymentFn({ address, network: test });
      } catch (e) {
        throw new Error(
          `Recipient address is not valid on the ${normalized} network: ${e.message}`
        );
      }
    };

    let payment;

    if(toKeyPair.address.length>=62){
      payment = buildPayment(bitcoin.payments.p2wsh, toKeyPair.address);
    } else if(toKeyPair.address.length<46){
      payment = buildPayment(bitcoin.payments.p2wpkh, toKeyPair.address);
    } else {
      payment = buildPayment(bitcoin.payments.p2wpkh, toKeyPair.address);
    }

    const output = {
      script: payment.output, // This should be a `Buffer` (internally a `Uint8Array`)
      value: satsNeeded, // Must be a `BigInt`
    };

     // 6) Outputs
   const psbt2 = addOutputDebug(psbt,output);

    console.log('Adding output:', output);

    const payment2 = buildPayment(bitcoin.payments.p2wpkh, own.address);

     const output2 = {
      script: payment2.output, // This should be a `Buffer` (internally a `Uint8Array`)
      value: change, // Must be a `BigInt`
    };

     console.log('change '+change +' '+Boolean(change>0n))
    if (change > 0n) {
       psbt2.addOutput(output2);
    }

    // If there's an OP_RETURN payload
    if (payload) {
      const data = Buffer.from(payload, 'utf8');
      const embed = bitcoin.payments.embed({ data: [data] });
      psbt2.addOutput({ script: embed.output, value: 0n });
    }

    // 7) Sign
    // If multiple inputs, you might signAllInputs or loop over signInput(i, keyPair)
    // If multiple inputs, you might signAllInputs or loop over signInput(i, keyPair)
    // Every input is signed with SIGHASH_ALL (see spendGuards.js).
    for (let index = 0; index < psbt.inputCount; index++) {
      signInputAllOutputs(psbt, index, keyPair);
    }

    // 8) Finalize
    psbt.finalizeAllInputs();

    // 9) Extract final TX
    const finalTx = psbt.extractTransaction();
    const rawTx = finalTx.toHex();
    const txid = finalTx.getId();

    // Return success
    return {
      success: true,
      data: { rawTx, txid },
    };
  } finally {
    zeroBuffer(keyBuffer);
    keyBuffer = null;
    keyPair = null;
    privateKeyBase64 = null;
    password = null;
  }
}

function addOutputDebug(psbt, output) {
  console.log('Attempting to add output:', output);

  // Check if `script` is defined
  if (output.script === undefined) {
    console.error('Output script is undefined.');
  } else if (!(output.script instanceof Uint8Array)) {
    console.error('Output script is not an instance of Uint8Array. Type:', typeof output.script);
  }

  // Check if `value` is defined
  if (output.value === undefined) {
    console.error('Output value is undefined.');
  } else if (typeof output.value !== 'bigint') {
    console.error('Output value is not a BigInt. Type:', typeof output.value);
  }

  // Log specific checks
  console.log('Output script type:', output.script instanceof Uint8Array);
  console.log('Output value type:', typeof output.value);

  // Add output to PSBT
  psbt.addOutput(output);
  return psbt
}
export const signInputsInPsbt = async (
  psbtHex,
  network,
  password,
  sellerFlag,
  witnessScript  // ← ADDED: 5th parameter for witnessScript from relayer
) => {
  const { normalized, network: test } = resolveNetwork(network);
  console.log('signInputsInPsbt using network:', normalized, test.bech32);
  console.log('witnessScript provided:', witnessScript ? 'YES (' + witnessScript.substring(0, 20) + '...)' : 'NO');

  console.log("Starting PSBT signing process... with sellerFlag? " + sellerFlag);

  let privateKeyBase64 = null;
  let keyBuffer = null;
  let keyPair = null;

  try {
    // Step 1: Reinitialize PSBT from provided hex
    const psbt = bitcoin.Psbt.fromHex(psbtHex, { network: test });
    console.log("Decoded PSBT:", psbt.data);
    console.log("Number of inputs:", psbt.data.inputs.length);

    // Step 2: Derive or decrypt private key for signing (v2 vault, with legacy cache migration)
    privateKeyBase64 = await getSigningKeyBase64(password, test);
    password = null;

    // Decode base64 into a raw buffer
    keyBuffer = Buffer.from(privateKeyBase64, 'base64');
    privateKeyBase64 = null;
    
    // Ensure the buffer has a valid private key length
    if (keyBuffer.length !== 32) {
      throw new Error(`Invalid private key length: ${keyBuffer.length}`);
    }

    // Create ECPair from private key buffer (pass a copy: ECPair keeps a
    // reference and the temporary buffer is zeroed immediately below)
    keyPair = ECPair.fromPrivateKey(Buffer.from(keyBuffer), { network: test });
    zeroBuffer(keyBuffer);
    keyBuffer = null;
    password = null;

    // Step 3: bind inputs to their witness scripts (seller, or when the relayer
    // supplies one). The relayer's script covers input 0; other inputs take the
    // registered script for their address.
    if (sellerFlag || witnessScript) {
      psbt.data.inputs.forEach((input, index) => {
        if (witnessScript && index === 0) {
          bindWitnessScript(psbt, index, witnessScript, test);
          return;
        }
        const redeemScript = registeredRedeemScript(input, test);
        if (redeemScript) {
          bindWitnessScript(psbt, index, redeemScript, test);
        }
      });
    }

    // Step 4: Sign Inputs
    psbt.data.inputs.forEach((input, index) => {
      console.log(`Signing input ${index}...`);

    if (index > 0 && sellerFlag === true) {
      console.log('seller flag has us exiting after signing input 0');
      return;
    }

    console.log(`Input ${index} details:`, input);
    console.log(`SighashType for input ${index}:`, bitcoin.Transaction.SIGHASH_ALL);
    
    try {
      if (input.witnessScript) {
        console.log('signing multisig input ' + index);
        // P2WSH signing requires the witnessScript
        signInputAllOutputs(psbt, index, keyPair);
      } else {
        console.log('signing vanilla input ' + index);
        // Standard signing for non-multisig inputs
        signInputAllOutputs(psbt, index, keyPair);
      }
      console.log(`Successfully signed input ${index}`);
    } catch (err) {
      console.error(`Failed to sign input ${index}:`, err);
      throw err;  // Re-throw to catch in SignPSBT component
    }
    });

    // Step 6: Finalize inputs if buyer (sellerFlag=false)
    let rawTx = "";
    if (!sellerFlag) {
      try {
        psbt.finalizeAllInputs();
        console.log("Finalized all inputs successfully.");
      } catch (finalizeError) {
        console.error("Failed to finalize inputs:", finalizeError);
        throw new Error("Finalization of inputs failed: " + finalizeError.message);
      }

      // Step 7: Extract the final transaction
      const finalTx = psbt.extractTransaction();
      rawTx = finalTx.toHex();
      const txid = finalTx.getId();

      console.log("Final transaction created:", { txid, rawTx });
      return {
        success: true,
        data: { rawTx, txid },
      };
    } else {
      // Seller returns partial PSBT
      rawTx = psbt.toHex();
      console.log('returning unfinished PSBT hex (length: ' + rawTx.length + ')');
      return {
        success: true,
        data: { rawTx },
      };
    }
  } finally {
    zeroBuffer(keyBuffer);
    keyBuffer = null;
    privateKeyBase64 = null;
    keyPair = null;
    password = null;
  }
};

// The one place a witness script is attached to a PSBT input. The UTXO script
// must commit to it. The script is checked here and never rewritten: a
// rewritten script would make the wallet sign for a UTXO the user was not shown.
function bindWitnessScript(psbt, index, witnessScriptHex, network) {
  const input = psbt.data.inputs[index];
  const witnessScript = Buffer.from(witnessScriptHex, 'hex');
  const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript }, network });
  const utxoScript = input.witnessUtxo?.script;
  if (!utxoScript || utxoScript.length === 0 || !Buffer.from(utxoScript).equals(Buffer.from(p2wsh.output))) {
    throw new Error(
      `Input ${index}: the UTXO script does not match the witness script; refusing to sign.`
    );
  }
  input.witnessScript = witnessScript;
}

// The registered witness script for the P2WSH address this input pays to, or
// that the PSBT names for it. Null when the wallet has no entry for it.
function registeredRedeemScript(input, network) {
  let address = null;
  if (input.witnessScript && input.witnessScript.length > 0) {
    address = getAddressFromWitnessScript(input.witnessScript, network);
  } else if (input.witnessUtxo?.script?.length > 0) {
    // Any standard script has an address (P2WPKH and P2WSH alike); a
    // P2WPKH-only decoder throws on a 34-byte P2WSH script.
    address = safeAddressFromOutputScript(input.witnessUtxo.script, network);
  }
  const entry = address ? getMultisigData(address) : undefined;
  return entry?.redeemScript ?? null;
}

function getMultisigData(bech32Address) {
  const multisigs = JSON.parse(localStorage.getItem('multisigs') || '[]');
  return multisigs.find((ms) => ms.address === bech32Address);
}

function getAddressFromWitnessScript(witnessScript, network) {
  const payment = bitcoin.payments.p2wsh({
    redeem: { output: witnessScript },
    network,
  });
  return payment.address;
}



function safeAddressFromOutputScript(script, network) {
  try {
    return bitcoin.address.fromOutputScript(Buffer.from(script), network);
  } catch {
    return null;
  }
}

function decodeOpReturn(script) {
  try {
    const chunks = bitcoin.script.decompile(script) || [];
    const payload = chunks.find((chunk) => chunk instanceof Uint8Array);
    return payload ? Buffer.from(payload).toString('utf8') : null;
  } catch {
    return null;
  }
}

export function summarizePsbtForDisplay(psbtHex, networkInput, ownAddresses = []) {
  const { normalized, network } = resolveNetwork(networkInput);
  const psbt = bitcoin.Psbt.fromHex(psbtHex, { network });
  const unsignedOutputs = psbt.txOutputs || [];

  const inputs = psbt.data.inputs.map((input, index) => {
    const witnessUtxo = input.witnessUtxo;
    const valueSats = witnessUtxo?.value != null ? Number(witnessUtxo.value) : null;
    const address = witnessUtxo?.script
      ? safeAddressFromOutputScript(witnessUtxo.script, network)
      : null;

    return {
      index,
      address,
      valueSats,
    };
  });

  const outputs = unsignedOutputs.map((output, index) => {
    const address = safeAddressFromOutputScript(output.script, network);
    const valueSats = Number(output.value);
    const isOpReturn = output.script?.[0] === bitcoin.opcodes.OP_RETURN;

    return {
      index,
      address,
      valueSats,
      isChange: address ? ownAddresses.includes(address) : false,
      isOpReturn,
      opReturnText: isOpReturn ? decodeOpReturn(output.script) : null,
    };
  });

  const totalInputSats = inputs.reduce((sum, input) => sum + (input.valueSats || 0), 0);
  const totalOutputSats = outputs.reduce((sum, output) => sum + output.valueSats, 0);

  return {
    network: normalized,
    inputCount: inputs.length,
    outputCount: outputs.length,
    inputs,
    outputs,
    totalInputSats,
    totalOutputSats,
    feeSats: totalInputSats > 0 ? Math.max(totalInputSats - totalOutputSats, 0) : null,
  };
}
