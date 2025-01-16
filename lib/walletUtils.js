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
import CryptoJS from 'crypto-js';
import { ethErrors, serializeError } from 'eth-rpc-errors';
console.log('ecc obj '+JSON.stringify(ecc))
const bip32 = BIP32Factory(ecc);
import { TransactionBuilder, networks,Psbt, payments } from 'bitcoinjs-lib';
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
  //try {
    let key = ecdsa.keyFromPrivate(privateKeyHex);
    console.log('key '+key)
    let messageHash = ecdsa.hash().update(message).digest('hex'); // Hash the message
    //const privateKey = Buffer.from(privateKeyHex, 'hex');

    // Sign the message
   const signature = key.sign(messageHash); // Use a synchronous method if available
   console.log('signature '+JSON.stringify(signature))
    const hexEncoded = encodeSignature(signature)

    // Wipe sensitive variables
    key = null // Overwrite private key buffer
    privateKeyHex = ''; // Overwrite string
    message = ''; // Overwrite message string for (let i = 0; i < messageHash.length; i++) {
      messageHash = ''; // Clear the hash

    return signature;
  //} catch (error) {
  //  console.error('Error signing message:', error);
  //  throw error;
  //}
};

export const generateAddressFromSeed = (seedPhrase, network) => {
    console.log('network in gen addr '+JSON.stringify(network))
    let test = ''
    if(network=='mainnet'||network.bech32=="ltc"){test=litecoinNetwork
    }else if(network=='litecoin-testnet'||network.bech32=='tltc'){test=litecoinTestnet}
    console.log('network object in gen addr '+JSON.stringify(test)+' .....'+test.bech32)
  try {
    let path
    if (test.bech32 === 'ltc') {
      // Litecoin mainnet (native SegWit as default)
      path = "m/84'/2'/0'/0";
    } else if (test.bech32 === 'tltc') {
      // Litecoin testnet (native SegWit as default)
      path = "m/84'/1'/0'/0";
    } else {
      throw new Error('Unsupported network.');
    }
    console.log('Generating address for network:', network, 'with path:', path);

    // Ensure the seed phrase is valid and convert it into a seed buffer
    const seed = bip39.mnemonicToSeedSync(seedPhrase);

    // Generate the HD node using the seed
    const hdNode = bip32.fromSeed(seed, test);

    // Derive the keypair based on the provided path
    console.log('about to derive node for path '+path)
       const derivedNode = hdNode.derivePath(path); // BIP44 path for Litecoin
       console.log('derived node '+JSON.stringify(derivedNode))
    // Generate a Bitcoin address from the derived public key
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: Buffer.from(derivedNode.publicKey), // Convert Uint8Array to Buffer
      network: test,
    });

    return {
      address: address,
      publicKey: derivedNode.publicKey.toString('hex'),
      privateKey: derivedNode.privateKey
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

  // Select the appropriate network configuration
  let selectedNetwork = network === 'LTCTEST' ? litecoinTestnet : litecoinNetwork;

  if(!network){selectedNetwork=litecoinTestnet}

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

  // Save to localStorage (or elsewhere)
  const multisigs = JSON.parse(localStorage.getItem('multisigs') || '[]');
  multisigs.push({
    bech32Address: p2wshData.address,
    witnessScript: witnessScriptHex,
    scriptPubKey: scriptPubKey,
    pubkeys,
    m,
  });
  localStorage.setItem('multisigs', JSON.stringify(multisigs));

  return {
    address: p2wshData.address,
    redeemScript: witnessScriptHex,
    scriptPubKey: scriptPubKey
  };
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
  let test = litecoinNetwork
  if(network=="LTCTEST"){console.log('switching param to testnet'),test = litecoinTestnet}

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

/*

export const generateAddressesFromSeed = (seedPhrase, network, accountIndex = 0, maxAddresses = 20) => {
  console.log('Network in gen addr: ' + JSON.stringify(network));

  let networkObject = '';
  if (network === 'mainnet') {
    networkObject = litecoinNetwork;
  } else if (network === 'litecoin-testnet') {
    networkObject = litecoinTestnet;
  } else {
    throw new Error('Unsupported network.');
  }

  try {
    let pathPrefix;
    if (networkObject.bech32 === 'ltc') {
      // Litecoin mainnet (native SegWit as default)
      pathPrefix = `m/84'/2'/${accountIndex}'/0`;
    } else if (networkObject.bech32 === 'tltc') {
      // Litecoin testnet (native SegWit as default)
      pathPrefix = `m/84'/1'/${accountIndex}'/0`;
    } else {
      throw new Error('Unsupported network.');
    }

    console.log('Generating addresses for network:', network, 'with path prefix:', pathPrefix);

    // Ensure the seed phrase is valid and convert it into a seed buffer
    const seed = bip39.mnemonicToSeedSync(seedPhrase);

    // Generate the HD node using the seed
    const hdNode = bip32.fromSeed(seed, networkObject);

    // Generate multiple addresses
    const addresses = [];
    for (let i = 0; i < maxAddresses; i++) {
      const path = `${pathPrefix}/${i}`;
      console.log(`Deriving address for path: ${path}`);

      // Derive the keypair based on the current path
      const derivedNode = hdNode.derivePath(path);

      // Generate a Bitcoin address from the derived public key
      const { address } = bitcoin.payments.p2wpkh({
        pubkey: Buffer.from(derivedNode.publicKey), // Convert Uint8Array to Buffer
        network: networkObject,
      });

      addresses.push({
        index: i,
        path: path,
        address: address,
        publicKey: derivedNode.publicKey.toString('hex'),
        privateKey: derivedNode.privateKey.toString('hex'),
      });
    }

    return addresses;
  } catch (error) {
    console.error('Error generating addresses from seed:', error);
    throw error;
  }
};
*/

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

// Example placeholder function to broadcast the transaction to the network

const broadcastTransaction = async (rawTx) => {
  try {
    // Define the BlockCypher API URL for broadcasting
    const url = 'https://api.blockcypher.com/v1/btc/main/txs/push';

    // Prepare the request body
    const body = {
      tx: rawTx,  // Include the raw transaction hex here
    };

    // Send the POST request to broadcast the transaction
    const response = await axios.post(url, body);

    // Check the response
    if (response.status === 201) {  // Check for success
      console.log('Transaction broadcasted successfully:', response.data);
      return response.data.tx.hash;  // Return the transaction hash
    } else {
      console.error('Error broadcasting transaction:', response.data.error);
      throw new Error(response.data.error || 'Error broadcasting transaction');
    }
  } catch (error) {
    console.error('Error broadcasting transaction:', error.message);
    throw error;  // Re-throw the error to be handled by the caller
  }
};
// Generate a random 12-word mnemonic using BIP39
export function generateMnemonic() {
  const seed = bip39.generateMnemonic();  // Generates a 12-word mnemonic
  //console.log(seed);
  return seed
}

// Derive a private key from the mnemonic using BIP32 (from bitcoinjs-lib)
/*export function derivePrivateKey(mnemonic) {
  const seed = bip39.mnemonicToSeedSync(mnemonic);  // Convert mnemonic to seed
  const root = bitcoin.bip32.fromSeed(seed);  // BIP32 root from seed
  const keyPair = root.derivePath("m/44'/0'/0'/0/0");  // Standard derivation path for BTC
  return keyPair.privateKey.toString('hex');  // Return private key in hexadecimal
}*/

// Encrypt private key using AES-256-CBC and a password
export function decryptPrivateKey(encryptedHex, password, ivHex) {
  // Convert hex values back to WordArray
  const encryptedData = CryptoJS.enc.Hex.parse(encryptedHex);
  const iv = CryptoJS.enc.Hex.parse(ivHex);

  // Decrypt the private key
  const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: encryptedData },
    CryptoJS.enc.Utf8.parse(password),
    {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }
  );

  // Convert the decrypted data back to a string
  return decrypted.toString(CryptoJS.enc.Utf8);
}

// Helper function to convert ArrayBuffer to Hex
function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}


// Sign a message with the private key using ECDSA (secp256k1)
export async function signMessage(message, password) {
  //console.log('inside sign message '+message+' '+password)

  let encryptedPrivateKey = localStorage.getItem('encryptedKey');
    if (!encryptedPrivateKey) {
       const encryptedSeed = localStorage.getItem('encryptedSeed');
        // Decrypt the seed phrase
      let bytes1 = CryptoJS.AES.decrypt(encryptedSeed, password);

      // Convert decrypted bytes into a string (seed phrase)
      let serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
      //console.log('serialized seed ' + serializedSeed);
      const address = generateAddressFromSeed(serializedSeed);

      encryptedPrivateKey = CryptoJS.AES.encrypt(address.privateKey.toString(), password)
      serializedSeed= ''
      bytes=''
      console.log('encrypted key '+encryptedKey)
      localStorage.setItem('encryptedKey', encryptedKey);

    }

    // Decrypt the private key using the password
    let bytes = CryptoJS.AES.decrypt(encryptedPrivateKey, password);
    password = ''
    console.log('bytes '+bytes)
    let privateKey = bytes.toString(CryptoJS.enc.Utf8);
    //console.log('priv '+privateKey)
    if (!privateKey) {
      throw new Error('Failed to decrypt private key.');
    }
 
    const signature = await signString(privateKey, message)
 
  bytes=''
  privateKey =''

  return signature.toString('hex');  // Return signature in hex format
}

export async function getOrDeriveKeyPair(password, network) {
  const storageLabel = `encryptedPrivateKey${network.bech32}`;
  let encryptedPrivateKey = localStorage.getItem(storageLabel);

  if (!encryptedPrivateKey) {
    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!encryptedSeed) {
      throw new Error('No encrypted seed found.');
    }

    console.log('Re-deriving private key from seed...');
    const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
    const serializedSeed = bytes.toString(CryptoJS.enc.Utf8).trim();
    if (!serializedSeed) {
      throw new Error('Failed to decrypt seed.');
    }

    const address = generateAddressFromSeed(serializedSeed, network);
    if (!address || !address.privateKey) {
      throw new Error('Failed to derive private key from seed.');
    }
    console.log('address privkey '+address.privateKey)
    // Encrypt the private key (store as base64 string)
    const privateKeyBase64 = Buffer.from(address.privateKey).toString('base64'); // Base64 encoding
    encryptedPrivateKey = CryptoJS.AES.encrypt(privateKeyBase64, password).toString();

    localStorage.setItem(storageLabel, encryptedPrivateKey);
    console.log('Encrypted and stored private key:', encryptedPrivateKey);
  }

  // Decrypt private key
  console.log('Encrypted Private Key:', encryptedPrivateKey);
  const bytes = CryptoJS.AES.decrypt(encryptedPrivateKey, password);
  const privateKeyBase64 = bytes.toString(CryptoJS.enc.Utf8).trim();

  console.log('Decrypted Base64 Private Key:', privateKeyBase64);

  // Decode base64 into a raw buffer
  const keyBuffer = Buffer.from(privateKeyBase64, 'base64');
  console.log('Decrypted Private Key Buffer:', keyBuffer);

  // Ensure the buffer has a valid private key length
  if (keyBuffer.length !== 32) {
    throw new Error(`Invalid private key length: ${keyBuffer.length}`);
  }

  // Create ECPair from private key buffer
  const keyPair = ECPair.fromPrivateKey(keyBuffer, { network });
  return keyPair;
}


export async function signTransaction(requestPayload, password, network) {
  //try {
    const {
      fromKeyPair,
      toKeyPair,
      amount,
      inputs,
      payload
    } = requestPayload;
    let test = litecoinTestnet
    if(network=="LTCTEST"){test=litecoinTestnet}else if(network=="LTC"){test=litecoinNetwork}
    console.log('network '+JSON.stringify(test))
    // 1) Derive or decrypt private key
    const keyPair = await getOrDeriveKeyPair(password, test);
    console.log('keypair:', keyPair);

    // 2) Convert LTC => satoshis
    // Note: must create a BigInt for final `value` in witnessUtxo
    const satsNeeded = BigInt(Math.round(amount * 1e8));

    // We'll do a simple coin selection from the UTXOs
    let selectedInputs = [];
    let totalSat = 0n;
    // Sort descending
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
    
    let payment

    if(toKeyPair.address.length>=62){
      payment = bitcoin.payments.p2wsh({
        address: toKeyPair.address,
        network: test,
      });
    }else if(fromKeyPair.address.length<46){
      payment = bitcoin.payments.p2wpkh({
        address: toKeyPair.address,
        network: test,
      });
    }

    const output = {
      script: payment.output, // This should be a `Buffer` (internally a `Uint8Array`)
      value: satsNeeded, // Must be a `BigInt`
    };

     // 6) Outputs
   const psbt2 = addOutputDebug(psbt,output);

    console.log('Adding output:', output);

    const payment2 = bitcoin.payments.p2wpkh({
      address: fromKeyPair.address,
      network: litecoinTestnet,
    });

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
if (psbt.inputCount > 1) {
  // Sign all inputs
  console.log('Multiple inputs detected, signing all inputs...');
  psbt.signAllInputs(keyPair);
} else {
  // Sign the first (and possibly only) input
  console.log('Single input detected, signing input 0...');
  psbt.signInput(0, keyPair);
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
  //} catch (err) {
  //  console.error("Error in signTransaction:", err);
  //  return { success: false, error: err.message };
  //}
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
  network = litecoinTestnet,
  password,
  sellerFlag
) => {
  let test = litecoinNetwork;
  if (network === "LTCTEST") {
    test = litecoinTestnet;
  }

  console.log("Starting PSBT signing process... with sellerFlag? "+sellerFlag);

  // Step 1: Reinitialize PSBT from provided hex
  let psbt = bitcoin.Psbt.fromHex(psbtHex, { network: test });
  console.log("Decoded PSBT:", psbt.data);

  // Step 2: Derive or decrypt private key for signing
  const keyPair = await getOrDeriveKeyPair(password, test);
  console.log("Derived keyPair:", keyPair);

  if(sellerFlag){

  // Step 3: Validate and Patch Inputs
    psbt.data.inputs.forEach((input, index) => {
      console.log(`Processing input ${index}:`, input);

      let derivedAddress = null;

      if (input.witnessScript && input.witnessScript.length > 0) {
        // Derive address from witnessScript (for P2WSH multisig inputs)
        derivedAddress = getAddressFromWitnessScript(input.witnessScript, test);
        console.log(`Derived address from witnessScript for input ${index}:`, derivedAddress);
      } else if (input.witnessUtxo && input.witnessUtxo.script && input.witnessUtxo.script.length > 0) {
        // Derive address from scriptPubKey (for P2WPKH or other inputs)
        derivedAddress = getAddressFromScript(input.witnessUtxo.script, test);
        console.log(`Derived address from scriptPubKey for input ${index}:`, derivedAddress);
      } else {
        console.warn(`Input ${index} does not contain a valid witnessScript or scriptPubKey.`);
      }

      if (derivedAddress) {
        const multisigData = getMultisigData(derivedAddress);

        if (multisigData) {
          const { witnessScript: localWitnessScript } = multisigData;

          // Validate the witnessScript
          const isValid = validateWitnessScript(input, localWitnessScript, test);

          if (!isValid) {
            console.warn(`Input ${index} has an invalid witnessScript. Patching...`);
            psbt = patchPsbtForMultisig(psbt, index, localWitnessScript, test);
          } else if (
            !input.witnessUtxo || // If witnessUtxo is missing
            !input.witnessUtxo.script || // Or if witnessUtxo.script is empty
            input.witnessUtxo.script.length === 0
          ) {
            console.warn(`Input ${index} is missing a valid witnessUtxo.script. Patching...`);
            psbt = patchPsbtForMultisig(psbt, index, localWitnessScript, test);
          }
        } else {
          console.warn(`No multisig data found for input ${index} (address: ${derivedAddress}).`);
        }
      } else {
        console.warn(`Could not derive address for input ${index}.`);
      }
    });
  }

  // Step 4: Sign Inputs
 psbt.data.inputs.forEach((input, index) => {
  console.log(`Signing input ${index}...`);

  if(index>0&&sellerFlag==true){
    console.log('seller flag has us exiting after signing input 0')
    return
  }

  console.log(`Input ${index} details:`, input);
  console.log(`SighashType for input ${index}:`, bitcoin.Transaction.SIGHASH_ALL);
  //try {
    if (input.witnessScript) {
      console.log('signing multisig '+input)
      // P2WSH signing requires the witnessScript
      psbt.signInput(index, keyPair, [bitcoin.Transaction.SIGHASH_ALL]);
    } else {
      console.log('signing vanilla '+index)
      // Standard signing for non-multisig inputs
      psbt.signInput(index, keyPair);
    }
    console.log(`Successfully signed input ${index}`);
  //} catch (err) {
  //  console.error(`Failed to sign input ${index}:`, err);
  //}
});


  // Step 5: Validate the signatures
  /*const allSignaturesValid = psbt.validateSignaturesOfAllInputs((pubkey, msghash, signature) =>
    keyPair.verify(msghash, signature)
  );
  console.log("Are all signatures valid?", allSignaturesValid);*/

  // Step 6: Finalize inputs if signatures are valid
  let rawTx =""
  if(!sellerFlag){
    try {
      psbt.finalizeAllInputs();
      console.log("Finalized all inputs successfully.");
    } catch (finalizeError) {
      console.error("Failed to finalize inputs:", finalizeError);
      throw new Error("Finalization of inputs failed.");
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
  }else{
    rawTx = psbt.toHex();
    console.log('returning unfinished tx '+rawTx)
    return {
      success: true,
      data: { rawTx},
    };
  }
  // Return success
  
};

function validateWitnessScript(input, localRedeemScript, network) {
  // Derive the hash of the local redeem script
  const derivedWitnessScriptHash = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(localRedeemScript)
  ).toString(CryptoJS.enc.Hex);

  // Check if the input has a witnessScript
  if (!input.witnessScript) {
    console.warn("Input does not contain a witnessScript. Patching...");
    return false;
  }

  // Calculate the hash of the input's witnessScript
  const actualWitnessScriptHash = CryptoJS.SHA256(
    CryptoJS.enc.Hex.parse(Buffer.from(input.witnessScript).toString("hex"))
  ).toString(CryptoJS.enc.Hex);

  // Compare the hashes
  if (actualWitnessScriptHash !== derivedWitnessScriptHash) {
    console.warn("Mismatch between witnessScript hash and local redeem script hash.");
    return false;
  }

  // Validate the derived witnessScript's address (optional, if needed)
  const p2wsh = bitcoin.payments.p2wsh({
    redeem: { output: input.witnessScript },
    network, // Use the provided network
  });

  if (!p2wsh.address) {
    console.warn("Failed to derive address from witnessScript.");
    return false;
  }

  console.log("WitnessScript validated successfully.");
  return true;
}


function patchPsbtForMultisig(psbt, inputIndex, localRedeemScript, network) {
  const input = psbt.data.inputs[inputIndex];

  // Patch the witnessScript
  
  input.witnessScript = Buffer.from(localRedeemScript, "hex");

  // Derive and set the witnessUtxo script
  const p2wsh = bitcoin.payments.p2wsh({
    redeem: { output: Buffer.from(localRedeemScript, "hex") },
    network,
  });

  input.witnessUtxo.script = p2wsh.output;
  return psbt
}

function getMultisigData(bech32Address) {
  const multisigs = JSON.parse(localStorage.getItem('multisigs') || '[]');
  return multisigs.find((ms) => ms.bech32Address === bech32Address);
}

function getAddressFromWitnessScript(witnessScript, network) {
  const payment = bitcoin.payments.p2wsh({
    redeem: { output: witnessScript },
    network,
  });
  return payment.address;
}


function getAddressFromScript(script, network) {
  const payment = bitcoin.payments.p2wpkh({
    output: script,
    network,
  });
  return payment.address;
}