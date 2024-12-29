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

export const generateAddressFromSeed = (seedPhrase, network=litecoinTestnet, path="m/44'/1'/0'/0/0") => {
  try {
    console.log('Generating address for network:', network, 'with path:', path);

    // Ensure the seed phrase is valid and convert it into a seed buffer
    const seed = bip39.mnemonicToSeedSync(seedPhrase);

    // Generate the HD node using the seed
    const hdNode = bip32.fromSeed(seed, network);

    // Derive the keypair based on the provided path
       const derivedNode = hdNode.derivePath(path); // BIP44 path for Litecoin

    // Generate a Bitcoin address from the derived public key
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: Buffer.from(derivedNode.publicKey), // Convert Uint8Array to Buffer
      network,
    });

    return {
      address: address,
      publicKey: derivedNode.publicKey.toString('hex'),
      privateKey: derivedNode.privateKey.toString('hex'),
    };
  } catch (error) {
    console.error('Error generating address from seed:', error);
    throw error;
  }
};

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
  let encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');

  if (!encryptedPrivateKey) {
    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!encryptedSeed) {
      throw new Error('No encrypted seed found.');
    }

    console.log('Re-deriving private key from seed...');
    const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
    const serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
    const address = generateAddressFromSeed(serializedSeed);

    // Store private key as a hex string
    encryptedPrivateKey = CryptoJS.AES.encrypt(
      Buffer.from(address.privateKey).toString('hex'), // Store as hex
      password
    );
    localStorage.setItem('encryptedPrivateKey', encryptedPrivateKey);
  }

  // Decrypt private key
  console.log('Encrypted Private Key:', encryptedPrivateKey);
  const bytes = CryptoJS.AES.decrypt(encryptedPrivateKey, password);
 // After decrypting:
const privateKeyHex = bytes.toString(CryptoJS.enc.Utf8).trim();
console.log('Decrypted Private Key:', privateKeyHex);

// Attempt to detect CSV vs. hex
let keyBuffer;
if (privateKeyHex.includes(',')) {
  // CSV decimal case
  const decimals = privateKeyHex.split(',')
    .map((s) => parseInt(s.trim(), 10));
  keyBuffer = Buffer.from(decimals);
} else {
  // Hex case
  keyBuffer = Buffer.from(privateKeyHex, 'hex');
}

if (keyBuffer.length !== 32) {
  throw new Error(`Invalid private key length: ${keyBuffer.length}`);
}

// Then create ECPair
const keyPair = ECPair.fromPrivateKey(keyBuffer, { network: litecoinTestnet });
return keyPair;
}


// In walletUtils.js or similar
export async function signTransaction(requestPayload, password) {
  //try {
    const { fromKeyPair, toKeyPair, amount, inputs, payload, network=litecoinTestnet } = requestPayload;
    
    // 1) Derive or decrypt private key
    const keyPair  = await getOrDeriveKeyPair(password, network); 
    // Suppose we have a helper that returns { keyPair, addressString }
    console.log('keypair '+JSON.stringify(keyPair))
    // 2) Build a PSBT
    //    Convert LTC => satoshis
    const satsNeeded = Math.round(amount * 1e8);

    // We'll do a simple coin selection from utxos
    let selectedInputs = [];
    let totalSat = 0;
    // Sort descending
    const sortedUtxos = inputs.sort((a, b) => b.amount - a.amount);
    for (const u of sortedUtxos) {
      selectedInputs.push(u);
      totalSat += Math.round(u.amount * 1e8);
      if (totalSat >= satsNeeded + 10000) { // e.g. ~ 0.0001 LTC for fee
        break;
      }
    }
    if (totalSat < satsNeeded) {
      throw new Error("Not enough funds.");
    }

    // 3) Create PSBT
    const psbt = new bitcoin.Psbt({ network: litecoinTestnet/*networks[network]*/ }); 
    // (Assuming you have a networks object with LTC main/test config.)

    // 4) Add inputs w/ witnessUtxo
    selectedInputs.forEach((inp) => {
      psbt.addInput({
        hash: inp.txid,
        index: inp.vout,
        witnessUtxo: {
          script: Buffer.from(inp.scriptPubKey, 'hex'),
          value: Math.round(inp.amount * 1e8),
        },
      });
    });
    console.log('selected Inputs '+JSON.stringify(selectedInputs))
    // 5) Calculate fee and change
    const feeSats = 10000; // e.g. 0.0001 LTC
    const change = totalSat - satsNeeded - feeSats;
    console.log('Adding output:', { address: toKeyPair.address, value: satsNeeded });

    // 6) Outputs
    psbt.addOutput({ address: toKeyPair.address, value: satsNeeded });

    // If we have leftover
    if (change > 0) {
      psbt.addOutput({ address: fromKeyPair.address, value: change });
    }

    // If there's an OP_RETURN payload
    if (payload) {
      const data = Buffer.from(payload, 'utf8');
      const embed = bitcoin.payments.embed({ data: [data] });
      psbt.addOutput({ script: embed.output, value: 0 });
    }

    // 7) Sign
    psbt.signInput(0, keyPair);
    //psbt.signAllInputs(keyPair);

    // 8) Finalize
    psbt.finalizeAllInputs();

    // 9) Extract
    const finalTx = psbt.extractTransaction();
    const rawTx = finalTx.toHex();
    const txid = finalTx.getId();

    // Return success
    return {
      success: true,
      data: { rawTx, txid },
    };
  //} catch (err) {
  //  console.error("Error in buildAndSignLtcTx:", err);
  //  return { success: false, error: err.message };
  //}
}


export const handleBuildAndSignLtcTx = async (partialRawHex, password, finalize = true) => {
  try {
    // Retrieve or re-derive the private key
    let encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');
    if (!encryptedPrivateKey) {
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (!encryptedSeed) {
        throw new Error('No encrypted seed found.');
      }

      console.log('Re-deriving private key from seed...');
      const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
      const serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
      const address = generateAddressFromSeed(serializedSeed);

      encryptedPrivateKey = CryptoJS.AES.encrypt(address.privateKey.toString(), password);
      localStorage.setItem('encryptedPrivateKey', encryptedPrivateKey);
    }

    const bytes = CryptoJS.AES.decrypt(encryptedPrivateKey, password);
    const privateKey = bytes.toString(CryptoJS.enc.Utf8);
    if (!privateKey) throw new Error('Failed to decrypt private key.');

    const privKeyArray = privateKey.split(',').map((str) => parseInt(str.trim(), 10));
    const keyBuffer = Buffer.from(privKeyArray);
    if (keyBuffer.length !== 32) {
      throw new Error(`Invalid private key buffer length: ${keyBuffer.length}`);
    }

    const keyPair = ECPair.fromPrivateKey(keyBuffer);
    const publicKeyHex = keyPair.publicKey.toString('hex');
    const publicKeyBuffer = Buffer.from(keyPair.publicKey);

    const { address } = bitcoin.payments.p2wpkh({
      pubkey: publicKeyBuffer,
      network: litecoinTestnet,
    });
    console.log('Litecoin Testnet Address:', address);

    // Load the PSBT
    const psbt = bitcoin.Psbt.fromBase64(partialRawHex);

    // Validate inputs and prepare for signing
    psbt.data.inputs.forEach((input, index) => {
      const inputAddress = bitcoin.payments.p2wpkh({
        output: input.witnessUtxo.script,
        network: litecoinTestnet,
      }).address;

      const psbtPubkeyHex = Buffer.from(input.bip32Derivation[0].pubkey).toString('hex');
      const actualScript = Buffer.from(input.witnessUtxo.script).toString('hex');
      const expectedScript = bitcoin.payments.p2wpkh({
        pubkey: publicKeyBuffer,
        network: litecoinTestnet,
      }).output.toString('hex');

      console.log(`Input ${index} Address:`, inputAddress);
      console.log(`Input ${index} PSBT Public Key:`, psbtPubkeyHex);
      console.log(`Derived Public Key:`, publicKeyBuffer);
      console.log(`Input ${index} Script:`, actualScript);
      console.log(`Expected Script:`, expectedScript);

      if (inputAddress !== address) {
        console.error(`Input ${index}: Address mismatch`);
      }
      if (psbtPubkeyHex !== publicKeyBuffer) {
        console.error(`Input ${index}: Public key mismatch`);
      }
      if (actualScript !== expectedScript) {
        console.error(`Input ${index}: Script mismatch`);
      }

      // Ensure bip32Derivation.pubkey matches the derived key
      input.bip32Derivation = input.bip32Derivation.map((derivation) => ({
        ...derivation,
        pubkey: keyPair.publicKey,
      }));
    });

    // Sign all inputs
    console.log('Signing inputs...');
    psbt.signAllInputs(keyPair);

    // Verify signing
    psbt.data.inputs.forEach((input, index) => {
      const signed = input.partialSig && input.partialSig.length > 0;
      console.log(`Input ${index} signed:`, signed);
    });

    if (finalize) {
      // Finalize the transaction
      psbt.finalizeAllInputs();
      const finalTx = psbt.extractTransaction();
      const rawTx = finalTx.toHex();
      const txid = finalTx.getId();
      console.log('Final Raw Transaction:', rawTx);
      console.log('Transaction ID:', txid);

      return { rawTx, txid };
    } else {
      // Return partially signed PSBT
      const psbtBase64 = psbt.toBase64();
      console.log('Partially Signed PSBT (Base64):', psbtBase64);
      return { psbtBase64 };
    }
  } catch (error) {
    console.error('Error signing transaction:', error.message || error);
    throw new Error('Error signing transaction: ' + error.message);
  }
};



export async function signExistingTx(partialRawHex, privateKeyHex, finalize = true) {
  const keyPair = bitcoin.ECPair.fromPrivateKey(Buffer.from(privateKeyHex, 'hex'));
  const tx = bitcoin.Transaction.fromHex(partialRawHex);

  // Convert Transaction => PSBT
  const psbt = new bitcoin.Psbt();
  psbt.setVersion(tx.version);
  psbt.setLocktime(tx.locktime);

  tx.ins.forEach((txIn) => {
    psbt.addInput({
      hash: txIn.hash,
      index: txIn.index,
      // Must provide nonWitnessUtxo or witnessUtxo
      // If you lack that data, you’d need to fetch it from a node or block explorer:
      // nonWitnessUtxo: Buffer.from(...),
      // or
      // witnessUtxo: { script: ..., value: ... },
    });
  });

  tx.outs.forEach((txOut) => {
    psbt.addOutput({
      script: txOut.script,
      value: txOut.value,
    });
  });

  // Sign
  psbt.signAllInputs(keyPair);

  if (finalize) {
    // Finalize means we want a fully signed transaction
    psbt.finalizeAllInputs();
    const finalTx = psbt.extractTransaction();
    const rawTx = finalTx.toHex();
    const txid = finalTx.getId(); // or finalTx.getId();  (both are same in latest versions)

    // Return both rawTx and txid, so you can pass it to a relayer or broadcast service
    return { rawTx, txid };
  } else {
    // If we’re not finalizing, return the partially signed PSBT
    // This can be shared with other co-signers in a multisig flow.
    const psbtBase64 = psbt.toBase64();
    return { psbtBase64 };
  }
}

/**
 * Example wrapper that auto-derives a private key from localStorage or seed,
 * then calls signExistingTx. Notice we also pass in the `finalize` flag.
 */
export async function signExistingTxWithAutoPrivKey(partialRawHex, password, finalize = true) {
  let encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');
  if (!encryptedPrivateKey) {
      const encryptedSeed = localStorage.getItem('encryptedSeed')
      if(!encryptedSeed){
          throw new Error('No encrypted seed found.');
      }
      console.log('re-deriving privkey from seed ')
      let bytes = CryptoJS.AES.decrypt(encryptedSeed, password);

      // Convert decrypted bytes into a string (seed phrase)
      let serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
      const address = generateAddressFromSeed(serializedSeed);
      address.privateKey.toString()
      encryptedPrivateKey = CryptoJS.AES.encrypt(address.privateKey.toString(), password)
      localStorage.setItem('encryptedPrivateKey', encryptedKey);
    }

    const bytes = CryptoJS.AES.decrypt(encryptedPrivateKey, password);
    const privateKeyHex = bytes.toString(CryptoJS.enc.Utf8);
    // Encrypt & store

  // Sign using the function above
  return signExistingTx(partialRawHex, privateKeyHex, finalize);
}


export const createAndSignPsbt = async => ({
  inputs,
  outputs,
  redeemKeyHex,
  redeemScriptHex,
  network = litecoinTestnet,
}) => {
  try {
    // Step 1: Initialize PSBT
    const psbt = new Psbt({ network });

    // Step 2: Add inputs (with redeem script for multisig)
    inputs.forEach((input) => {
      const hash = input.txid;
      const index = input.vout;
      const value = BigInt(input.value * 1e8); // Convert LTC to satoshis
      const script = Buffer.from(input.scriptPubKey, 'hex');
      const redeemScript = Buffer.from(redeemScriptHex, 'hex');

      psbt.addInput({
        hash,
        index,
        witnessUtxo: { script, value },
        redeemScript, // Required for multisig inputs
      });
    });

    // Step 3: Add outputs
    outputs.forEach((output) => {
      psbt.addOutput({
        address: output.address,
        value: Math.round(output.value * 1e8), // Convert LTC to satoshis
      });
    });

    // Step 4: Sign inputs with redeem key
    const keyPair = ECPair.fromPrivateKey(Buffer.from(redeemKeyHex, 'hex'), { network });
    psbt.signAllInputs(keyPair);

    // Step 5: Finalize PSBT (if possible)
    try {
      psbt.finalizeAllInputs();
      const finalTxHex = psbt.extractTransaction().toHex();
      return { psbtHex: psbt.toHex(), finalTx: finalTxHex };
    } catch (err) {
      console.warn('PSBT partially signed, cannot finalize yet.');
      return { psbtHex: psbt.toHex(), finalTx: null };
    }
  } catch (error) {
    console.error('Error in createAndSignPsbt:', error);
    throw new Error('Failed to create or sign PSBT.');
  }
};

export const signInputsInPsbt = async => ({
  psbtHex,
  redeemKeyHex,
  network = litecoinTestnet,
}) => {
  try {
    // Step 1: Reinitialize PSBT from provided hex
    const psbt = Psbt.fromHex(psbtHex, { network });

    // Step 2: Create keypair from the redeem private key
    const keyPair = ECPair.fromPrivateKey(Buffer.from(redeemKeyHex, 'hex'), { network });

    // Step 3: Attempt to sign all inputs this key can sign
    psbt.signAllInputs(keyPair);

    // Step 4: Validate the signatures
    const allSignaturesValid = psbt.validateSignaturesOfAllInputs((pubkey, msghash, signature) =>
      keyPair.verify(msghash, signature)
    );

    console.log('Are all signatures valid?', allSignaturesValid);

    // Step 5: Return the partially signed PSBT
    return { psbtHex: psbt.toHex(), allSignaturesValid };
  } catch (error) {
    console.error('Error in signInputsInPsbt:', error);
    throw new Error('Failed to partially sign PSBT.');
  }
};
