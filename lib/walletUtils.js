import * as bitcoin from "../lib/bitcoinjs-lib.js";  // Bitcoinjs for all required functionality
import * as bip39 from 'bip39';  // Import bip39 separately
import BIP32Factory from 'bip32';
import ECPair from 'ECPair'
import axios from 'axios';
import ecc from '@bitcoinerlab/secp256k1';
import * as secp from '@noble/secp256k1';
import { ec } from 'elliptic';
import CryptoJS from 'crypto-js';
import { ethErrors, serializeError } from 'eth-rpc-errors';
console.log('ecc obj '+JSON.stringify(ecc))
const bip32 = BIP32Factory(ecc);
import { TransactionBuilder, networks } from 'bitcoinjs-lib';
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

    console.log('Derived public key:', derivedNode.publicKey.toString('hex'));
    console.log('Derived private key:', derivedNode.privateKey.toString('hex'));

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
  console.log(seed);
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
  console.log('inside sign message '+message+' '+password)

  let encryptedPrivateKey = localStorage.getItem('encryptedKey');
    if (!encryptedPrivateKey) {
       const encryptedSeed = localStorage.getItem('encryptedSeed');
        // Decrypt the seed phrase
      let bytes1 = CryptoJS.AES.decrypt(encryptedSeed, password);

      // Convert decrypted bytes into a string (seed phrase)
      let serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
      console.log('serialized seed ' + serializedSeed);
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
    console.log('priv '+privateKey)
    if (!privateKey) {
      throw new Error('Failed to decrypt private key.');
    }
 
    const signature = await signString(privateKey, message)
 
  bytes=''
  privateKey =''

  return signature.toString('hex');  // Return signature in hex format
}

// Create and sign a Bitcoin transaction with the private key

export const signTransaction = async (decodedTx, password) => {
  try {
    // Retrieve the encrypted private key from localStorage
    const encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');
    if (!encryptedPrivateKey) {
      throw new Error('No encrypted private key found.');
    }

    // Decrypt the private key using the password
    const bytes = CryptoJS.AES.decrypt(encryptedPrivateKey, password);
    const privateKey = bytes.toString(CryptoJS.enc.Utf8);

    if (!privateKey) {
      throw new Error('Failed to decrypt private key.');
    }

    // Create the key pair from the decrypted private key
    const keyPair = bitcoin.ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));

    // Build the transaction using the decoded input/output data
    const txb = new bitcoin.TransactionBuilder();

    // Add inputs to the transaction
    decodedTx.inputs.forEach((input) => {
      txb.addInput(input.txid, input.vout);
    });

    // Add outputs to the transaction
    decodedTx.outputs.forEach((output) => {
      txb.addOutput(output.scriptPubKey, output.value * 1e8); // Convert BTC to satoshis
    });

    // Sign the transaction with the private key
    txb.sign(0, keyPair);

    // Build the raw transaction and send it to the network
    const rawTx = txb.build().toHex();
    const txid = await broadcastTransaction(rawTx); // Function to broadcast the transaction

    return txid;  // Return the transaction ID
  } catch (error) {
    throw new Error('Error signing transaction: ' + error.message);
  }
};
