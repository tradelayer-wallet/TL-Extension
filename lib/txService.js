import * as bitcoin from 'bitcoinjs-lib'
import * as protobuf from 'protobufjs'

/**
 * Function to securely store the private key in encrypted format in chrome.storage
 * @param {string} privateKeyWIF - Wallet Import Format (WIF) private key to store
 */
export const storePrivateKey = async (privateKeyWIF) => {
  try {
    // Encrypt the private key before storing it securely
    const encryptedPrivateKey = await encryptData(privateKeyWIF, yourEncryptionKey)

    // Store the encrypted private key in chrome.storage.local
    chrome.storage.local.set({ 'privateKey': encryptedPrivateKey }, function () {
      console.log('Private key saved securely.');
    })
  } catch (error) {
    console.error('Error storing private key:', error)
  }
}

/**
 * Function to retrieve and decrypt the private key from chrome.storage
 */
export const retrievePrivateKey = async () => {
  try {
    chrome.storage.local.get('privateKey', async function (result) {
      if (result.privateKey) {
        // Decrypt the private key securely
        const decryptedPrivateKey = await decryptData(result.privateKey, yourDecryptionKey)
        console.log('Decrypted private key:', decryptedPrivateKey)

        // Use the decrypted private key for signing transactions
        return decryptedPrivateKey
      }
    })
  } catch (error) {
    console.error('Error retrieving private key:', error)
  }
}

/**
 * Function to generate a unique transaction ID
 * @param {string} sidepitId - The user's sidepit ID (bitcoin address)
 * @param {number} timestamp - The timestamp of the transaction
 */
export const generateTransactionId = (sidepitId, timestamp) => {
  return `${sidepitId}-${timestamp}`
}

/**
 * Function to generate the signature for a transaction
 * @param {object} dto - The transaction object to sign
 */
async function txToSignature(dto) {
  try {
    const proto = await protobuf.load('/proto/spapi.proto')
    const Transaction = proto.lookupType('Transaction')
    const txMessage = Transaction.create(dto)
    const buffer = Transaction.encode(txMessage).finish()
    const base64Encoded = Buffer.from(buffer).toString('base64')

    // Retrieve the private key securely from chrome.storage
    const privateKeyWIF = await retrievePrivateKey()

    // Decode the private key from WIF and create a key pair
    const keyPair = bitcoin.ECPair.fromWIF(privateKeyWIF)

    // Sign the base64 encoded transaction with the private key
    const signature = signMessageWithPrivateKey(base64Encoded, keyPair)

    return signature
  } catch (error) {
    console.error('Error generating signature:', error)
    return null
  }
}

/**
 * Function to sign a message using the private key
 * @param {string} base64Message - The message to sign in base64 format
 * @param {object} keyPair - The key pair to sign the message with
 */
function signMessageWithPrivateKey(base64Message, keyPair) {
  const hash = bitcoin.crypto.sha256(Buffer.from(base64Message)) // Create a SHA-256 hash of the message
  const signature = keyPair.sign(hash) // Sign the hash using secp256k1

  // Convert the signature to base64
  const signatureBase64 = signature.toString('base64')
  return signatureBase64
}

/**
 * Function to send the signed transaction to the backend
 * @param {object} tx - The transaction object to send
 */
export const sendTx = async (tx) => {
  try {
    const url = `${process.env.NEXT_PUBLIC_BACKEND_URL}/tx`

    // Get the signature and add it to the transaction
    const signature = await txToSignature(tx)
    if (!signature) {
      console.error("Failed to sign the transaction.")
      return
    }

    const txWithSignature = {
      ...tx,
      signature: signature, // Add the signature to the transaction
    }

    // Send the transaction to the backend
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(txWithSignature),
    })

    return await response.json()
  } catch (error) {
    console.error('An error occurred while sending the transaction:', error)
  }
}

/**
 * Function to securely encrypt data
 * @param {string} data - The data to encrypt
 * @param {CryptoKey} key - The encryption key
 */
async function encryptData(data, key) {
  const encodedData = new TextEncoder().encode(data)
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12) }, // iv: Initialization Vector
    key, // key: imported/derived key
    encodedData
  )
  return encryptedData
}

/**
 * Function to securely decrypt data
 * @param {ArrayBuffer} encryptedData - The encrypted data to decrypt
 * @param {CryptoKey} key - The decryption key
 */
async function decryptData(encryptedData, key) {
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12) }, // same iv used for encryption
    key, // key: imported/derived key
    encryptedData
  )
  const decoder = new TextDecoder()
  return decoder.decode(decryptedData)
}

/**
 * Example: How to get the private key from a secure source (mock function)
 */
async function getPrivateKeyWIF() {
  // This is just a mock function - replace with your mechanism for securely storing the private key
  const keyPair = bitcoin.ECPair.makeRandom() // Generates a random key pair
  const privateKeyWIF = keyPair.toWIF() // Convert the private key to WIF format
  console.log(privateKeyWIF) // This is your WIF private key (use securely)
  return privateKeyWIF
}

// Export the service functions
export const service = { txToSignature, sendTx, storePrivateKey, retrievePrivateKey }
