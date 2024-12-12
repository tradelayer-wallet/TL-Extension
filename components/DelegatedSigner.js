// DelegatedSigner.js

import CryptoJS from 'crypto-js';
import * as bitcoin from 'bitcoinjs-lib';

class DelegatedSigner {
  constructor() {
    this.saltKey = 'delegatedSignerSalt';
    this.encryptedKeyKey = 'encryptedDelegatedKey';
  }

  /**
   * Generate a random salt for encryption.
   * @returns {string} Hexadecimal representation of the salt.
   */
  generateSalt() {
    const salt = CryptoJS.lib.WordArray.random(16); // 128-bit salt
    return salt.toString(CryptoJS.enc.Hex);
  }

  /**
   * Save the salt to secure browser storage.
   * @param {string} salt - The salt to save.
   */
  saveSalt(salt) {
    chrome.storage.local.set({ [this.saltKey]: salt }, () => {
      console.log('Salt saved securely:', salt);
    });
  }

  /**
   * Encrypt the private key using a password and salt.
   * @param {string} privateKey - The private key to encrypt.
   * @param {string} password - The user-provided password.
   * @param {string} salt - The salt used for key derivation.
   * @returns {string} Encrypted private key.
   */
  encryptPrivateKey(privateKey, password, salt) {
    const key = CryptoJS.PBKDF2(password, salt, {
      keySize: 256 / 32, // 256-bit key
      iterations: 10000,
    });
    return CryptoJS.AES.encrypt(privateKey, key).toString();
  }

  /**
   * Save the encrypted key to secure browser storage.
   * @param {string} encryptedKey - The encrypted private key.
   */
  saveEncryptedKey(encryptedKey) {
    chrome.storage.local.set({ [this.encryptedKeyKey]: encryptedKey }, () => {
      console.log('Encrypted delegated key saved securely.');
    });
  }

  /**
   * Decrypt the private key using the password and salt.
   * @param {string} encryptedKey - The encrypted private key.
   * @param {string} password - The user-provided password.
   * @param {string} salt - The salt used for key derivation.
   * @returns {string} Decrypted private key.
   */
  decryptPrivateKey(encryptedKey, password, salt) {
    const key = CryptoJS.PBKDF2(password, salt, {
      keySize: 256 / 32,
      iterations: 10000,
    });
    const decryptedBytes = CryptoJS.AES.decrypt(encryptedKey, key);
    return decryptedBytes.toString(CryptoJS.enc.Utf8);
  }

  /**
   * Sign a Litecoin transaction.
   * @param {object} tx - The BitcoinJS TransactionBuilder instance.
   * @param {string} privateKey - The private key to sign the transaction.
   * @returns {string} Raw transaction in hex format.
   */
  signTransaction(tx, privateKey) {
    const keyPair = bitcoin.ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
    tx.sign(0, keyPair); // Assuming input index 0
    return tx.build().toHex();
  }

  /**
   * Initialize the signer with a private key, password, and generated salt.
   * @param {string} privateKey - The private key to be delegated.
   * @param {string} password - The user-provided password.
   */
  initialize(privateKey, password) {
    const salt = this.generateSalt();
    const encryptedKey = this.encryptPrivateKey(privateKey, password, salt);
    this.saveSalt(salt);
    this.saveEncryptedKey(encryptedKey);
  }

  /**
   * Use the delegated signing key to sign a transaction.
   * @param {object} tx - The BitcoinJS TransactionBuilder instance.
   * @param {string} password - The user-provided password.
   * @returns {string} Raw transaction in hex format.
   */
  async useDelegatedKey(tx, password) {
    return new Promise((resolve, reject) => {
      chrome.storage.local.get([this.saltKey, this.encryptedKeyKey], (result) => {
        const { delegatedSignerSalt: salt, encryptedDelegatedKey: encryptedKey } = result;
        if (!salt || !encryptedKey) {
          return reject(new Error('Salt or encrypted key not found.')); // Ensure both are present
        }

        try {
          const privateKey = this.decryptPrivateKey(encryptedKey, password, salt);
          const signedTx = this.signTransaction(tx, privateKey);
          resolve(signedTx);
        } catch (error) {
          reject(new Error('Failed to sign transaction: ' + error.message));
        }
      });
    });
  }
}

export default DelegatedSigner;
