// Seed-vault seam used by the popup components. This file is the legacy implementation
// (crypto-js AES over `localStorage.encryptedSeed`, exactly as PasswordSetup, ExposeSeed and
// ResetPass did inline). The Rust build (rust/tl-extension-app/build.mjs) replaces this
// module with one that calls the tl-wallet-core vault compiled to WebAssembly.
import CryptoJS from 'crypto-js';
import { clearPrivateKeyCaches } from './walletUtils';

export const vaultExists = () => !!localStorage.getItem('encryptedSeed');

// Returns { ok: true } or { ok: false, message }.
export const createVault = (password, seedPhrase) => {
  let encryptedSeed = localStorage.getItem('encryptedSeed');

  // If there's no encrypted seed, encrypt the seedPhrase and store it
  if (!encryptedSeed || encryptedSeed.length === 0) {
    encryptedSeed = CryptoJS.AES.encrypt(seedPhrase, password).toString();
    localStorage.setItem('encryptedSeed', encryptedSeed);
    clearPrivateKeyCaches();
  }

  // Decrypt the seed phrase using the entered password
  const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
  const serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
  return serializedSeed ? { ok: true } : { ok: false, message: 'Incorrect password. Please try again.' };
};

// Returns { ok: true, phrase } or { ok: false, message }.
export const exposeSeed = (password) => {
  const encryptedSeed = localStorage.getItem('encryptedSeed');
  if (!encryptedSeed) return { ok: false, message: 'Encrypted seed not found.' };

  const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
  const decrypted = bytes.toString(CryptoJS.enc.Utf8);
  return decrypted
    ? { ok: true, phrase: decrypted }
    : { ok: false, message: 'Incorrect password. Please try again.' };
};

// Returns { ok: true } or { ok: false, message }.
export const changePassword = (currentPassword, newPassword) => {
  const encryptedSeed = localStorage.getItem('encryptedSeed');
  if (!encryptedSeed) return { ok: false, message: 'Encrypted seed not found.' };

  const bytes = CryptoJS.AES.decrypt(encryptedSeed, currentPassword);
  const decrypted = bytes.toString(CryptoJS.enc.Utf8);
  if (!decrypted) return { ok: false, message: 'Incorrect current password. Please try again.' };

  localStorage.setItem('encryptedSeed', CryptoJS.AES.encrypt(decrypted, newPassword).toString());
  clearPrivateKeyCaches();
  return { ok: true };
};
